from __future__ import print_function
from ipykernel.kernelbase import Kernel
from ipykernel.comm import CommManager
from ipykernel.zmqshell import ZMQInteractiveShell
from IPython.core.display_trap import DisplayTrap

from subprocess import check_output

from traitlets import Instance, Type


import pkg_resources
import atexit
import time
import os
import re
import yaml
import threading
from subprocess import Popen, STDOUT, PIPE
import logging
import json
import traceback
import tempfile
import six
import pprint
import shutil
from pprint import pformat
from six.moves import queue
from collections import namedtuple, defaultdict

import zmq
from zmq.eventloop.zmqstream import ZMQStream

from .modules import modules
from .module_args import module_args
from .task_args import task_args
from .play_args import play_args

from six.moves import configparser
from zmq.eventloop.ioloop import IOLoop


import ansible_runner


StatusMessage = namedtuple('StatusMessage', ['message'])
TaskCompletionMessage = namedtuple('TaskCompletionMessage', ['task_num'])


TASK_ARGS_MODULES = modules + task_args

__version__ = '0.9.0'

logger = logging.getLogger('ansible_kernel.kernel')

version_pat = re.compile(r'version (\d+(\.\d+)+)')

DEBUG = False


def ensure_directory(d):
    if not os.path.exists(d):
        os.mkdir(d)


class _NullDisplay(object):

    def __init__(self):
        self.exec_result = None

    def __call__(self, result):
        logger.debug("NullDisplay %s", result)
        self.exec_result = result


NullDisplay = _NullDisplay()
NullDisplayTrap = DisplayTrap(hook=NullDisplay)


class Splitter(object):

    def __init__(self, channels):
        self.channels = channels

    def send_multipart(self, msg, *args, **kwargs):
        logger.debug('send_multipart %s %s %s', msg, args, kwargs)
        for channel in self.channels:
            result = channel.send_multipart(msg, *args, **kwargs)
            logger.debug('result %s', result)


class AnsibleKernelHelpersThread(object):

    def __init__(self, queue):
        self.queue = queue
        self.io_loop = IOLoop(make_current=False)
        context = zmq.Context.instance()
        self.pause_socket = context.socket(zmq.REP)
        self.pause_socket_port = self.pause_socket.bind_to_random_port(
            "tcp://127.0.0.1")
        self.status_socket = context.socket(zmq.PULL)
        self.status_socket_port = self.status_socket.bind_to_random_port(
            "tcp://127.0.0.1")

        self.pause_stream = ZMQStream(self.pause_socket, self.io_loop)
        self.status_stream = ZMQStream(self.status_socket, self.io_loop)

        self.pause_stream.on_recv(self.recv_pause)
        self.status_stream.on_recv(self.recv_status)
        self.thread = threading.Thread(target=self._thread_main)
        self.thread.daemon = True

    def start(self):
        logger.info('thread.start')
        self.thread.start()
        atexit.register(self.stop)

    def stop(self):
        logger.info('thread.stop start')
        if not self.thread.is_alive():
            return
        self.io_loop.add_callback(self.io_loop.stop)
        self.thread.join()
        logger.info('thread.stop end')

    def recv_status(self, msg):
        logger.info(msg)
        self.queue.put(StatusMessage(json.loads(msg[0])))

    def recv_pause(self, msg):
        logger.info("completed %s waiting...", msg)
        self.queue.put(TaskCompletionMessage(json.loads(msg[0])))

    def _thread_main(self):
        """The inner loop that's actually run in a thread"""
        self.io_loop.make_current()
        self.io_loop.start()
        self.io_loop.close(all_fds=True)


class AnsibleKernel(Kernel):

    shell = Instance('IPython.core.interactiveshell.InteractiveShellABC', allow_none=True)
    shell_class = Type(ZMQInteractiveShell)

    implementation = 'ansible_kernel'
    implementation_version = __version__

    @property
    def language_version(self):
        m = version_pat.search(self.banner)
        return m.group(1)

    _banner = None

    @property
    def banner(self):
        if self._banner is None:
            self._banner = check_output(
                ['ansible', '--version']).decode('utf-8')
        return self._banner

    language_info = {'name': 'ansible',
                     'codemirror_mode': 'yaml',
                     'mimetype': 'text/yaml',
                     'file_extension': '.yml'}

    help_links = [
        {
            'text': 'Ansible Reference',
            'url': 'https://docs.ansible.com/ansible/latest/index.html'
        }
    ]

    def __init__(self, **kwargs):
        start_time = time.time()
        Kernel.__init__(self, **kwargs)

        logger.debug("session %s %s", type(self.session), self.session)
        logger.debug("iopub_socket %s %s", type(self.iopub_socket), self.iopub_socket)

        self.original_iopub_socket = self.iopub_socket

        self.iopub_socket = Splitter([self.original_iopub_socket, self])

        self.shell = self.shell_class.instance(parent=self,
                                               profile_dir=self.profile_dir,
                                               user_ns=self.user_ns,
                                               kernel=self)
        self.shell.displayhook.session = self.session
        self.shell.displayhook.pub_socket = self.iopub_socket
        self.shell.displayhook.topic = self._topic('execute_result')
        self.shell.display_pub.session = self.session
        self.shell.display_pub.pub_socket = self.iopub_socket

        self.comm_manager = CommManager(parent=self, kernel=self)

        self.shell.configurables.append(self.comm_manager)

        self.shell_handlers['comm_open'] = self.comm_open
        self.shell_handlers['comm_msg'] = self.comm_msg
        self.shell_handlers['comm_close'] = self.comm_close

        self.ansible_cfg = None
        self.ansible_process = None
        self.current_play = None
        self.next_task_file = None
        self.task_files = []
        self.registered_variable = None
        self.playbook_file = None
        self.silent = False
        self.runner = None
        self.runner_thread = None
        self.shutdown_requested = False
        self.shutdown = False
        self.widgets = defaultdict(dict)
        self.widget_update_order = 0
        self.vault_password = None

        self.default_inventory = "[all]\nlocalhost ansible_connection=local\n"
        self.default_play = yaml.dump(dict(hosts='localhost',
                                           name='default',
                                           gather_facts=False))
        self.temp_dir = tempfile.mkdtemp(prefix="ansible_kernel_playbook")
        self.queue = None
        self.tasks_counter = 0
        self.current_task = None
        logger.debug(self.temp_dir)
        ensure_directory(os.path.join(self.temp_dir, 'env'))
        ensure_directory(os.path.join(self.temp_dir, 'project'))
        self.copy_files()
        ensure_directory(os.path.join(self.temp_dir, 'project', 'roles'))
        with open(os.path.join(self.temp_dir, 'env', 'settings'), 'w') as f:
            f.write(json.dumps(dict(idle_timeout=0,
                                    job_timeout=0)))
        self.do_inventory(self.default_inventory)
        self.shell.run_code("import json")
        self.do_execute_play(self.default_play)
        logger.info("Kernel init finished took %s", time.time() - start_time)

    def copy_files(self):
        src = os.path.abspath('.')
        dest = os.path.join(self.temp_dir, 'project')
        src_files = os.listdir(src)
        for file_name in src_files:
            full_file_name = os.path.join(src, file_name)
            if (os.path.isfile(full_file_name)):
                shutil.copy(full_file_name, dest)
            if (os.path.isdir(full_file_name)):
                shutil.copytree(full_file_name, os.path.join(dest, file_name))

    def start_helper(self):
        self.queue = queue.Queue()
        self.helper = AnsibleKernelHelpersThread(self.queue)
        self.helper.start()
        self.process_widgets()
        logger.info("Started helper")
        config = configparser.SafeConfigParser()
        if self.ansible_cfg is not None:
            config.readfp(six.StringIO(self.ansible_cfg))
        if not os.path.exists(os.path.join(self.temp_dir, 'project')):
            os.mkdir(os.path.join(self.temp_dir, 'project'))

        if not config.has_section('defaults'):
            config.add_section('defaults')
        if config.has_option('defaults', 'roles_path'):
            roles_path = config.get('defaults', 'roles_path')
            roles_path = ":".join([os.path.abspath(x) for x in roles_path.split(":")])
            roles_path = "{0}:{1}".format(roles_path,
                                          os.path.abspath(pkg_resources.resource_filename('ansible_kernel', 'roles')))
            config.set('defaults', 'roles_path', roles_path)
        else:
            config.set('defaults', 'roles_path', os.path.abspath(
                pkg_resources.resource_filename('ansible_kernel', 'roles')))
        logger.debug("vault_password? %s", self.vault_password and not config.has_option('defaults', 'vault_password_file'))
        if self.vault_password and not config.has_option('defaults', 'vault_password_file'):
            vault_password_file = os.path.join(self.temp_dir, 'project', 'vault-secret')
            with open(vault_password_file, 'w') as vpf:
                vpf.write(self.vault_password)
            config.set('defaults', 'vault_password_file', vault_password_file)
        if not config.has_section('callback_ansible_kernel_helper'):
            config.add_section('callback_ansible_kernel_helper')
        config.set('callback_ansible_kernel_helper',
                   'status_port', str(self.helper.status_socket_port))
        with open(os.path.join(self.temp_dir, 'project', 'ansible.cfg'), 'w') as f:
            config.write(f)
        logger.info("Wrote ansible.cfg")

    def rewrite_ports(self):

        with open(self.playbook_file, 'r') as f:
            playbook = yaml.load(f.read(), Loader=yaml.FullLoader)
        playbook[0]['tasks'][0]['pause_for_kernel']['port'] = self.helper.pause_socket_port
        with open(self.playbook_file, 'w') as f:
            f.write(yaml.safe_dump(playbook, default_flow_style=False))

    def clean_up_task_files(self, backup=False):
        for task_file in self.task_files:
            if backup:
                shutil.copy(task_file, task_file + ".bak")
            if os.path.exists(task_file):
                os.unlink(task_file)
        self.task_files = []

    def runner_process_message(self, data):
        logger.info("runner message:\n{}".format(pprint.pformat(data)))
        try:

            event_data = data.get('event_data', {})
            task = event_data.get('task')
            role = event_data.get('role', None)
            event = data.get('event')

            if DEBUG:
                stream_content = dict(name='stdout',
                                      text="{}\n".format(pprint.pformat(data)))
                self.send_response(self.iopub_socket, 'stream', stream_content)

            if event == 'playbook_on_start':
                pass
            elif event == 'playbook_on_play_start':
                pass
            elif event == 'playbook_on_stats':
                pass
            elif event == 'playbook_on_include':
                pass
            elif event == 'playbook_on_task_start':
                logger.debug('playbook_on_task_start')
                task_args = event_data.get('task_args', [])
                task_uuid = data.get('uuid', '')
                self.queue.put(StatusMessage(['TaskStart', dict(task_name=task,
                                                                role_name=role,
                                                                task_arg=task_args,
                                                                task_id=task_uuid)]))
            elif event == 'runner_on_ok':
                logger.debug('runner_on_ok')
                results = event_data.get('res', {})
                device_name = event_data.get('host')
                task_uuid = data.get('uuid', '')
                self.queue.put(StatusMessage(['TaskStatus', dict(task_name=task,
                                                                 role_name=role,
                                                                 device_name=device_name,
                                                                 delegated_host_name=device_name,
                                                                 changed=results.get('changed', False),
                                                                 failed=False,
                                                                 unreachable=False,
                                                                 skipped=False,
                                                                 application_python=self._format_application_python(results),
                                                                 text_html=self._format_text_html(results),
                                                                 output=self._format_output(results),
                                                                 error=self._format_error(results),
                                                                 full_results=json.dumps(results).replace('\\', '\\\\'),
                                                                 results=self._dump_results(results),
                                                                 task_id=task_uuid)]))

            elif event == 'runner_on_failed':
                device_name = event_data.get('host')
                task_uuid = data.get('uuid', '')
                results = event_data.get('res', {})
                self.queue.put(StatusMessage(['TaskStatus', dict(task_name=task,
                                                                 role_name=role,
                                                                 device_name=device_name,
                                                                 changed=False,
                                                                 failed=True,
                                                                 unreachable=False,
                                                                 skipped=False,
                                                                 delegated_host_name=device_name,
                                                                 application_python=self._format_application_python(results),
                                                                 text_html=self._format_text_html(results),
                                                                 output=self._format_output(results),
                                                                 error=self._format_error(results),
                                                                 full_results=json.dumps(results).replace('\\', '\\\\'),
                                                                 results=self._dump_results(results),
                                                                 task_id=task_uuid)]))

            elif event == 'runner_on_unreachable':
                device_name = event_data.get('host')
                task_uuid = data.get('uuid', '')
                self.queue.put(StatusMessage(['TaskStatus', dict(task_name=task,
                                                                 role_name=role,
                                                                 device_name=device_name,
                                                                 changed=False,
                                                                 failed=False,
                                                                 unreachable=True,
                                                                 skipped=False,
                                                                 task_id=task_uuid)]))
            elif event == 'error':
                self.queue.put(StatusMessage(['Error', dict(stdout=data.get('stdout', ''))]))
            else:
                stream_content = dict(name='stdout',
                                      text="{}\n".format(pprint.pformat(data)))
                self.send_response(self.iopub_socket, 'stream', stream_content)

        except BaseException:
            logger.error(traceback.format_exc())

    def process_message(self, message):
        logger.info("message %s", message)

        stop_processing = False

        message_type = message[0]
        message_data = message[1]

        logger.info("message_type %s", message_type)
        logger.info("message_data %s", message_data)

        if message_data.get('task_name', '') == 'pause_for_kernel':
            logger.debug('pause_for_kernel')
            return stop_processing
        if message_data.get('task_name', '') == 'include_variables':
            return stop_processing
        if message_data.get('task_name', '') == 'include_vars':
            return stop_processing
        if message_data.get('task_name', '') == 'include_tasks':
            logger.debug('include_tasks')
            if message_type == 'TaskStatus' and message_data.get('failed', False):
                logger.debug('failed')
                output = 'fatal: [%s]: FAILED!' % message_data['device_name']
                if message_data.get('results', None):
                    output += " => "
                    output += message_data['results']
                output += "\n"
                stream_content = {'name': 'stdout', 'text': str(output)}
                self.send_response(self.iopub_socket, 'stream', stream_content)
            return stop_processing

        output = ''

        if message_type == 'TaskStart':
            logger.debug('TaskStart')
            task_name = message_data['task_name']
            if message_data.get('role_name'):
                task_name = "%s : %s" % (message_data['role_name'], task_name)
            output = 'TASK [%s] %s\n' % (task_name, '*' * (72 - len(task_name)))
        elif message_type == 'DeviceStatus':
            logger.debug('DeviceStatus')
            pass
        elif message_type == 'PlaybookEnded':
            logger.debug('PlaybookEnded')
            output = "\nPlaybook ended\nContext lost!\n"
            self.do_shutdown(False)
            self.clean_up_task_files(True)
            self.start_helper()
            self.rewrite_ports()
            self.start_ansible_playbook()
            stop_processing = True
        elif message_type == 'TaskStatus':
            logger.debug('TaskStatus')
            if message_data.get('changed', False):
                logger.debug('changed')
                output = 'changed: [%s]' % message_data['device_name']
            elif message_data.get('unreachable', False):
                logger.debug('unreachable')
                output = 'fatal: [%s]: UNREACHABLE!' % message_data['device_name']
            elif message_data.get('failed', False):
                logger.debug('failed')
                output = 'fatal: [%s]: FAILED!' % message_data['device_name']
            else:
                logger.debug('ok')
                output = 'ok: [%s]' % message_data['device_name']

            if message_data.get('full_results', None) and self.registered_variable is not None:
                logger.debug('full_results %s', type(message_data.get('full_results')))

                line1 = "import json"
                line2 = "{0} = globals().get('{0}', dict())".format(self.registered_variable)
                line3 = "{0}['{2}'] = json.loads('{1}')".format(self.registered_variable,
                                                                message_data.get('full_results'),
                                                                message_data['device_name'])

                for line in [line1, line2, line3]:
                    logger.debug(line)
                    self.shell.run_cell(line)

            if message_data.get('results', None):
                output += " => "
                output += message_data['results']
            if message_data.get('output', None):
                output += "\n\n[%s] stdout:\n" % message_data['device_name']
                output += message_data['output']
            if message_data.get('error', None):
                output += "\n\n[%s] stderr:\n" % message_data['device_name']
                output += message_data['error']
            if message_data.get('application_python', None):
                self.shell.run_cell(message_data.get('application_python'))
            if message_data.get('text_html', None):
                self.send_response(self.iopub_socket, 'display_data', dict(source="",
                                                                           data={"text/html": message_data.get('text_html')}))

            output += "\n"
        elif message_type == 'Error':
            logger.debug('Error')
            output = message_data.get('stdout')
        else:
            output = str(message)

        logger.info("output %s", output)

        if not self.silent:

            # Send standard output
            logger.info("sending output")
            stream_content = {'name': 'stdout', 'text': str(output)}
            self.send_response(self.iopub_socket, 'stream', stream_content)
        else:
            logger.info("silent")

        logger.info("stop_processing %s", stop_processing)
        return stop_processing

    def do_execute(self, code, silent, store_history=True,
                   user_expressions=None, allow_stdin=False):
        self.silent = silent
        if not code.strip():
            return {'status': 'ok', 'execution_count': self.execution_count,
                    'payload': [], 'user_expressions': {}}

        logger.debug('code %r', code)

        try:

            if code.strip().startswith("#inventory"):
                return self.do_inventory(code)
            elif code.strip().startswith("#ansible.cfg"):
                return self.do_ansible_cfg(code)
            elif code.strip().startswith("#host_vars"):
                return self.do_host_vars(code)
            elif code.strip().startswith("#group_vars"):
                return self.do_group_vars(code)
            elif code.strip().startswith("#vars"):
                return self.do_vars(code)
            elif code.strip().startswith("#template"):
                return self.do_template(code)
            elif code.strip().startswith("#task"):
                return self.do_execute_task(code)
            elif code.strip().startswith("#play"):
                return self.do_execute_play(code)
            elif code.strip().startswith("#python"):
                return self.do_execute_python(code)
            elif code.strip().startswith("#vault_password"):
                return self.do_execute_vault_password(code)
            else:
                return self.do_execute_task(code)

        except BaseException as e:
            logger.error(traceback.format_exc())
            reply = {'status': 'error', 'execution_count': self.execution_count,
                     'payload': [], 'user_expressions': {}, 'traceback': traceback.format_exc().splitlines(), 'ename': type(e).__name__, 'evalue': str(e)}
            self.send_response(self.iopub_socket, 'error', reply, ident=self._topic('error'))
            return reply

    def send_traceback(self, e, limit=None):
        reply = {'status': 'error', 'execution_count': self.execution_count,
                 'payload': [], 'user_expressions': {}, 'traceback': traceback.format_exc(limit).splitlines(), 'ename': type(e).__name__, 'evalue': str(e)}
        self.send_response(self.iopub_socket, 'error', reply, ident=self._topic('error'))
        return reply

    def send_error(self, e, limit=None):
        reply = {'status': 'error', 'execution_count': self.execution_count,
                 'payload': [], 'user_expressions': {}, 'traceback': str(e).splitlines(), 'ename': type(e).__name__, 'evalue': str(e)}
        self.send_response(self.iopub_socket, 'error', reply, ident=self._topic('error'))
        return reply

    def do_inventory(self, code):
        logger.info("inventory set to %s", code)
        with open(os.path.join(self.temp_dir, 'inventory'), 'w') as f:
            f.write("\n".join(code.splitlines()[1:]))
        return {'status': 'ok', 'execution_count': self.execution_count,
                'payload': [], 'user_expressions': {}}

    def do_ansible_cfg(self, code):
        self.ansible_cfg = str(code)
        # Test that the code for ansible.cfg is parsable.  Do not write the file yet.
        try:
            config = configparser.SafeConfigParser()
            if self.ansible_cfg is not None:
                config.readfp(six.StringIO(self.ansible_cfg))
        except configparser.ParsingError as e:
            return self.send_error(e, 0)
        logger.info("ansible.cfg set to %s", code)
        return {'status': 'ok', 'execution_count': self.execution_count,
                'payload': [], 'user_expressions': {}}

    def do_host_vars(self, code):
        code_lines = code.strip().splitlines(True)
        host = code_lines[0][len('#host_vars'):].strip()
        logger.debug("host %s", host)
        host_vars = os.path.join(self.temp_dir, 'project', 'host_vars')
        if not os.path.exists(host_vars):
            os.mkdir(host_vars)
        with open(os.path.join(host_vars, host), 'w') as f:
            f.write("".join(code_lines[1:]))
        return {'status': 'ok', 'execution_count': self.execution_count,
                'payload': [], 'user_expressions': {}}

    def do_vars(self, code):
        code_lines = code.strip().splitlines(True)
        vars = code_lines[0][len('#vars'):].strip()
        logger.debug("vars %s", vars)
        with open(os.path.join(self.temp_dir, 'project', vars), 'w') as f:
            f.write("".join(code_lines[1:]))
        return {'status': 'ok', 'execution_count': self.execution_count,
                'payload': [], 'user_expressions': {}}

    def do_template(self, code):
        code_lines = code.strip().splitlines(True)
        template = code_lines[0][len('#template'):].strip()
        logger.debug("template %s", template)
        with open(os.path.join(self.temp_dir, 'project', template), 'w') as f:
            f.write("".join(code_lines[1:]))
        return {'status': 'ok', 'execution_count': self.execution_count,
                'payload': [], 'user_expressions': {}}

    def do_group_vars(self, code):
        code_lines = code.strip().splitlines(True)
        group = code_lines[0][len('#group_vars'):].strip()
        logger.debug("group %s", group)
        group_vars = os.path.join(self.temp_dir, 'project', 'group_vars')
        if not os.path.exists(group_vars):
            os.mkdir(group_vars)
        with open(os.path.join(group_vars, group), 'w') as f:
            f.write("".join(code_lines[1:]))
        return {'status': 'ok', 'execution_count': self.execution_count,
                'payload': [], 'user_expressions': {}}

    def do_execute_play(self, code):
        if self.is_ansible_alive():
            self.do_shutdown(False)
        self.start_helper()
        code_data = yaml.load(code, Loader=yaml.FullLoader)
        logger.debug('code_data %r', code_data)
        logger.debug('code_data type: %s', type(code_data))
        self.current_play = code

        playbook = []

        current_play = yaml.load(self.current_play, Loader=yaml.FullLoader)
        if current_play is None:
            current_play = {}
        playbook.append(current_play)
        tasks = current_play['tasks'] = current_play.get('tasks', [])
        current_play['roles'] = current_play.get('roles', [])
        for role in current_play['roles']:
            if "." in role:
                self.get_galaxy_role(role)
        current_play['roles'].insert(0, 'ansible_kernel_helpers')

        tasks.append({'pause_for_kernel': {'host': '127.0.0.1',
                                           'port': self.helper.pause_socket_port,
                                           'task_num': self.tasks_counter - 1}})
        widget_vars_file = os.path.join(self.temp_dir, 'project', 'widget_vars.yml')
        with open(widget_vars_file, 'w') as f:
            f.write(yaml.dump({}))
        tasks.append({'include_vars': {'file': 'widget_vars.yml'}})
        tasks.append(
            {'include_tasks': 'next_task{0}.yml'.format(self.tasks_counter)})

        logger.debug(yaml.safe_dump(playbook, default_flow_style=False))

        if not os.path.exists(os.path.join(self.temp_dir, 'project')):
            os.mkdir(os.path.join(self.temp_dir, 'project'))
        self.playbook_file = (os.path.join(self.temp_dir, 'project', 'playbook.yml'))
        with open(self.playbook_file, 'w') as f:
            f.write(yaml.safe_dump(playbook, default_flow_style=False))

        # Weird work around for streaming content not showing
        stream_content = {'name': 'stdout', 'text': '\n'}
        self.send_response(self.iopub_socket, 'stream', stream_content)
        # End weird work around
        self.start_ansible_playbook()
        logger.info("done")
        return {'status': 'ok', 'execution_count': self.execution_count,
                'payload': [], 'user_expressions': {}}

    def start_ansible_playbook(self):
        # We may need to purge artifacts when we start again
        if os.path.exists(os.path.join(self.temp_dir, 'artifacts')):
            shutil.rmtree(os.path.join(self.temp_dir, 'artifacts'))

        logger.info("runner starting")
        env = os.environ.copy()
        env['ANSIBLE_KERNEL_STATUS_PORT'] = str(self.helper.status_socket_port)
        self.runner_thread, self.runner = ansible_runner.run_async(private_data_dir=self.temp_dir,
                                                                   playbook="playbook.yml",
                                                                   quiet=True,
                                                                   debug=True,
                                                                   ignore_logging=True,
                                                                   cancel_callback=self.cancel_callback,
                                                                   finished_callback=self.finished_callback,
                                                                   event_handler=self.runner_process_message)
        logger.info("runner started")
        logger.info("Runner status: {}".format(self.runner.status))
        while self.runner.status in ['unstarted', 'running', 'starting']:
            logger.info("In runner loop")

            try:
                logger.info("getting message %s", self.helper.pause_socket_port)
                msg = self.queue.get(timeout=1)
            except queue.Empty:
                logger.info("Queue Empty!")
                continue
            logger.info(msg)
            if isinstance(msg, StatusMessage):
                if self.process_message(msg.message):
                    break
            elif isinstance(msg, TaskCompletionMessage):
                logger.info('msg.task_num %s tasks_counter %s', msg.task_num, self.tasks_counter)
                break
            elif not self.is_ansible_alive():
                logger.info("ansible is dead")
                self.do_shutdown(False)
                break

            logger.info("Bottom of runner loop")
            time.sleep(1)
        logger.info("Runner state is now {}".format(self.runner.status))
        self.clean_up_task_files()

        logger.info("done")

    def process_widgets(self):

        # Extract values from widgets
        # Values in widgets with a var_name property are added to the vars file
        # Values in widgets with a ansible_kernel_property are store into special variables
        widget_vars_file = os.path.join(self.temp_dir, 'project', 'widget_vars.yml')
        logger.debug("widget_vars_file %s", widget_vars_file)
        widget_vars = {}
        for widget in sorted(self.widgets.values(), key=lambda x: x['widget_update_order']):
            logger.debug("widget %s", pformat(widget))
            if 'var_name' in widget and 'value' in widget:
                widget_vars[widget['var_name']] = widget['value']
            if 'ansible_kernel_property' in widget and 'value' in widget:
                if widget['ansible_kernel_property'] == 'vault_password':
                    self.vault_password = widget['value']
                    logger.debug("set vault_password")

        # Save the vars from the widgets and include it for this task
        with open(widget_vars_file, 'w') as f:
            f.write(yaml.safe_dump(widget_vars, default_flow_style=False))

    def do_execute_task(self, code):
        if not self.is_ansible_alive():
            logger.info("ansible is dead")
            self.do_shutdown(False)
        if self.helper is None:
            output = "No play found. Run a valid play cell"
            stream_content = {'name': 'stdout', 'text': str(output)}
            self.send_response(self.iopub_socket, 'stream', stream_content)
            return {'status': 'ok', 'execution_count': self.execution_count,
                    'payload': [], 'user_expressions': {}}

        self.registered_variable = None
        self.current_task = code
        try:
            code_data = yaml.load(code, Loader=yaml.FullLoader)
        except Exception:
            code_data = code
        logger.debug('code_data %s', code_data)
        logger.debug('code_data type: %s', type(code_data))

        if isinstance(code_data, str):
            if (code_data.endswith("?")):
                module = code_data[:-1].split()[-1]
            else:
                module = code_data.split()[-1]
            data = self.get_module_doc(module)
            payload = dict(
                source='',
                data=data)
            logging.debug('payload %s', payload)
            # content = {'name': 'stdout', 'text': str(payload)}
            self.send_response(self.iopub_socket, 'display_data', payload)
            return {'status': 'ok', 'execution_count': self.execution_count,
                    'payload': [], 'user_expressions': {}}
        elif isinstance(code_data, list):
            code_data = code_data[0]
        elif isinstance(code_data, dict):
            code_data = code_data
        elif code_data is None:
            return {'status': 'ok', 'execution_count': self.execution_count,
                    'payload': [], 'user_expressions': {}}
        else:
            logger.error('code_data %s unsupported type', type(code_data))

        if not isinstance(code_data, dict):
            try:
                code_data = yaml.load(code, Loader=yaml.FullLoader)
                tb = []
            except Exception:
                tb = traceback.format_exc(1).splitlines()
            reply = {'status': 'error', 'execution_count': self.execution_count,
                     'payload': [], 'user_expressions': {},
                     'traceback': ['Invalid task cell\n'] + tb,
                     'ename': 'Invalid cell',
                     'evalue': ''}
            self.send_response(self.iopub_socket, 'error', reply, ident=self._topic('error'))
            return reply

        if 'include_role' in code_data.keys():
            role_name = code_data['include_role'].get('name', '')
            if '.' in role_name:
                self.get_galaxy_role(role_name)

        if 'register' in code_data.keys():
            self.registered_variable = code_data['register']

        interrupted = False
        try:

            tasks = []

            current_task_data = yaml.load(self.current_task, Loader=yaml.FullLoader)
            current_task_data['ignore_errors'] = True
            tasks.append(current_task_data)
            tasks.append({'pause_for_kernel': {'host': '127.0.0.1',
                                               'port': self.helper.pause_socket_port,
                                               'task_num': self.tasks_counter}})

            self.process_widgets()
            tasks.append({'include_vars': {'file': 'widget_vars.yml'}})

            # Create the include file task to look for the future task
            tasks.append(
                {'include_tasks': 'next_task{0}.yml'.format(self.tasks_counter + 1)})

            logger.debug(yaml.safe_dump(tasks, default_flow_style=False))

            self.next_task_file = os.path.join(self.temp_dir, 'project',
                                               'next_task{0}.yml'.format(self.tasks_counter))
            self.tasks_counter += 1
            self.task_files.append(self.next_task_file)
            with open(self.next_task_file, 'w') as f:
                f.write(yaml.safe_dump(tasks, default_flow_style=False))
            logger.info('Wrote %s', self.next_task_file)

            self.helper.pause_socket.send_string('Proceed')

            while True:
                logger.info("getting message %s", self.helper.pause_socket_port)
                msg = self.queue.get()
                logger.info(msg)
                if isinstance(msg, StatusMessage):
                    if self.process_message(msg.message):
                        break
                elif isinstance(msg, TaskCompletionMessage):
                    logger.info('msg.task_num %s tasks_counter %s', msg.task_num, self.tasks_counter)
                    break

        except KeyboardInterrupt:
            logger.error(traceback.format_exc())

        if interrupted:
            return {'status': 'abort', 'execution_count': self.execution_count}

        return {'status': 'ok', 'execution_count': self.execution_count,
                'payload': [], 'user_expressions': {}}

    def do_execute_python(self, code):

        code = "".join(code.splitlines(True)[1:])

        reply_content = {}

        res = self.shell.run_cell(code)

        logger.debug('do_execute_python res %s', pformat(res))

        if res.success:
            reply_content['status'] = 'ok'
        else:
            reply_content['status'] = 'error'

        reply_content['execution_count'] = self.execution_count

        reply_content['payload'] = self.shell.payload_manager.read_payload()
        self.shell.payload_manager.clear_payload()

        self.export_python_variables()

        return reply_content

    def export_python_variables(self):

        try:
            self.silent = True
            original_display_trap = self.shell.display_trap
            self.shell.display_trap = NullDisplayTrap

            line1 = "import types"
            line2 = "import json"
            line3 = "json.dumps([_x for _x, _v in globals().items() if " \
                    "not _x.startswith('_') and " \
                    "_x not in ['In', 'Out', 'quit', 'pprint', 'exit', 'get_ipython'] and " \
                    "not isinstance(_v, types.ModuleType)])"

            for line in [line1, line2, line3]:
                res = self.shell.run_cell(line)

            logger.debug('export_python_variables res %s', pformat(res))
            logger.debug('export_python_variables NullDisplay %s', pformat(NullDisplay.exec_result))

            variable_values = dict()

            if res.success and NullDisplay.exec_result:
                logger.debug('export_python_variables %s', pformat(json.loads(NullDisplay.exec_result)))
                variable_names = json.loads(NullDisplay.exec_result)
                NullDisplay.exec_result = None
                for variable in variable_names:
                    res = self.shell.run_cell('json.dumps({0})'.format(variable))
                    if res.success and NullDisplay.exec_result:
                        variable_values[variable] = json.loads(NullDisplay.exec_result)
                        NullDisplay.exec_result = None
            else:
                logger.debug('export_python_variables error')

            logger.debug('export_python_variables variable_values %s', pformat(variable_values))

            self.do_execute_task(yaml.dump(dict(set_fact=variable_values)))
        finally:
            self.silent = False
            self.shell.display_trap = original_display_trap

    def do_execute_vault_password(self, code):

        self.shell.run_cell("import ansible_kernel.widgets\n"
                            "style = {'description_width': 'initial'}\n"
                            "ansible_kernel.widgets.VaultPassword(description='Vault Password:', style=style)\n")

        return {'status': 'ok', 'execution_count': self.execution_count,
                'payload': [], 'user_expressions': {}}

    def do_complete(self, code, cursor_pos):
        code = code[:cursor_pos]
        default = {'matches': [], 'cursor_start': 0,
                   'cursor_end': cursor_pos, 'metadata': dict(),
                   'status': 'ok'}

        if code.strip().startswith("#inventory"):
            return default
        elif code.strip().startswith("#ansible.cfg"):
            return default
        elif code.strip().startswith("#host_vars"):
            return default
        elif code.strip().startswith("#group_vars"):
            return default
        elif code.strip().startswith("#task"):
            return self.do_complete_task(code, cursor_pos)
        elif code.strip().startswith("#play"):
            return self.do_complete_play(code, cursor_pos)
        else:
            return self.do_complete_task(code, cursor_pos)

    def do_complete_task(self, code, cursor_pos):

        default = {'matches': [], 'cursor_start': 0,
                   'cursor_end': cursor_pos, 'metadata': dict(),
                   'status': 'ok'}

        logger.debug('code %r', code)

        if not code or code[-1] == ' ':
            return default

        found_module = False
        code_data = None
        try:
            code_data = yaml.load(code, Loader=yaml.FullLoader)
        except Exception:
            try:
                code_data = yaml.load(code + ":", Loader=yaml.FullLoader)
            except Exception:
                code_data = None

        if code_data is not None:
            logger.debug('code_data %s', code_data)

            if isinstance(code_data, list) and len(code_data) > 0:
                code_data = code_data[0]
            if isinstance(code_data, dict):
                for key in code_data.keys():
                    if key in modules:
                        module_name = key
                        found_module = True
                        break

        logger.debug('found_module %s', found_module)

        tokens = code.split()
        if not tokens:
            return default

        matches = []
        token = tokens[-1]
        start = cursor_pos - len(token)

        logger.debug('token %s', token)

        if not found_module:
            for module in TASK_ARGS_MODULES:
                if module.startswith(token):
                    matches.append(module)
        else:
            for arg in module_args.get(module_name, []) + task_args:
                if arg.startswith(token):
                    matches.append(arg)

        if not matches:
            return default
        matches = [m for m in matches if m.startswith(token)]

        return {'matches': sorted(matches), 'cursor_start': start,
                'cursor_end': cursor_pos, 'metadata': dict(),
                'status': 'ok'}

    def do_complete_play(self, code, cursor_pos):

        default = {'matches': [], 'cursor_start': 0,
                   'cursor_end': cursor_pos, 'metadata': dict(),
                   'status': 'ok'}

        logger.debug('code %r', code)

        if not code or code[-1] == ' ':
            return default

        tokens = code.split()
        if not tokens:
            return default

        matches = []
        token = tokens[-1]
        start = cursor_pos - len(token)

        logger.debug('token %s', token)

        for arg in play_args:
            if arg.startswith(token):
                matches.append(arg)

        if not matches:
            return default
        matches = [m for m in matches if m.startswith(token)]

        return {'matches': sorted(matches), 'cursor_start': start,
                'cursor_end': cursor_pos, 'metadata': dict(),
                'status': 'ok'}

    def do_inspect(self, code, cursor_pos, detail_level=0):
        logger.debug("code %s", code)
        logger.debug("cursor_pos %s", cursor_pos)
        logger.debug("detail_level %s", detail_level)

        if code.strip().startswith("#inventory"):
            logger.info("#inentory not supported")
            return {'status': 'ok', 'data': {}, 'metadata': {}, 'found': True}
        elif code.strip().startswith("#task"):
            return self.do_inspect_module(code, cursor_pos, detail_level)
        elif code.strip().startswith("#play"):
            logger.info("#play not supported")
            return {'status': 'ok', 'data': {}, 'metadata': {}, 'found': True}
        else:
            return self.do_inspect_module(code, cursor_pos, detail_level)

    def do_inspect_module(self, code, cursor_pos, detail_level=0):

        data = dict()

        code_data = yaml.load(code, Loader=yaml.FullLoader)

        logger.debug("code_data %s", code_data)

        if isinstance(code_data, str):
            module = code_data
        elif isinstance(code_data, dict):
            for arg in task_args:
                if arg in code_data:
                    del code_data[arg]
            module = code_data.keys()[0]
        else:
            logger.warn('code type not supported %s', type(code_data))
            return {'status': 'ok', 'data': {}, 'metadata': {}, 'found': False}

        data.update(self.get_module_doc(module))

        return {'status': 'ok', 'data': data, 'metadata': {}, 'found': True}

    def get_galaxy_role(self, role_name):

        command = ['ansible-galaxy', 'list', '-p', 'project/roles']
        logger.debug("command %s", command)
        p = Popen(command, cwd=self.temp_dir, stdout=PIPE, stderr=STDOUT)
        p.wait()
        exitcode = p.returncode
        logger.debug('exitcode %s', exitcode)
        output = p.communicate()[0].decode('utf-8')

        for line in output.splitlines():
            if line.startswith('- '):
                role, _, version = line[2:].partition(',')
                role = role.strip()
                if role == role_name:
                    return

        p = Popen(command, cwd=self.temp_dir, stdout=PIPE, stderr=STDOUT, )
        command = ['ansible-galaxy', 'install', '-p', 'project/roles', role_name]
        logger.debug("command %s", command)
        p = Popen(command, cwd=self.temp_dir, stdout=PIPE, stderr=STDOUT, )
        p.wait()
        exitcode = p.returncode
        logger.debug('exitcode %s', exitcode)
        output = p.communicate()[0].decode('utf-8')
        logger.debug('output %s', output)
        stream_content = {'name': 'stdout', 'text': str(output)}
        self.send_response(self.iopub_socket, 'stream', stream_content)

    def get_module_doc(self, module):

        data = {}

        logger.debug("command %s", " ".join(
            ['ansible-doc', '-t', 'module', module]))
        p = Popen(['ansible-doc', '-t', 'module', module],
                  stdout=PIPE, stderr=STDOUT, )
        p.wait()
        exitcode = p.returncode
        logger.debug('exitcode %s', exitcode)
        output = p.communicate()[0].decode('utf-8')
        logger.debug('output %s', output)
        data['text/plain'] = output

        return data

    def is_ansible_alive(self):
        if self.runner_thread is None:
            logger.info("NOT STARTED")
            return False
        if self.runner_thread.is_alive():
            logger.info("YES")
        else:
            logger.info("NO")
        return self.runner_thread.is_alive()

    def cancel_callback(self):
        logger.info('called')
        return self.shutdown_requested

    def finished_callback(self, runner):
        logger.info('called')
        self.shutdown = True
        if not self.shutdown_requested:
            self.queue.put(StatusMessage(['PlaybookEnded', {}]))

    def do_shutdown(self, restart):

        if self.is_ansible_alive():
            self.shutdown = False
            self.shutdown_requested = True

            while not self.shutdown:
                if not self.is_ansible_alive():
                    break
                logger.info("waiting for shutdown")
                time.sleep(1)
            logger.info("shutdown complete")

        self.shutdown_requested = False
        self.runner_thread = None
        self.runner = None
        if self.helper is not None:
            self.helper.stop()
            self.helper = None

        return {'status': 'ok', 'restart': restart}

    def _format_application_python(self, result):
        if 'application/x-python' in result:
            ret_value = result['application/x-python']
            del result['application/x-python']
            return ret_value
        return ""

    def _format_text_html(self, result):
        if 'text/html' in result:
            ret_value = result['text/html']
            del result['text/html']
            return ret_value
        return ""

    def _format_output(self, result):
        if 'stdout_lines' in result:
            return '\n'.join(result['stdout_lines'])
        return ""

    def _format_error(self, result):
        if 'stderr_lines' in result:
            return '\n'.join(result['stderr_lines'])
        return ""

    def _dump_results(self, result):

        r = result
        for key in ['_ansible_verbose_always',
                    '_ansible_no_log',
                    '_ansible_parsed',
                    'invocation']:
            if key in r:
                del r[key]
        if 'stdout' in r:
            if r['stdout']:
                r['stdout'] = '[see below]'
        if 'stdout_lines' in r:
            if r['stdout_lines']:
                r['stdout_lines'] = '[removed for clarity]'
        if 'stderr' in r:
            if r['stderr']:
                r['stderr'] = '[see below]'
        if 'stderr_lines' in r:
            if r['stderr_lines']:
                r['stderr_lines'] = '[removed for clarity]'
        if 'changed' in r:
            del r['changed']
        if 'reason' in r:
            return r['reason']
        return json.dumps(r, sort_keys=True, indent=4)

    def set_parent(self, ident, parent):
        super(AnsibleKernel, self).set_parent(ident, parent)
        self.shell.set_parent(parent)

    def send_multipart(self, msg, *args, **kwargs):
        logger.debug('send_multipart %s %s %s %s', len(msg), msg, args, kwargs)
        if len(msg) == 7:
            msg0, msg1, msg2, msg3, msg4, msg5, msg6 = msg
            logger.debug("msg0 %s", msg0)
            logger.debug("msg1 %s", msg1)
            logger.debug("msg2 %s", msg2)
            logger.debug("msg3 %s", pformat(json.loads(msg3)))
            logger.debug("msg4 %s", pformat(json.loads(msg4)))
            logger.debug("msg5 %s", pformat(json.loads(msg5)))
            logger.debug("msg6 %s", pformat(json.loads(msg6)))

            msg3_data = json.loads(msg3)
            msg6_data = json.loads(msg6)

            if msg0.startswith(b"comm"):
                _, _, comm_id = msg0.partition('-')
                if msg3_data['msg_type'] == 'comm_open' and msg6_data['comm_id'] == comm_id:
                    self.update_widget(comm_id, msg6_data.get('data', {}).get('state', {}))
                    logger.debug("new widget %s %s", comm_id, pformat(self.widgets[comm_id]))

                if msg3_data['msg_type'] == 'comm_msg' and msg6_data['comm_id'] == comm_id:
                    if msg6_data.get('data', {}).get('method') == 'update':
                        self.update_widget(comm_id, msg6_data.get('data', {}).get('state', {}))
                        logger.debug("update widget %s %s", comm_id, pformat(self.widgets[comm_id]))

    def update_widget(self, comm_id, state):
        self.widgets[comm_id].update(state)
        self.widgets[comm_id]['widget_update_order'] = self.widget_update_order
        self.widget_update_order += 1

    def comm_open(self, stream, ident, msg):
        logger.debug("comm_open: %s %s", ident, msg)
        self.comm_manager.comm_open(stream, ident, msg)

    def comm_msg(self, stream, ident, msg):
        logger.debug("comm_msg: %s %s", ident, msg)
        logger.debug("msg %s", pformat(msg))

        comm_id = msg.get('content', {}).get('comm_id', {})
        if comm_id in self.widgets:
            self.widgets[comm_id].update(msg.get('content', {}).get('data', {}).get('state', {}))
            logger.debug("updated widget %s %s", comm_id, self.widgets[comm_id])
        self.comm_manager.comm_msg(stream, ident, msg)

    def comm_close(self, stream, ident, msg):
        logger.debug("comm_close: %s %s", ident, msg)
        self.comm_manager.comm_close(stream, ident, msg)
