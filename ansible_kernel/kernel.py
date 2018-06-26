from __future__ import print_function
from ipykernel.kernelbase import Kernel

from subprocess import check_output

import pkg_resources
import atexit
import os
import io
import re
import yaml
import threading
from subprocess import Popen, STDOUT, PIPE
import logging
import json
import traceback
import tempfile
import psutil
from Queue import Queue
from collections import namedtuple

import zmq
from zmq.eventloop.zmqstream import ZMQStream

from modules import modules
from module_args import module_args
from task_args import task_args
from play_args import play_args

from ConfigParser import SafeConfigParser
from zmq.eventloop.ioloop import IOLoop

StatusMessage = namedtuple('StatusMessage', ['message'])
TaskCompletionMessage = namedtuple('TaskCompletionMessage', ['task_num'])


TASK_ARGS_MODULES = modules + task_args

__version__ = '0.0.1'

logger = logging.getLogger('ansible_kernel.kernel')

version_pat = re.compile(r'version (\d+(\.\d+)+)')


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
        logger = logging.getLogger('ansible_kernel.kernel.recv_status')
        logger.info(msg)
        self.queue.put(StatusMessage(json.loads(msg[0])))

    def recv_pause(self, msg):
        logger = logging.getLogger('ansible_kernel.kernel.recv_pause')
        logger.info("completed %s waiting...", msg)
        self.queue.put(TaskCompletionMessage(json.loads(msg[0])))

    def _thread_main(self):
        """The inner loop that's actually run in a thread"""
        self.io_loop.make_current()
        self.io_loop.start()
        self.io_loop.close(all_fds=True)


class AnsibleKernel(Kernel):
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
        Kernel.__init__(self, **kwargs)
        logger = logging.getLogger('ansible_kernel.kernel.__init__')
        self.ansible_cfg = None
        self.ansible_process = None
        self.current_play = None
        self.default_play = yaml.dump(dict(hosts='localhost',
                                           name='default',
                                           gather_facts=False))
        self.temp_dir = tempfile.mkdtemp(prefix="ansible_kernel_playbook")
        self.queue = Queue()
        self.tasks_counter = 0
        self.current_task = None
        logger.debug(self.temp_dir)
        self.do_execute_play(self.default_play)

    def start_helper(self):
        self.helper = AnsibleKernelHelpersThread(self.queue)
        self.helper.start()
        config = SafeConfigParser()
        if self.ansible_cfg is not None:
            config.readfp(io.BytesIO(self.ansible_cfg))
        with open(os.path.join(self.temp_dir, 'ansible.cfg'), 'w') as f:
            if not config.has_section('defaults'):
                config.add_section('defaults')
            config.set('defaults', 'callback_whitelist',
                       'ansible_kernel_helper')
            config.set('defaults', 'callback_plugins', os.path.abspath(
                pkg_resources.resource_filename('ansible_kernel', 'plugins/callback')))
            config.set('defaults', 'roles_path', os.path.abspath(
                pkg_resources.resource_filename('ansible_kernel', 'roles')))
            config.set('defaults', 'inventory', 'inventory')
            if not config.has_section('callback_ansible_kernel_helper'):
                config.add_section('callback_ansible_kernel_helper')
            config.set('callback_ansible_kernel_helper',
                       'status_port', str(self.helper.status_socket_port))
            config.write(f)

    def process_message(self, message):
        logger = logging.getLogger('ansible_kernel.kernel.process_message')
        logger.info("message %s", message)

        message_type = message[0]
        message_data = message[1]

        logger.info("message_type %s", message_type)
        logger.info("message_data %s", message_data)

        if message_data.get('task_name', '') == 'pause_for_kernel':
            return
        if message_data.get('task_name', '') == 'include_tasks':
            return

        output = ''

        if message_type == 'TaskStart':
            output = 'TASK [%s] %s\n' % (
                message_data['task_name'], '*' * (72 - len(message_data['task_name'])))

        elif message_type == 'DeviceStatus':
            pass
        elif message_type == 'PlaybookEnded':
            pass
        elif message_type == 'TaskStatus':
            if message_data.get('changed', False):
                output = 'changed: [%s]' % message_data['device_name']
            elif message_data.get('unreachable', False):
                output = 'fatal: [%s]: UNREACHABLE!' % message_data['device_name']
            elif message_data.get('failed', False):
                output = 'fatal: [%s]: FAILED!' % message_data['device_name']
            else:
                output = 'ok: [%s]' % message_data['device_name']

            if message_data.get('results', None):
                output += " => "
                output += message_data['results']
            output += "\n"
        else:
            output = str(message)

        logger.info("output %s", output)

        if not self.silent:

            # Send standard output
            stream_content = {'name': 'stdout', 'text': str(output)}
            self.send_response(self.iopub_socket, 'stream', stream_content)

    def do_execute(self, code, silent, store_history=True,
                   user_expressions=None, allow_stdin=False):
        logger = logging.getLogger('ansible_kernel.kernel.do_execute')
        self.silent = silent
        if not code.strip():
            return {'status': 'ok', 'execution_count': self.execution_count,
                    'payload': [], 'user_expressions': {}}

        logger.debug('code %r', code)

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
        else:
            return self.do_execute_task(code)

    def do_inventory(self, code):
        logger = logging.getLogger('ansible_kernel.kernel.do_inventory')
        logger.info("inventory set to %s", code)
        with open(os.path.join(self.temp_dir, 'inventory'), 'w') as f:
            f.write(code)
        return {'status': 'ok', 'execution_count': self.execution_count,
                'payload': [], 'user_expressions': {}}

    def do_ansible_cfg(self, code):
        logger = logging.getLogger('ansible_kernel.kernel.do_ansible_cfg')
        self.ansible_cfg = str(code)
        config = SafeConfigParser()
        if self.ansible_cfg is not None:
            config.readfp(io.BytesIO(self.ansible_cfg))
        logger.info("ansible.cfg set to %s", code)
        return {'status': 'ok', 'execution_count': self.execution_count,
                'payload': [], 'user_expressions': {}}

    def do_host_vars(self, code):
        logger = logging.getLogger('ansible_kernel.kernel.do_host_vars')
        code_lines = code.strip().splitlines(True)
        host = code_lines[0][len('#host_vars'):].strip()
        logger.debug("host %s", host)
        host_vars = os.path.join(self.temp_dir, 'host_vars')
        if not os.path.exists(host_vars):
            os.mkdir(host_vars)
        with open(os.path.join(host_vars, host), 'w') as f:
            f.write("".join(code_lines[1:]))
        return {'status': 'ok', 'execution_count': self.execution_count,
                'payload': [], 'user_expressions': {}}

    def do_vars(self, code):
        logger = logging.getLogger('ansible_kernel.kernel.do_vars')
        code_lines = code.strip().splitlines(True)
        vars = code_lines[0][len('#vars'):].strip()
        logger.debug("vars %s", vars)
        with open(os.path.join(self.temp_dir, vars), 'w') as f:
            f.write("".join(code_lines[1:]))
        return {'status': 'ok', 'execution_count': self.execution_count,
                'payload': [], 'user_expressions': {}}

    def do_template(self, code):
        logger = logging.getLogger('ansible_kernel.kernel.do_template')
        code_lines = code.strip().splitlines(True)
        template = code_lines[0][len('#template'):].strip()
        logger.debug("template %s", template)
        with open(os.path.join(self.temp_dir, template), 'w') as f:
            f.write("".join(code_lines[1:]))
        return {'status': 'ok', 'execution_count': self.execution_count,
                'payload': [], 'user_expressions': {}}

    def do_group_vars(self, code):
        logger = logging.getLogger('ansible_kernel.kernel.do_group_vars')
        code_lines = code.strip().splitlines(True)
        group = code_lines[0][len('#group_vars'):].strip()
        logger.debug("group %s", group)
        group_vars = os.path.join(self.temp_dir, 'group_vars')
        if not os.path.exists(group_vars):
            os.mkdir(group_vars)
        with open(os.path.join(group_vars, group), 'w') as f:
            f.write("".join(code_lines[1:]))
        return {'status': 'ok', 'execution_count': self.execution_count,
                'payload': [], 'user_expressions': {}}

    def do_execute_play(self, code):
        logger = logging.getLogger('ansible_kernel.kernel.do_execute_play')
        if self.is_ansible_alive():
            self.do_shutdown(False)
        self.start_helper()
        code_data = yaml.load(code)
        logger.debug('code_data %r %s', code_data)
        logger.debug('code_data type: %s', type(code_data))
        self.current_play = code

        playbook = []

        current_play = yaml.load(self.current_play)
        playbook.append(current_play)
        tasks = current_play['tasks'] = current_play.get('tasks', [])
        current_play['roles'] = current_play.get('roles', [])
        current_play['roles'].insert(0, 'ansible_kernel_helpers')

        tasks.append({'pause_for_kernel': {'host': '127.0.0.1',
                                           'port': self.helper.pause_socket_port,
                                           'task_num': self.tasks_counter}})
        tasks.append(
            {'include_tasks': 'next_task{0}.yml'.format(self.tasks_counter)})
        self.tasks_counter += 1

        logger.debug(yaml.safe_dump(playbook, default_flow_style=False))

        with open(os.path.join(self.temp_dir, 'playbook.yml'), 'w') as f:
            f.write(yaml.safe_dump(playbook, default_flow_style=False))

        command = ['ansible-playbook', 'playbook.yml', '-vvvv']

        logger.info("command %s", command)

        env = os.environ.copy()
        env['ANSIBLE_KERNEL_STATUS_PORT'] = str(self.helper.status_socket_port)

        self.ansible_process = Popen(command, cwd=self.temp_dir, env=env)

        while True:
            logger.info("getting message")
            msg = self.queue.get()
            logger.info(msg)
            if isinstance(msg, StatusMessage):
                self.process_message(msg.message)
            elif isinstance(msg, TaskCompletionMessage):
                break

        return {'status': 'ok', 'execution_count': self.execution_count,
                'payload': [], 'user_expressions': {}}

    def do_execute_task(self, code):
        logger = logging.getLogger('ansible_kernel.kernel.do_execute_task')
        self.current_task = code
        try:
            code_data = yaml.load(code)
        except Exception:
            code_data = code
        logger.debug('code_data %s', code_data)
        logger.debug('code_data type: %s', type(code_data))

        if isinstance(code_data, basestring):
            if (code_data.endswith("?")):
                module = code_data[:-1].split()[-1]
            else:
                module = code_data.split()[-1]
            data = self.get_module_doc(module)
            payload = dict(
                source='page',
                data=data,
                start=0)
            logging.debug('payload %s', payload)
            return {'status': 'ok', 'execution_count': self.execution_count,
                    'payload': [payload], 'user_expressions': {}}
        elif isinstance(code_data, list):
            code_data = code_data[0]
        elif isinstance(code_data, dict):
            code_data = code_data
        elif code_data is None:
            return {'status': 'ok', 'execution_count': self.execution_count,
                    'payload': [], 'user_expressions': {}}
        else:
            logger.error('code_data %s unsupported type', type(code_data))

        interrupted = False
        try:

            tasks = []

            current_task_data = yaml.load(self.current_task)
            current_task_data['ignore_errors'] = True
            tasks.append(current_task_data)
            tasks.append({'pause_for_kernel': {'host': '127.0.0.1',
                                               'port': self.helper.pause_socket_port,
                                               'task_num': self.tasks_counter}})
            tasks.append(
                {'include_tasks': 'next_task{0}.yml'.format(self.tasks_counter)})
            self.tasks_counter += 1

            logger.debug(yaml.safe_dump(tasks, default_flow_style=False))

            with open(os.path.join(self.temp_dir, 'next_task{0}.yml'.format(self.tasks_counter - 2)), 'w') as f:
                f.write(yaml.safe_dump(tasks, default_flow_style=False))

            self.helper.pause_socket.send('Proceed')

            while True:
                logger.info("getting message")
                msg = self.queue.get()
                logger.info(msg)
                if isinstance(msg, StatusMessage):
                    self.process_message(msg.message)
                elif isinstance(msg, TaskCompletionMessage):
                    break

        except KeyboardInterrupt:
            logger.error(traceback.format_exc())

        if interrupted:
            return {'status': 'abort', 'execution_count': self.execution_count}

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

        logger = logging.getLogger('ansible_kernel.kernel.do_complete_task')
        logger.debug('code %r', code)

        if not code or code[-1] == ' ':
            return default

        found_module = False
        code_data = None
        try:
            code_data = yaml.load(code)
        except Exception:
            try:
                code_data = yaml.load(code + ":")
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

        logger = logging.getLogger('ansible_kernel.kernel.do_complete_task')
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
        logger = logging.getLogger('ansible_kernel.kernel.do_inspect')
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
        logger = logging.getLogger('ansible_kernel.kernel.do_inspect_module')

        data = dict()

        code_data = yaml.load(code)

        logger.debug("code_data %s", code_data)

        if isinstance(code_data, basestring):
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

    def get_module_doc(self, module):

        data = {}

        logger.debug("command %s", " ".join(
            ['ansible-doc', '-t', 'module', module]))
        p = Popen(['ansible-doc', '-t', 'module', module],
                  stdout=PIPE, stderr=STDOUT)
        p.wait()
        exitcode = p.returncode
        logger.debug('exitcode %s', exitcode)
        output = p.communicate()[0]
        logger.debug('output %s', output)
        data['text/plain'] = output

        return data

    def is_ansible_alive(self):
        if self.ansible_process is None:
            return False
        try:
            os.kill(self.ansible_process.pid, 0)
            return True
        except Exception:
            return False

    def do_shutdown(self, restart):

        logger = logging.getLogger('ansible_kernel.kernel.do_shutdown')

        current_process = psutil.Process(self.ansible_process.pid)
        children = current_process.children(recursive=True)
        for child in children:
            print('Child pid is {}'.format(child.pid))

        if self.is_ansible_alive():
            logger.info('killing ansible {0}'.format(self.ansible_process.pid))
            self.ansible_process.kill()
            for child in children:
                logger.info('killing ansible sub {0}'.format(child.pid))
                child.kill()

        logger.info('stopping helper')
        self.helper.stop()

        logger.info('clean up')
        self.ansible_process = None
        return {'status': 'ok', 'restart': restart}
