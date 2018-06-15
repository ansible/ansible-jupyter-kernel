from ipykernel.kernelbase import Kernel

from subprocess import check_output

import os
import re
import yaml
from subprocess import Popen, STDOUT, PIPE
import logging
import traceback
import tempfile

from modules import modules

__version__ = '0.0.1'

logger = logging.getLogger('ansible_kernel.kernel')

version_pat = re.compile(r'version (\d+(\.\d+)+)')


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
            self._banner = check_output(['ansible', '--version']).decode('utf-8')
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
        self.temp_dir = tempfile.mkdtemp(prefix="ansible_kernel_playbook")
        self.current_play = {}
        self.current_task = []
        logger.debug(self.temp_dir)

    def process_output(self, output):
        if not self.silent:

            # Send standard output
            stream_content = {'name': 'stdout', 'text': output}
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
        elif code.strip().startswith("#host_vars"):
            return self.do_host_vars(code)
        elif code.strip().startswith("#group_vars"):
            return self.do_group_vars(code)
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

    def do_host_vars(self, code):
        logger = logging.getLogger('ansible_kernel.kernel.do_host_vars')
        host = code.strip().splitlines()[0][len('#host_vars'):].strip()
        logger.debug("host %s", host)
        host_vars = os.path.join(self.temp_dir, 'host_vars')
        if not os.path.exists(host_vars):
            os.mkdir(host_vars)
        with open(os.path.join(host_vars, host), 'w') as f:
            f.write(code)
        return {'status': 'ok', 'execution_count': self.execution_count,
                'payload': [], 'user_expressions': {}}

    def do_group_vars(self, code):
        logger = logging.getLogger('ansible_kernel.kernel.do_group_vars')
        group = code.strip().splitlines()[0][len('#group_vars'):].strip()
        logger.debug("group %s", group)
        group_vars = os.path.join(self.temp_dir, 'group_vars')
        if not os.path.exists(group_vars):
            os.mkdir(group_vars)
        with open(os.path.join(group_vars, group), 'w') as f:
            f.write(code)
        return {'status': 'ok', 'execution_count': self.execution_count,
                'payload': [], 'user_expressions': {}}

    def do_execute_play(self, code):
        logger = logging.getLogger('ansible_kernel.kernel.do_execute_play')
        code_data = yaml.load(code)
        logger.debug('code_data %r %s', code_data)
        logger.debug('code_data type: %s', type(code_data))
        self.current_play = code
        return {'status': 'ok', 'execution_count': self.execution_count,
                'payload': [], 'user_expressions': {}}

    def do_execute_task(self, code):
        logger = logging.getLogger('ansible_kernel.kernel.do_execute_task')
        self.current_task = code
        code_data = yaml.load(code)
        logger.debug('code_data %r %s', code_data)
        logger.debug('code_data type: %s', type(code_data))

        if isinstance(code_data, basestring):
            if (code_data.endswith("?")):
                module = code_data[:-1]
            else:
                module = code_data
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

            playbook = []

            current_play = yaml.load(self.current_play)
            playbook.append(current_play)
            tasks = current_play['tasks'] = current_play.get('tasks', [])

            tasks.append(yaml.load(self.current_task))

            logger.debug(yaml.safe_dump(playbook, default_flow_style=False))

            with open(os.path.join(self.temp_dir, 'playbook'), 'w') as f:
                f.write(yaml.safe_dump(playbook, default_flow_style=False))

            command = ['ansible-playbook',
                       '-i',
                       os.path.join(self.temp_dir, 'inventory'),
                       os.path.join(self.temp_dir, 'playbook')]
            logger.debug("command %s", " ".join(command))
            p = Popen(command, stdout=PIPE, stderr=STDOUT)
            p.wait()
            exitcode = p.returncode
            logger.debug('exitcode %s', exitcode)
            output = p.communicate()[0]
            logger.debug('output %s', output)
            self.process_output(output)
        except KeyboardInterrupt:
            logger.error(traceback.format_exc())

        if interrupted:
            return {'status': 'abort', 'execution_count': self.execution_count}

        if exitcode:
            error_content = {'execution_count': self.execution_count,
                             'ename': '', 'evalue': str(exitcode), 'traceback': []}

            self.send_response(self.iopub_socket, 'error', error_content)
            error_content['status'] = 'error'
            return error_content
        else:
            return {'status': 'ok', 'execution_count': self.execution_count,
                    'payload': [], 'user_expressions': {}}

    def do_complete(self, code, cursor_pos):
        code = code[:cursor_pos]
        default = {'matches': [], 'cursor_start': 0,
                   'cursor_end': cursor_pos, 'metadata': dict(),
                   'status': 'ok'}

        logger = logging.getLogger('ansible_kernel.kernel.do_complete')
        logger.debug('code %r', code)

        if not code or code[-1] == ' ':
            return default

        tokens = code.split()
        if not tokens:
            return default

        matches = []
        token = tokens[-1]
        start = cursor_pos - len(token)

        for module in modules:
            if module.startswith(token):
                matches.append(module)

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
            module = code_data.keys()[0]
        else:
            logger.warn('code type not supported %s', type(code_data))
            return {'status': 'ok', 'data': {}, 'metadata': {}, 'found': False}

        data.update(self.get_module_doc(module))

        return {'status': 'ok', 'data': data, 'metadata': {}, 'found': True}

    def get_module_doc(self, module):

        data = {}

        logger.debug("command %s", " ".join(['ansible-doc', '-t', 'module', module]))
        p = Popen(['ansible-doc', '-t', 'module', module], stdout=PIPE, stderr=STDOUT)
        p.wait()
        exitcode = p.returncode
        logger.debug('exitcode %s', exitcode)
        output = p.communicate()[0]
        logger.debug('output %s', output)
        data['text/plain'] = output

        return data
