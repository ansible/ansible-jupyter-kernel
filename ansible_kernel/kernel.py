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
        self.inventory = "localhost"

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
        elif code.strip().startswith("#task"):
            return self.do_execute_module(code)
        elif code.strip().startswith("#play"):
            logger.error("#play not supported")
            return {'status': 'ok', 'execution_count': self.execution_count,
                    'payload': [], 'user_expressions': {}}
        else:
            return self.do_execute_module(code)

    def do_inventory(self, code):
        logger = logging.getLogger('ansible_kernel.kernel.do_inventory')
        self.inventory = code
        logger.info("inventory set to %s", self.inventory)
        return {'status': 'ok', 'execution_count': self.execution_count,
                'payload': [], 'user_expressions': {}}

    def do_execute_module(self, code):
        logger = logging.getLogger('ansible_kernel.kernel.do_execute_module')
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

        target = 'all'

        if 'host' in code_data:
            target = code_data['host']
            del code_data['host']

        if 'name' in code_data:
            del code_data['name']

        for module, args in code_data.items():
            if isinstance(args, dict):
                logger.debug('is dict')
                m_args = ' '.join(['{0}="{1}"'.format(k,
                                                      ",".join(v) if isinstance(v, list) else v) for k, v in args.items()])
            elif isinstance(args, basestring):
                logger.debug('is string')
                m_args = args
            elif args is None:
                logger.debug('is None')
                m_args = ''
            else:
                logger.debug('is not supported %s', type(args))
                raise Exception("Not supported type {0}".format(type(args)))
            interrupted = False
            try:
                inventory_handle, inventory_name = tempfile.mkstemp(prefix="inventory")
                os.write(inventory_handle, self.inventory)
                os.close(inventory_handle)
                logger.debug("command %s", " ".join(['ansible', '-m', module, "-a", "{0}".format(m_args), '-i', inventory_name, target]))
                p = Popen(['ansible', '-m', module, "-a", "{0}".format(m_args), '-i', inventory_name, target], stdout=PIPE, stderr=STDOUT)
                p.wait()
                exitcode = p.returncode
                logger.debug('exitcode %s', exitcode)
                output = p.communicate()[0]
                logger.debug('output %s', output)
                self.process_output(output)
            except KeyboardInterrupt:
                logger.error(traceback.format_exc())
            finally:
                os.unlink(inventory_name)

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
