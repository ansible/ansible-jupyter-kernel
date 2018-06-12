from ipykernel.kernelbase import Kernel

from subprocess import check_output

import re
import yaml
from subprocess import Popen, STDOUT, PIPE

__version__ = '0.0.1'

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

    def __init__(self, **kwargs):
        Kernel.__init__(self, **kwargs)

    def process_output(self, output):
        if not self.silent:

            # Send standard output
            stream_content = {'name': 'stdout', 'text': output}
            self.send_response(self.iopub_socket, 'stream', stream_content)

    def do_execute(self, code, silent, store_history=True,
                   user_expressions=None, allow_stdin=False):
        self.silent = silent
        if not code.strip():
            return {'status': 'ok', 'execution_count': self.execution_count,
                    'payload': [], 'user_expressions': {}}

        code_data = yaml.load(code)

        for module, args in code_data.items():
            if isinstance(args, dict):
                m_args = ' '.join(['{0}="{1}"'.format(k, v) for k, v in args.items()])
            elif isinstance(args, basestring):
                m_args = args
            elif args is None:
                m_args = ''
            else:
                raise Exception("Not supported type {0}".format(type(args)))
            interrupted = False
            try:
                #self.process_output(' '.join(['ansible', '-m', module, "-a", "{0}".format(m_args), '-i', 'localhost', 'localhost']))
                p = Popen(['ansible', '-m', module, "-a", "{0}".format(m_args), '-i', 'localhost', 'localhost'], stdout=PIPE, stderr=STDOUT)
                p.wait()
                exitcode = p.returncode
                self.process_output(p.communicate()[0])
            except KeyboardInterrupt:
                self.bashwrapper._expect_prompt()

        if interrupted:
            return {'status': 'abort', 'execution_count': self.execution_count}

        exitcode = 1

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

        if not code or code[-1] == ' ':
            return default

        tokens = code.replace(';', ' ').split()
        if not tokens:
            return default

        matches = []
        token = tokens[-1]
        start = cursor_pos - len(token)

        if token[0] == '$':
            # complete variables
            cmd = 'compgen -A arrayvar -A export -A variable %s' % token[1:]  # strip leading $
            output = self.bashwrapper.run_command(cmd).rstrip()
            completions = set(output.split())
            # append matches including leading $
            matches.extend(['$' + c for c in completions])
        else:
            # complete functions and builtins
            cmd = 'compgen -cdfa %s' % token
            output = self.bashwrapper.run_command(cmd).rstrip()
            matches.extend(output.split())

        if not matches:
            return default
        matches = [m for m in matches if m.startswith(token)]

        return {'matches': sorted(matches), 'cursor_start': start,
                'cursor_end': cursor_pos, 'metadata': dict(),
                'status': 'ok'}
