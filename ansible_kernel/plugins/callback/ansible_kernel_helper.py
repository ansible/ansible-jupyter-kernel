from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.plugins.callback import CallbackBase
from ansible.playbook.task_include import TaskInclude
import json
import zmq


from functools import wraps

DEBUG = True


def debug(fn):
    if DEBUG:
        @wraps(fn)
        def wrapper(*args, **kwargs):
            print('Calling', fn)
            ret_value = fn(*args, **kwargs)
            return ret_value
        return wrapper
    else:
        return fn


class CallbackModule(CallbackBase):
    '''
    This callback sends task results to ansible kernel and waits for the next task before proceeding.
    '''

    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'aggregate'
    CALLBACK_NAME = 'ansible_kernel_helper'
    CALLBACK_NEEDS_WHITELIST = True

    def __init__(self):
        super(CallbackModule, self).__init__()
        self.zmq_context = zmq.Context()
        self.socket = self.zmq_context.socket(zmq.PUSH)
        self.socket.connect("tcp://localhost:5556")
        self.task = None
        self.play = None
        self.hosts = []

    @debug
    def v2_playbook_on_setup(self):
        pass

    @debug
    def v2_playbook_on_handler_task_start(self, task):
        args = ''
        if not task.no_log:
            args = u', '.join(u'%s=%s' % a for a in task.args.items())
            args = u' %s' % args
        self.socket.send(json.dumps(['TaskStart', dict(task_name=task.get_name().strip(),
                                                       task_arg=args,
                                                       task_id=str(task._uuid))]))

    @debug
    def v2_runner_on_ok(self, result):
        if isinstance(result._task, TaskInclude):
            return
        delegated_vars = result._result.get('_ansible_delegated_vars', {})
        self._clean_results(result._result, result._task.action)
        self.socket.send(json.dumps(['TaskStatus', dict(task_name=self.task.get_name().strip(),
                                                        device_name=result._host.get_name(),
                                                        delegated_host_name=str(delegated_vars.get('ansible_host', '')),
                                                        changed=result._result.get('changed', False),
                                                        results=self._dump_results(result._result) if '_ansible_verbose_always' in result._result else None,
                                                        task_id=str(result._task._uuid))]))

    @debug
    def v2_runner_on_failed(self, result, ignore_errors=False):
        delegated_vars = result._result.get('_ansible_delegated_vars', {})
        self._clean_results(result._result, result._task.action)
        self.socket.send(json.dumps(['TaskStatus', dict(task_name=self.task.get_name().strip(),
                                                        device_name=result._host.get_name(),
                                                        delegated_host_name=str(delegated_vars.get('ansible_host', '')),
                                                        results=self._dump_results(result._result) if '_ansible_verbose_always' in result._result else None,
                                                        task_id=str(result._task._uuid))]))

    @debug
    def runner_on_unreachable(self, host, result, ignore_errors=False):
        self.socket.send(json.dumps(['TaskStatus', dict(task_name=self.task.get_name().strip(),
                                                        device_name=host,
                                                        task_id=str(self.task._uuid))]))

    @debug
    def v2_runner_item_on_skipped(self, result, ignore_errors=False):
        self.socket.send(json.dumps(['TaskStatus', dict(task_name=self.task.get_name().strip(),
                                                        device_name=result._host.get_name(),
                                                        task_id=str(result._task._uuid))]))

    @debug
    def DISABLED_v2_on_any(self, *args, **kwargs):
        self._display.display("--- play: {} task: {} ---".format(getattr(self.play, 'name', None), self.task))

        self._display.display("     --- ARGS ")
        for i, a in enumerate(args):
            self._display.display('     %s: %s' % (i, a))

        self._display.display("      --- KWARGS ")
        for k in kwargs:
            self._display.display('     %s: %s' % (k, kwargs[k]))

    @debug
    def v2_playbook_on_play_start(self, play):
        self.play = play
        self.hosts = play.get_variable_manager()._inventory.get_hosts()

        for host in self.hosts:
            self.socket.send(json.dumps(['DeviceStatus', dict(name=host.get_name())]))

    @debug
    def v2_playbook_on_task_start(self, task, is_conditional):
        self.task = task
        args = ''
        if not task.no_log:
            args = u', '.join(u'%s=%s' % a for a in task.args.items())
            args = u' %s' % args
        self.socket.send(json.dumps(['TaskStart', dict(task_name=task.get_name().strip(),
                                                       task_arg=args,
                                                       task_id=str(task._uuid))]))

    @debug
    def v2_playbook_on_stats(self, stats):
        for host in self.hosts:
            s = stats.summarize(host.get_name())
            status = "pass"
            status = "fail" if s['failures'] > 0 else status
            status = "fail" if s['unreachable'] > 0 else status
            self.socket.send(json.dumps(['DeviceStatus', dict(name=host.get_name())]))

    @debug
    def v2_playbook_on_no_hosts_remaining(self):
        pass

    def _handle_warnings(self, res):
        ''' display warnings, if enabled and any exist in the result '''
        warnings = []
        deprecations = []
        if 'warnings' in res and res['warnings']:
            for warning in res['warnings']:
                warnings.append(warning)
            del res['warnings']
        if 'deprecations' in res and res['deprecations']:
            for warning in res['deprecations']:
                deprecations.append(warning)
            del res['deprecations']
        return warnings, deprecations

    def _handle_exception(self, result):

        exception = None
        if 'exception' in result:
            exception = "The full traceback is:\n" + result['exception']
            del result['exception']
        return exception
