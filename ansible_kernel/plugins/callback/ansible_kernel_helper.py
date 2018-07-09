from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.plugins.callback import CallbackBase
from ansible.playbook.task_include import TaskInclude
import json
import zmq
import os


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
        self.status_port = os.getenv('ANSIBLE_KERNEL_STATUS_PORT')
        if self.status_port:
            self.socket.connect("tcp://127.0.0.1:{0}".format(self.status_port))
        else:
            self.socket = None
        self.task = None
        self.play = None
        self.hosts = []

    def _format_output(self, result):
        if 'stdout_lines' in result:
            return '\n'.join(result['stdout_lines'])
        return ""

    def _format_error(self, result):
        if 'stderr_lines' in result:
            return '\n'.join(result['stderr_lines'])
        return ""

    def _dump_results(self, result):

        r = result.copy()
        if 'invocation' in r:
            del r['invocation']
        if 'stdout' in r:
            if r['stdout']:
                r['stdout'] = '[see below]'
        if 'stdout_lines' in r:
            if r['stdout_lines']:
                r['stdout_lines']  = '[removed for clarity]'
        if 'stderr' in r:
            if r['stderr']:
                r['stderr'] = '[see below]'
        if 'stderr_lines' in r:
            if r['stderr_lines']:
                r['stderr_lines']  = '[removed for clarity]'
        if 'changed' in r:
            del r['changed']
        if 'reason' in r:
            return r['reason']
        return super(CallbackModule, self)._dump_results(r, indent=4, sort_keys=True)


    @debug
    def v2_playbook_on_setup(self):
        pass

    @debug
    def v2_playbook_on_handler_task_start(self, task):
        if self.socket is None:
            return
        args = ''
        if not task.no_log:
            args = u', '.join(u'%s=%s' % a for a in task.args.items())
            args = u' %s' % args
        self.socket.send_string(json.dumps(['TaskStart', dict(task_name=task.get_name().strip(),
                                                              task_arg=args,
                                                              task_id=str(task._uuid))]))

    @debug
    def v2_runner_on_ok(self, result):
        if self.socket is None:
            return
        if isinstance(result._task, TaskInclude):
            return
        delegated_vars = result._result.get('_ansible_delegated_vars', {})
        self._clean_results(result._result, result._task.action)
        self.socket.send_string(json.dumps(['TaskStatus', dict(task_name=self.task.get_name().strip(),
                                                               device_name=result._host.get_name(),
                                                               delegated_host_name=str(delegated_vars.get('ansible_host', '')),
                                                               changed=result._result.get('changed', False),
                                                               failed=False,
                                                               unreachable=False,
                                                               skipped=False,
                                                               results=self._dump_results(result._result),
                                                               output=self._format_output(result._result),
                                                               error=self._format_error(result._result),
                                                               task_id=str(result._task._uuid))]))

    @debug
    def v2_runner_on_failed(self, result, ignore_errors=False):
        if self.socket is None:
            return
        delegated_vars = result._result.get('_ansible_delegated_vars', {})
        self._clean_results(result._result, result._task.action)
        self.socket.send_string(json.dumps(['TaskStatus', dict(task_name=self.task.get_name().strip(),
                                                               device_name=result._host.get_name(),
                                                               changed=False,
                                                               failed=True,
                                                               unreachable=False,
                                                               skipped=False,
                                                               delegated_host_name=str(delegated_vars.get('ansible_host', '')),
                                                               results=self._dump_results(result._result),
                                                               output=self._format_output(result._result),
                                                               error=self._format_error(result._result),
                                                               task_id=str(result._task._uuid))]))

    @debug
    def runner_on_unreachable(self, host, result, ignore_errors=False):
        if self.socket is None:
            return
        self.socket.send_string(json.dumps(['TaskStatus', dict(task_name=self.task.get_name().strip(),
                                                               device_name=host,
                                                               changed=False,
                                                               failed=False,
                                                               unreachable=True,
                                                               skipped=False,
                                                               task_id=str(self.task._uuid))]))

    @debug
    def v2_runner_item_on_skipped(self, result, ignore_errors=False):
        if self.socket is None:
            return
        self.socket.send_string(json.dumps(['TaskStatus', dict(task_name=self.task.get_name().strip(),
                                                               changed=False,
                                                               failed=False,
                                                               unreachable=False,
                                                               skipped=True,
                                                               task_id=str(result._task._uuid))]))

    @debug
    def DISABLED_v2_on_any(self, *args, **kwargs):
        if self.socket is None:
            return
        self._display.display("--- play: {} task: {} ---".format(getattr(self.play, 'name', None), self.task))

        self._display.display("     --- ARGS ")
        for i, a in enumerate(args):
            self._display.display('     %s: %s' % (i, a))

        self._display.display("      --- KWARGS ")
        for k in kwargs:
            self._display.display('     %s: %s' % (k, kwargs[k]))

    @debug
    def v2_playbook_on_play_start(self, play):
        if self.socket is None:
            return
        self.play = play
        self.hosts = play.get_variable_manager()._inventory.get_hosts()

        for host in self.hosts:
            self.socket.send_string(json.dumps(['DeviceStatus', dict(name=host.get_name())]))

    @debug
    def v2_playbook_on_task_start(self, task, is_conditional):
        if self.socket is None:
            return
        self.task = task
        args = ''
        if not task.no_log:
            args = u', '.join(u'%s=%s' % a for a in task.args.items())
            args = u' %s' % args
        self.socket.send_string(json.dumps(['TaskStart', dict(task_name=task.get_name().strip(),
                                                              task_arg=args,
                                                              task_id=str(task._uuid))]))

    @debug
    def v2_playbook_on_stats(self, stats):
        if self.socket is None:
            return
        for host in self.hosts:
            s = stats.summarize(host.get_name())
            status = "pass"
            status = "fail" if s['failures'] > 0 else status
            status = "fail" if s['unreachable'] > 0 else status
            self.socket.send_string(json.dumps(['DeviceStatus', dict(name=host.get_name())]))
        self.socket.send_string(json.dumps(['PlaybookEnded', dict()]))

    @debug
    def v2_playbook_on_no_hosts_remaining(self):
        if self.socket is None:
            return
