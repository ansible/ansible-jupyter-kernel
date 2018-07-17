from ansible.plugins.action import ActionBase

import zmq

DEBUG = False


def debug(format_str, *args):
    if DEBUG:
        if args:
            print (format_str % args)
        else:
            print (format_str)


class ActionModule(ActionBase):

    BYPASS_HOST_LOOP = True

    def run(self, tmp=None, task_vars=None):
        debug('pause_for_kernel')
        if task_vars is None:
            task_vars = dict()
        host = self._task.args.get('host', None)
        port = self._task.args.get('port', None)
        task_num = self._task.args.get('task_num', None)
        debug("task_num %s", task_num)
        result = super(ActionModule, self).run(tmp, task_vars)

        context = zmq.Context()
        socket = context.socket(zmq.REQ)
        socket.setsockopt(zmq.LINGER, 0)
        debug('connecting...')
        socket.connect("tcp://{0}:{1}".format(host, port))
        debug('connected')
        debug('sending...')
        socket.send_string("{0}".format(task_num))
        debug('sent')
        debug('waiting...')
        debug(socket.recv())
        debug('received')
        debug('closing...')
        socket.close()
        debug('closed')
        return result
