from ansible.plugins.action import ActionBase

import zmq


class ActionModule(ActionBase):

    BYPASS_HOST_LOOP = True

    def run(self, tmp=None, task_vars=None):
        print ('pause_for_kernel')
        if task_vars is None:
            task_vars = dict()
        host = self._task.args.get('host', None)
        port = self._task.args.get('port', None)
        task_num = self._task.args.get('task_num', None)
        print (task_num)
        result = super(ActionModule, self).run(tmp, task_vars)

        context = zmq.Context()
        socket = context.socket(zmq.REQ)
        socket.setsockopt(zmq.LINGER, 0)
        print ('connecting...')
        socket.connect("tcp://{0}:{1}".format(host, port))
        print ('connected')
        print ('sending...')
        socket.send_string("{0}".format(task_num))
        print ('sent')
        print ('waiting...')
        print (socket.recv())
        print ('received')
        print ('closing...')
        socket.close()
        print ('closed')
        return result
