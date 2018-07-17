import logging
FORMAT = "[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
logging.basicConfig(filename='ansible_kernel.log', level=logging.DEBUG, format=FORMAT) # noqa
from ipykernel.kernelapp import IPKernelApp
from .kernel import AnsibleKernel
IPKernelApp.launch_instance(kernel_class=AnsibleKernel)
