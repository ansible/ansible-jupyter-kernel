from ipykernel.kernelapp import IPKernelApp
from .kernel import AnsibleKernel
IPKernelApp.launch_instance(kernel_class=AnsibleKernel)
