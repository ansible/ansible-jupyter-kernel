import ipywidgets as widgets
from traitlets import Unicode


class VaultPassword(widgets.Password):
    ansible_kernel_property = Unicode('vault_password').tag(sync=True)


class SSHPassword(widgets.Password):
    ansible_kernel_property = Unicode('ssh_password').tag(sync=True)


class SSHPrivateKey(widgets.Password):
    ansible_kernel_property = Unicode('ssh_private_key').tag(sync=True)
