import json
import os
from setuptools import setup, find_packages
from setuptools.command.install import install


class Installer(install):
    def run(self):
        # Regular install
        install.run(self)

        # Post install
        print('Installing Ansible Kernel kernelspec')
        from jupyter_client.kernelspec import KernelSpecManager
        from IPython.utils.tempdir import TemporaryDirectory
        kernel_json = {
            "argv": ["python", "-m", "ansible_kernel", "-f", "{connection_file}"],
            "codemirror_mode": "yaml",
            "display_name": "Ansible",
            "language": "ansible"
        }
        with TemporaryDirectory() as td:
            os.chmod(td, 0o755)
            with open(os.path.join(td, 'kernel.json'), 'w') as f:
                json.dump(kernel_json, f, sort_keys=True)
            ksm = KernelSpecManager()
            ksm.install_kernel_spec(td, 'ansible', user=self.user, replace=True, prefix=self.prefix)


setup(
    name='ansible-kernel',
    version='1.0.0',
    description='An Ansible kernel for Jupyter notebooks',
    long_description='An Ansible kernel for Jupyter notebooks',
    long_description_content_type='text/plain',
    packages=find_packages(),
    package_data={'ansible_kernel': ['templates/ansible_playbook.tpl',
                                     'templates/ansible_tasks.tpl',
                                     'modules.yml',
                                     'module_args.yml']},
    cmdclass={'install': Installer},
    license='Apache',
    install_requires=[
        'ansible',
        'ansible-runner>=1.1.0',
        'PyYAML',
        'psutil',
        'jupyter',
        'tqdm',
        'docopt',
        'six',
        'ipywidgets',
    ],
    entry_points={
        "nbconvert.exporters": [
            'ansible_tasks=ansible_kernel.exporters:AnsibleTasksExporter',
            'ansible_playbook=ansible_kernel.exporters:AnsiblePlaybookExporter',
            'ansible_zip=ansible_kernel.exporters:AnsibleZipExporter']
    },
    zip_safe=False
)
