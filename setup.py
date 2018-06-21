from setuptools import setup, find_packages

setup(
    name='ansible_kernel',
    version='0.0.1',
    packages=find_packages(),
    install_requires=[
        'PyYAML',
    ],
    zip_safe=False
)
