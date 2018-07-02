import pkg_resources
import yaml
with open(pkg_resources.resource_filename('ansible_kernel', 'modules.yml')) as f:
    modules = yaml.load(f.read())
modules = modules
