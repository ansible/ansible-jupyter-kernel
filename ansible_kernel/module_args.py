import pkg_resources
import yaml
with open(pkg_resources.resource_filename('ansible_kernel', 'module_args.yml')) as f:
    module_args = yaml.load(f.read())
module_args = module_args
