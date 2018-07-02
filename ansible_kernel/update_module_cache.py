#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
Usage:
    update_module_cache [options]

Options:
    -h, --help        Show this page
    --debug            Show debug logging
    --verbose        Show verbose logging
"""
from docopt import docopt
import logging
import sys
import yaml
from tqdm import tqdm
from subprocess import Popen, STDOUT, PIPE
import pkg_resources

logger = logging.getLogger('update_module_cache')


def parse_ansible_doc(output):
    lines = output.splitlines()
    lines.reverse()

    args = []

    state = 'start'

    while lines:

        line = lines.pop()

        # start
        if state == 'start' and line.startswith("OPTIONS"):
            state = 'options'
        elif state == 'start':
            continue
        elif state == 'options' and line.startswith("AUTHOR"):
            break
        elif state == 'options' and line.startswith("EXAMPLES"):
            break
        elif state == 'options' and line.startswith("NOTES"):
            break
        elif state == 'options' and line.startswith("REQUIREMENTS"):
            break
        elif state == 'options' and line.startswith("- "):
            args.append(line[2:])
        elif state == 'options' and line.startswith("= "):
            args.append(line[2:])

    return args


def main(args=None):
    if args is None:
        args = sys.argv[1:]
    parsed_args = docopt(__doc__, args)
    if parsed_args['--debug']:
        logging.basicConfig(level=logging.DEBUG)
    elif parsed_args['--verbose']:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARNING)
    print ("Updating module cache")
    p = Popen(['ansible-doc', '-t', 'module', '-l'],
              stdout=PIPE, stderr=STDOUT)
    output = p.communicate()[0]

    modules = []
    module_args = {}
    for line in output.splitlines():
        module_name = (line.split(' ')[0])
        modules.append(module_name)

    with open(pkg_resources.resource_filename('ansible_kernel', 'modules.yml'), 'w') as f:
        f.write(yaml.safe_dump(modules, default_flow_style=False))

    for module_name in tqdm(modules):
        p = Popen(['ansible-doc', '-t', 'module', module_name],
                  stdout=PIPE, stderr=STDOUT)
        output = p.communicate()[0]
        args = parse_ansible_doc(output)
        module_args[module_name] = args

    with open(pkg_resources.resource_filename('ansible_kernel', 'module_args.yml'), 'w') as f:
        f.write(yaml.safe_dump(module_args, default_flow_style=False))


    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
