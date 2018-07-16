#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Usage:
    convert_playbook [options] <playbook> [<output>] [(--vars-file <vars-file>)]... [(--template-file <template-file>)]...

Options:
    -h, --help           Show this page
    --debug              Show debug logging
    --verbose            Show verbose logging
    --ansible-cfg=<a>
    --inventory=<i>
    --host-vars-files-dir=<h>
    --group-vars-files-dir=<g>
    --templates-dir=<t>
    --vars-files-dir=<v>
"""
from docopt import docopt
import logging
import sys
import yaml
import json
import os
import glob
import functools

NB_FORMAT = 4
NB_FORMAT_MINOR = 2
METADATA = json.loads('''{
  "kernelspec": {
   "display_name": "Ansible",
   "language": "ansible",
   "name": "ansible"
  },
  "language_info": {
   "codemirror_mode": "yaml",
   "file_extension": ".yml",
   "mimetype": "text/yaml",
   "name": "ansible"
  }
}''')

logger = logging.getLogger('convert_playbook')


yaml_dump = functools.partial(yaml.safe_dump, default_flow_style=False)
json_dump = functools.partial(json.dumps, indent=4, sort_keys=True, separators=(',', ': '))


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

    playbook_file = os.path.abspath(parsed_args['<playbook>'])
    ansible_cfg = parsed_args['--ansible-cfg']
    inventory = parsed_args['--inventory']
    templates_dir = parsed_args['--templates-dir']
    vars_files_dir = parsed_args['--vars-files-dir']
    group_vars_files_dir = parsed_args['--group-vars-files-dir']
    host_vars_files_dir = parsed_args['--host-vars-files-dir']
    vars_files = parsed_args['<vars-file>']
    template_files = parsed_args['<template-file>']
    print (parsed_args)
    if not os.path.exists(playbook_file):
        print ("No playbook file found at {0}".format(playbook_file))
        return 1

    if ansible_cfg is not None:
        ansible_cfg = os.path.abspath(ansible_cfg)
        if not os.path.exists(ansible_cfg):
            print ("No ansible.cfg file found at {0}".format(ansible_cfg))
            return 1

    if inventory is not None:
        inventory = os.path.abspath(inventory)
        if not os.path.exists(inventory):
            print ("No inventory file found at {0}".format(inventory))
            return 1

    if templates_dir is not None:
        if not os.path.exists(templates_dir):
            print ("No templates directory found at {0}".format(templates_dir))
            return 1

    if vars_files_dir is not None:
        if not os.path.exists(vars_files_dir):
            print ("No vars files directory found at {0}".format(vars_files_dir))
            return 1

    if host_vars_files_dir is not None:
        if not os.path.exists(host_vars_files_dir):
            print ("No host vars directory found at {0}".format(host_vars_files_dir))
            return 1

    if group_vars_files_dir is not None:
        if not os.path.exists(group_vars_files_dir):
            print ("No group vars directory found at {0}".format(group_vars_files_dir))
            return 1
    if vars_files is not None:
        for vars_file in vars_files:
            if not os.path.exists(vars_file):
                print ("No vars file found at {0}".format(vars_file))
                return 1
    if template_files is not None:
        for template_file in template_files:
            if not os.path.exists(template_file):
                print ("No template file found at {0}".format(vars_file))
                return 1


    if parsed_args['<output>'] is not None:
        output_file = os.path.abspath(parsed_args['<output>'])
    else:
        base_name, _ = os.path.splitext(playbook_file)
        output_file = os.path.abspath(base_name + ".ipynb")

    with open(playbook_file) as f:
        content = f.read()
        plays = yaml.load(content)

    cells = []

    def add_code_cell(cell_type, code):
        source = "#{0}\n{1}".format(cell_type, code)
        new_cell = dict(cell_type="code",
                        metadata={},
                        execution_count=None,
                        outputs=[],
                        source=source.splitlines(True))
        print (new_cell)
        cells.append(new_cell)


    if ansible_cfg is not None:
        with open(ansible_cfg) as f:
            add_code_cell('ansible.cfg', f.read())

    if inventory is not None:
        with open(inventory) as f:
            add_code_cell('inventory', f.read())

    if templates_dir is not None:
        for template in glob.glob(templates_dir, '*'):
            with open(template) as f:
                add_code_cell('template {0}'.format(template), f.read())

    if template_files is not None:
        for template_file in template_files:
            with open(template_file) as f:
                add_code_cell('template_file {0}'.format(template_file), f.read())

    if vars_files_dir is not None:
        for vars_file in glob.glob(vars_files_dir, '*'):
            with open(vars_file) as f:
                add_code_cell('vars_file {0}'.format(vars_file), f.read())

    if vars_files is not None:
        for vars_file in vars_files:
            with open(vars_file) as f:
                add_code_cell('vars_file {0}'.format(vars_file), f.read())

    if group_vars_files_dir is not None:
        for group_vars in glob.glob(group_vars_files_dir, '*'):
            with open(group_vars) as f:
                add_code_cell('group_vars {0}'.format(group_vars), f.read())

    if host_vars_files_dir is not None:
        for host_vars in glob.glob(host_vars_files_dir, '*'):
            with open(host_vars) as f:
                add_code_cell('host_vars {0}'.format(host_vars), f.read())


    for play in plays:
        play_copy = play.copy()
        if 'tasks' in play_copy:
            del play_copy['tasks']
        add_code_cell('play', yaml_dump(play_copy))
        for task in play.get('tasks', []):
            add_code_cell('task', yaml_dump(task))


    with open(output_file, 'w') as f:
        f.write(json_dump(dict(cells=cells,
                               metadata=METADATA,
                               nbformat=NB_FORMAT,
                               nbformat_minor=NB_FORMAT_MINOR)))

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
