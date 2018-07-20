"""Ansible Playbook Exporter class"""

import six
import zipfile

from traitlets import default

from nbconvert.exporters.exporter import Exporter
from .ansible_playbook import AnsiblePlaybookExporter


DEFAULT_INVENTORY = '[all]\nlocalhost ansible_connection=local'


class AnsibleZipExporter(Exporter):
    """
    Exports an Ansible Bundle file.
    """

    export_from_notebook = 'Ansible Zip Bundle'
    output_mimetype = 'application/zip'

    @default('file_extension')
    def _file_extension_default(self):
        return '.zip'

    def from_notebook_node(self, nb, resources=None, **kw):
        nb_copy, resources = super(AnsibleZipExporter, self).from_notebook_node(nb, resources, **kw)

        print (nb_copy)

        resources_copy = resources.copy()

        contents = six.BytesIO()

        playbook_exporter = AnsiblePlaybookExporter()
        playbook, _ = playbook_exporter.from_notebook_node(nb, resources_copy, **kw)
        inventory = DEFAULT_INVENTORY
        ansible_cfg = None
        templates = []
        vars_files = []
        host_vars = []
        group_vars = []

        def get_file_name(source, prefix):
            return source[0][len(prefix):].strip()

        for cell in nb_copy.get('cells', []):
            print (cell)
            source = cell.get('source', '').strip().splitlines()
            if len(source) > 0:
                if source[0].startswith("#inventory"):
                    inventory = '\n'.join(source[1:])
                elif source[0].startswith("#ansible.cfg"):
                    ansible_cfg = '\n'.join(source[1:])
                elif source[0].startswith("#template"):
                    file_name = get_file_name(source, '#template')
                    templates.append((file_name, '\n'.join(source[1:])))
                elif source[0].startswith("#vars"):
                    file_name = get_file_name(source, '#vars')
                    vars_files.append((file_name, '\n'.join(source[1:])))
                elif source[0].startswith("#host_vars"):
                    file_name = get_file_name(source, '#host_vars')
                    host_vars.append((file_name, '\n'.join(source[1:])))
                elif source[0].startswith("#group_vars"):
                    file_name = get_file_name(source, '#group_vars')
                    group_vars.append((file_name, '\n'.join(source[1:])))

        zip_file = zipfile.ZipFile(contents, "a", zipfile.ZIP_DEFLATED, False)
        if ansible_cfg is not None:
            zip_file.writestr('ansible.cfg', ansible_cfg)

        zip_file.writestr('inventory', inventory)

        for template in templates:
            zip_file.writestr(*template)
        for vars_file in vars_files:
            zip_file.writestr(*vars_file)
        for host_vars_file in host_vars:
            zip_file.writestr(*host_vars_file)
        for group_vars_file in group_vars:
            zip_file.writestr(*group_vars_file)
        zip_file.writestr("playbook.yml", playbook)
        zip_file.close()

        output = contents.getvalue()

        return output, resources
