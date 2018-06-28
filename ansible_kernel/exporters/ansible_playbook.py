"""Ansible Playbook Exporter class"""

import os

from traitlets import default

from nbconvert.exporters.templateexporter import TemplateExporter


class AnsiblePlaybookExporter(TemplateExporter):
    """
    Exports an Ansible Playbook file.
    """

    export_from_notebook = 'Ansible Playbook'
    output_mimetype = 'text/yml'

    @default('file_extension')
    def _file_extension_default(self):
        return '.yml'

    @default('template_file')
    def _template_file_default(self):
        return 'ansible_playbook.tpl'

    @property
    def template_path(self):
        return super(AnsiblePlaybookExporter, self).template_path + [os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")]

