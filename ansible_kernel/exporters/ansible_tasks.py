"""Ansible tasks Exporter class"""

import os

from traitlets import default

from nbconvert.exporters.templateexporter import TemplateExporter


class AnsibleTasksExporter(TemplateExporter):
    """
    Exports an Ansible tasks file.
    """

    export_from_notebook = "Ansible Tasks"
    output_mimetype = 'text/yml'

    @default('file_extension')
    def _file_extension_default(self):
        return '.yaml'

    @default('template_file')
    def _template_file_default(self):
        return 'ansible_tasks.tpl'

    @property
    def template_path(self):
        return super(AnsibleTasksExporter, self).template_path + [os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")]
