{%- extends 'null.tpl' -%}

{%- block header -%}
---
{% endblock header %}

{% block input -%}
{% if cell.source.strip().startswith("#inventory")%}
{% elif cell.source.strip().startswith("#host_vars")%}
{% elif cell.source.strip().startswith("#group_vars")%}
{% elif cell.source.strip().startswith("#play") %}
{% elif cell.source.strip().startswith("#task") %}
{% if cell.source.strip()[5:].strip() %}- {%endif%}{{cell.source.strip()[5:].strip() | indent(2) | trim}}
{%else%}
{% if cell.source.strip() %}- {%endif%}{{cell.source.strip() | indent(2) | trim}}
{%endif%}
{% endblock input %}


{% block markdowncell scoped %}
{{ cell.source | comment_lines }}
{% endblock markdowncell %}

{%- block footer -%}
...
{% endblock footer %}
