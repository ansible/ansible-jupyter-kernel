
Project: Jupyter Notebook as a Playbook Builder
===============================================

Problem
-------

Getting started with Ansible requires an understanding of the Linux command line shells.
Network engineers may be new to Linux command line shells and this will reduce the
number of customers and/or increase how long it will take for them to get started.

Solution
--------

Provide a way to build playbooks interactively and to debug interactively by
using a Jupyter Notebook style interface with ansible play cells and
ansible task cells.   This web interface could be provided with AWX/Tower
to remove the need to understand Linux for playbook developers.


Pitch Concept and Demo to interested parties
--------------------------------------------

Jupyter notebook + ansible cell type = web-based ansible playbook builder


Reactions
---------

* [Fri June 8th 10:46 AM] matburt:  :open_mouth: :mind-blown.gif:
* [Tue Jun 12 12:41:09 EDT 2018] chrismeyers:  that'd be hot.  patent that.
* [Tue Jun 12 15:44:31 EDT 2018] matburt :open_mouth: wowsa how do I get this hotness?
* [Wed Jun 13 2018] docschick: You've earned your brownies.


Jupyter Notebook Technical Details
----------------------------------

* Front end javascript
* Back end python
* Back end is split up into many projects/repositories
  + https://github.com/jupyter/notebook
  + https://github.com/ipython/ipykernel
  + https://github.com/jupyter/jupyter_core
  + https://github.com/jupyter/jupyter_client
  + https://github.com/jupyter/nbformat
  + https://github.com/jupyter/nbconvert

* Depends on tornado for event loop
* Depends on ZMQ for messaging
* Client-server communication is via a REST API + a web socket.
  + See: https://github.com/jupyter/jupyter/wiki/Jupyter-Notebook-Server-API

* There are already many kernels for other languages:
  + https://github.com/jupyter/jupyter/wiki/Jupyter-kernels
  + http://jupyter-client.readthedocs.io/en/latest/kernels.html

* Kernels are very easy to write with the given base class that handles messaging.
  +  See: https://github.com/ipython/ipykernel/blob/master/ipykernel/kernelbase.py



Initial Project Evaluation
---------------------------
* Time: 2 days (100% done)
* 1 resource: 1 architect
* Result: this document


Prototype
---------
* Time: 1 week (50% done)
* 1 resource: Python/Javascript
* Result: Run contents of a notebook cell as an Ansible ad-hoc command and
    display output of after it finishes on the notebook.

Tasks:

- Add ansible ad-hoc kernel.  See ipython/ipykernel for an example of a kernel. (wip)
- Add tab completion for ansible modules (done)
- Add tab completion for ansible module arguments
- Add documentation integration (done)
- Add export to task list for use with include_tasks (done)
- Rewrite a few of the Ansible for Networks tutorials with this

Release 1 Product (Proposed for 3.4)
------------------------------------
* Time: 3 months work
* 4 resources: 1 python, 1 javascript, 1 designer, 1 tester
* Result: A product useful for building ansible task files for used in include_tasks

Tasks:

- Playbook importing
- Add ansible kernel that keeps a play context running. See ipython/ipykernel for an example of a kernel.
- Change branding to Tower with Jupyter
- Integrate with Tower
- Add RBAC
- Add integration with projects
- Add integration with inventories

Result:  A web based UI that can build simple playbooks consisting of tasks


Release 2 Product (Proposed for 3.5)
------------------------------------
* Time: 3 months work
* 5 resources: 1 python, 2 javascript, 1 designer, 1 tester
* Result: A product for useful for building and editing most playbooks

Tasks:

- Complete conversion of Jupyter Notebook to Ansible Playook builder

Release 3 Product (Proposed for 3.6)
------------------------------------
* Time: 3 months work
* 4 resources: 1 python, 1 javascript, 1 designer, 1 tester
* Result:  A web based UI that can build most playbooks and roles

Tasks:

- Add features for building roles


Release 4 Product (Proposed for 3.7)
------------------------------------
* Time: 3 months work
* 5 resources: 1 python, 2 javascript, 1 designer, 1 tester
* Result:  A web based UI that can build most playbooks, roles, and modules

Tasks:

- Add features for building modules

Risks
-----

- Jupyter has a BSD license with modifications.
- Many repositories would need vendoring or repackage into one repository
- Managing upstream changes from a project with many changes.
- Managing community reactions to a Jupyter notebook fork.
- Adding new dependencies to production Tower
- We may have to add an Ansible kernel for each version of Ansible that we want to support.

Risk Mitigation
---------------

- Jupyter Notebook is already used in AWX development for debug/management of django.
- Jupyter Notebook is architected in multiple repositories which allows for plugging
in code to support ansible fairly easily.
- BSD licensed projects can be re-licensed
- Vendoring Jupyter source into Tower should be easy enough. Although upstream patches would have to be applied manually.
- The Ansible kernel could be a part of core to reduce cost of maintaining the strict version requirements for future releases.



