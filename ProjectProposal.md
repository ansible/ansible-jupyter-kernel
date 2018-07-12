
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
* [Jun 27 2018] @rrrrrrrix: holy shit
* [July 9th 2018 10:45 AM ] shanemcd: awesome. i love this btw.


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


Road Map
========


Initial Project Evaluation
---------------------------
* Time: 2 days (100% done)
* 1 resource: 1 architect
* Result: this document


Prototype
---------
* Time: 1 week (100% done)
* 1 resource: Python/Javascript
* Result: Run contents of a notebook cell as a task in an Ansible playbook and
    display output of after it finishes on the notebook.

Tasks:

- Add ansible kernel that keeps a play context running. See ipython/ipykernel for an example of a kernel. (done)
- Add tab completion for ansible modules (done)
- Add tab completion for ansible module arguments (done)
- Add documentation integration (done)
- Add export to playbook (done)
- Rewrite a few of the Ansible for Networks tutorials with this


Release 0 Beta (Early Access)
-----------------------------
* Time: 3 weeks
* 2 resources: 1 python, 1 tester, +community
* Result:  Improve prototype to a useful point and release as a stand-alone module
for use the Juypter notebooks and add to AWX.

Tasks:

- Legal license approval (done)
- Release manager approval (done)
- Add to public repo under ansible (done)
- Add all the standard python packaging files (done)
- Push module to PYPI (done)
- Push container to dockerhub (done)
- Add awx integration
- Test by converting tutorials to notebooks
- Write blog post
- Write AnsibleFest talk (submitted talk)
- Demo recordings


Release 1 Product
------------------------------------
* Time: 3 months work
* 4 resources: 1 python, 1 javascript, 1 designer, 1 tester
* Result: A product useful for building ansible playbooks

Tasks:

- Playbook importing
- Change branding to Tower with Jupyter
- Integrate with Tower
- Add RBAC
- Add integration with projects
- Add integration with inventories

Result:  A web based UI that can build simple playbooks consisting of tasks


Release 2 Product
------------------------------------
* Time: 3 months work
* 5 resources: 1 python, 2 javascript, 1 designer, 1 tester
* Result: A product for useful for building and editing most playbooks

Tasks:

- Complete conversion of Jupyter Notebook to Ansible Playook builder

Release 3 Product
------------------------------------
* Time: 3 months work
* 4 resources: 1 python, 1 javascript, 1 designer, 1 tester
* Result:  A web based UI that can build most playbooks and roles

Tasks:

- Add features for building roles


Release 4 Product
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

- Very few modifications to Juypter repos  are needed to support Ansible as a kernel.
    (only changes to nbconvert were needed for exporting playbooks)
- Jupyter Notebook is already used in AWX development for debug/management of django.
- Jupyter Notebook is architected in multiple repositories which allows for plugging
in code to support ansible fairly easily.
- BSD licensed projects can be re-licensed
- Vendoring Jupyter source into Tower should be easy enough. Although upstream patches would have to be applied manually.
- The Ansible kernel could be a part of core to reduce cost of maintaining the strict version requirements for future releases.

Proposal Review
---------------

* This is hot
* This is cool
* Does this have a git workflow?  No.
* How many ansible users would this use this feature?  About 50%.
* It's probably more for new users than power users.
* It might be useful for power users.
* Integration with Ansible Runner would be useful for both projects.
* Integration with Tower may come at a later date.
* Release as an OS community project.


Blog and Talk Ideas
-------------------

* Ansible Playbook builder using Jupyter and Ansible Kernel for the Ansible community
* Setting up AWS with Ansible and Jupyter targeting the Jupyter community

