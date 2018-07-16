# Changelog

## [0.6.0] - 2018-07-16

### Added

- Ansible playbook to Jupyter notebook format converter
- Export a notebook to an Ansible bundle zip file containing the playbook, inventory, etc

## [0.5.0] - 2018-07-10

### Fixes

- Python 3: Multiple fixes for package names that have changed
- Python 3: String to/from byte conversions.

### Changed

- Improves shell output display

## [0.4.2] - 2018-07-09

### Fixes

- Kernel crash when ansible-playbook shuts down.

## [0.4.1] - 2018-07-08

### Fixes

- Fixed connection to localhost to use local connection type

### Added

- Dockerfile

## [0.4] - 2018-07-05

### Fixes
- Python 3: Encodes unicode messages for ZMQ properly

### Added
- Module argument cache
- Role support
- Automatic Ansible Galaxy role installation

## [0.3] - 2018-06-28
### Fixes
- Fixed packaging

## [0.2] - 2018-06-28
### Added
- Export notebook to Ansible playbook
- Export notebook to Ansible tasks file
- Error handling in play and task cells
- Feedback for syntax errors in play and task cells


## [0.1] - 2018-06-27
### Added
- Basic support for ansible tasks in Jupyter notebooks
- Command completion support for modules, module args, and play args
- Support for inventory cells
- Support for task cells
- Support for play cells
- Support for group var cells
- Support for host var cells
- Support for vars file cells
- Support for template cells
- Support for ansible.cfg cell
- Support for ansible vault in vars file cells


