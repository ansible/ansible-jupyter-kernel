
# Ansible Jupyter Kernel Release Process


- Create release branch with format `release_{version}`
- Update CHANGELOG.md
- Update ROADMAP.md
- Update version in setup.py, ansible_kernel/kernel.py, Dockerfile
- Create pull request for the release
- Run `make dist sdist`
- Run `make docker-dev`
- Run `make docker-run-dev`
- Run all notebooks as tests in Jupyter notebook UI
- Run `twine upload dist/*`
- Check that the version uploaded to pypi at https://pypi.org/project/ansible-kernel/#history
- Run `make docker`
- Run `docker build -t benthomasson/ansible-jupyter-kernel:{version} .`
- Run `docker push benthomasson/ansible-jupyter-kernel:{version}`
- Merge pull request
- Run `git pull upstream master`
- Run `git tag -a {version}` with comment {version}
- Run `git push --tags upstream`
- Done

