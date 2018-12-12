PYTHON ?= python
ifeq ($(origin VIRTUAL_ENV),undefined)
	DIST_PYTHON ?= pipenv run $(PYTHON)
else
	DIST_PYTHON ?= $(PYTHON)
endif

NAME = ansible-runner
IMAGE_NAME ?= $(NAME)
PIP_NAME = ansible_runner
VERSION = $(shell $(DIST_PYTHON) setup.py --version)

.PHONY: clean dist sdist dev shell

clean:
	rm -rf dist

dist:
	$(DIST_PYTHON) setup.py bdist_wheel --universal

sdist: dist/$(PIP_NAME)-$(VERSION).tar.gz

dist/$(PIP_NAME)-$(VERSION).tar.gz:
	$(DIST_PYTHON) setup.py sdist

dev:
	pipenv install

shell:
	pipenv shell

docker:
	docker build -t benthomasson/ansible-jupyter-kernel:latest .

docker-dev: dist
	docker build  -t benthomasson/ansible-jupyter-kernel:dev -f Dockerfile.dev .

docker-run:
	docker run -it -p 8888:8888 benthomasson/ansible-jupyter-kernel:latest

docker-run-dev:
	docker run -it -p 8888:8888 benthomasson/ansible-jupyter-kernel:dev
