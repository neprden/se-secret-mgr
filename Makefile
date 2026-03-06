.PHONY: install install-dev test coverage

VENV_PY := .venv/bin/python

install:
	python3 -m venv --system-site-packages .venv
	$(VENV_PY) -m pip install -e . --no-deps

install-dev: install
	$(VENV_PY) -m pip install -e .[test]

test:
	$(VENV_PY) -m pytest

coverage: install-dev
	$(VENV_PY) -m pytest --cov --cov-config=.coveragerc --cov-report=term-missing --cov-fail-under=35
