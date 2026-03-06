.PHONY: install test coverage

install:
	python3 -m venv --system-site-packages .venv
	.venv/bin/python -m pip install -e . --no-deps

test:
	python3 -m pytest

coverage:
	python3 -m pytest --cov --cov-config=.coveragerc --cov-report=term-missing --cov-fail-under=35
