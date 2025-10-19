# Simple Makefile for development tasks

VENV=.venv
PYTHON=$(VENV)/bin/python
PIP=$(VENV)/bin/pip

.PHONY: help venv install test clean

help:
	@echo "Available targets:"
	@echo "  venv    - create a virtualenv in $(VENV)"
	@echo "  install - install dependencies from requirements.txt into $(VENV)"
	@echo "  test    - run pytest using $(PYTHON)"
	@echo "  clean   - remove $(VENV)"

venv:
	@test -d $(VENV) || python -m venv $(VENV)
	@$(PYTHON) -m pip install --upgrade pip

install: venv
	@$(PIP) install -r requirements.txt

test: install
	@$(PYTHON) -m pytest -q

run: install
	@echo "Running keystore CLI..."
	@$(PYTHON) keystore.py $(ARGS)

serve: install
	@echo "Serving GUI at http://127.0.0.1:5000"
	@$(PYTHON) gui.py

clean:
	@rm -rf $(VENV)
	@echo "Removed $(VENV)"
