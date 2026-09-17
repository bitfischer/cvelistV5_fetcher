VENV := .venv
PYTHON := $(VENV)/bin/python3
HOST ?= 0.0.0.0
PORT ?= 8420

.PHONY: install fetch run dev test clean

install: $(PYTHON)

$(PYTHON):
	python3 -m venv $(VENV) --without-pip
	python3 -m pip --python $(PYTHON) install -e ".[dev]"

fetch: install
	$(VENV)/bin/cvelistv5-fetch

run: install
	$(VENV)/bin/uvicorn app.main:app --host $(HOST) --port $(PORT)

dev: install
	$(VENV)/bin/uvicorn app.main:app --reload --port $(PORT)

test: install
	$(VENV)/bin/pytest -q

clean:
	rm -rf $(VENV) .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
