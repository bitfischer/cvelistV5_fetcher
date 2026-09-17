VENV := .venv
PYTHON := $(VENV)/bin/python3
SBOM_VENV := .sbom-venv
HOST ?= 0.0.0.0
PORT ?= 8420

.PHONY: install fetch run dev test sbom clean

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

# Regenerates web/sbom.json from a clean, runtime-only install of the project
# (not the dev venv, which also has pytest/cyclonedx-bom/etc. in it) so the
# SBOM reflects exactly what ships, nothing more.
sbom: install
	rm -rf $(SBOM_VENV)
	python3 -m venv $(SBOM_VENV) --without-pip
	python3 -m pip --python $(SBOM_VENV)/bin/python3 install .
	$(VENV)/bin/cyclonedx-py environment \
		--pyproject pyproject.toml \
		--mc-type application \
		--output-format JSON \
		--output-reproducible \
		--gather-license-texts \
		--validate \
		-o web/sbom.json \
		$(SBOM_VENV)/bin/python3
	rm -rf $(SBOM_VENV) build

clean:
	rm -rf $(VENV) $(SBOM_VENV) build .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
