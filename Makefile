# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Development commands

PYTHON ?= .venv/bin/python
TYPOS ?= typos

.PHONY: install lock lint fmt typecheck bandit typos audit audit-authoring test test-file preflight preflight-fast build docs docs-build docker-build docker-smoke install-hooks clean

install:
	$(PYTHON) -m pip install --require-hashes -r requirements/ci.txt
	$(PYTHON) -m pip install --no-build-isolation --no-deps -e .

lock:
	$(PYTHON) -m piptools compile --allow-unsafe --generate-hashes --strip-extras --output-file requirements/build.txt requirements/build.in
	$(PYTHON) -m piptools compile --allow-unsafe --generate-hashes --strip-extras --output-file requirements/ci.txt requirements/ci.in
	$(PYTHON) -m piptools compile --allow-unsafe --generate-hashes --strip-extras --output-file requirements/runtime.txt requirements/runtime.in
	$(PYTHON) -m piptools compile --allow-unsafe --generate-hashes --strip-extras --output-file requirements/security.txt requirements/security.in
	$(PYTHON) -m piptools compile --allow-unsafe --generate-hashes --strip-extras --output-file requirements/test.txt requirements/test.in

lint:
	$(PYTHON) -m ruff check src tests tools
	$(PYTHON) -m ruff format --check src tests tools

fmt:
	$(PYTHON) -m ruff check --fix src tests tools
	$(PYTHON) -m ruff format src tests tools

typecheck:
	$(PYTHON) -m mypy --strict src/rigor_foundry tools

bandit:
	$(PYTHON) -m bandit -q -c pyproject.toml -r src/rigor_foundry tools

typos:
	$(TYPOS) --config _typos.toml

audit:
	$(PYTHON) -m tools.audit

audit-authoring:
	$(PYTHON) -m tools.audit --strict-authoring

test:
	@test "$(ALLOW_LOCAL_FULL_TESTS)" = "1" || { echo "Local full suite blocked; run a focused test-file or use CI."; exit 2; }
	$(PYTHON) -m pytest tests -q --cov=rigor_foundry --cov-branch --cov-report=term-missing --cov-fail-under=95

test-file:
	@test -n "$(TEST)" || { echo "Usage: make test-file TEST=tests/test_name.py"; exit 2; }
	$(PYTHON) -m pytest -q "$(TEST)"

preflight:
	$(PYTHON) -m tools.preflight

preflight-fast:
	$(PYTHON) -m tools.preflight --fast

build:
	$(PYTHON) -m build --no-isolation
	$(PYTHON) -m twine check dist/*

docs:
	$(PYTHON) -m mkdocs serve

docs-build:
	$(PYTHON) -m mkdocs build --strict

docker-build:
	docker build --tag rigor-foundry:local .

docker-smoke:
	rm -rf /tmp/rigor-foundry-container-smoke
	git init --initial-branch=main /tmp/rigor-foundry-container-smoke
	git -C /tmp/rigor-foundry-container-smoke config user.name 'RigorFoundry Smoke'
	git -C /tmp/rigor-foundry-container-smoke config user.email audit-tests@example.invalid
	cp README.md /tmp/rigor-foundry-container-smoke/README.md
	git -C /tmp/rigor-foundry-container-smoke add README.md
	git -C /tmp/rigor-foundry-container-smoke commit -m 'test: container fixture'
	docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges --mount type=bind,src=/tmp/rigor-foundry-container-smoke,dst=/workspace,readonly rigor-foundry:local scan --root /workspace

install-hooks:
	$(PYTHON) -m pre_commit install --hook-type pre-commit --hook-type pre-push --hook-type commit-msg

clean:
	rm -rf build dist site htmlcov .coverage .pytest_cache .mypy_cache .ruff_cache
	find src tests tools -type d -name __pycache__ -prune -exec rm -rf {} +
	find src tests tools -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
