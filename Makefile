UV ?= uv
PYTHON := .venv/bin/python
RUFF := .venv/bin/ruff

.PHONY: help install test lint check eval scan-demo api ui docker

help:
	@echo "install    Sync locked development dependencies into Python 3.12 .venv"
	@echo "test       Run local pytest suite"
	@echo "lint       Check Ruff lint, import sorting, and formatting"
	@echo "check      Run lint and tests (evaluation added in task 1.12)"
	@echo "eval       Evaluate accuracy once scripts/eval.py exists"
	@echo "scan-demo  Scan starter inputs once the CLI exists; output goes to out/"
	@echo "api        Run API at :8000 once api/main.py exists"
	@echo "ui         Run frontend dev server once frontend/package.json exists"
	@echo "docker     Build quantumtrace image once Dockerfile exists"

install:
	$(UV) sync --locked --extra dev --python 3.12

test:
	$(PYTHON) -m pytest

lint:
	$(RUFF) check .
	$(RUFF) format --check .

# Evaluation becomes part of this gate in task 1.12.
check: lint test

eval:
	@test -f scripts/eval.py || { echo "Evaluation is unavailable: scripts/eval.py is planned for task 1.12." >&2; exit 1; }
	$(PYTHON) scripts/eval.py

scan-demo:
	@test -f src/quantumtrace/cli.py || { echo "Scanning is unavailable: the CLI is planned for task 1.10." >&2; exit 1; }
	.venv/bin/qtrace scan sample-repos cloud-posture network-capture --out out/

api:
	@test -f api/main.py || { echo "API is unavailable: api/main.py belongs to M4." >&2; exit 1; }
	$(PYTHON) -m uvicorn api.main:app --reload --host 127.0.0.1 --port 8000

ui:
	@test -f frontend/package.json || { echo "UI is unavailable: frontend/package.json belongs to M4." >&2; exit 1; }
	npm --prefix frontend run dev

docker:
	@test -f Dockerfile || { echo "Container build is unavailable: Dockerfile belongs to M4." >&2; exit 1; }
	docker build -t quantumtrace .
