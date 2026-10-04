.PHONY: setup lint test test-all data train serve ext clean

PYTHON ?= .venv/bin/python
UV ?= uv

ifeq ($(OS),Windows_NT)
    PYTHON = .venv/Scripts/python.exe
endif

setup:
	@echo "Setting up virtual environment and dependencies with uv..."
	uv venv .venv --python 3.11 || true
	uv pip install -e ".[dev]"

lint:
	$(PYTHON) -m ruff check core ml backend
	$(PYTHON) -m mypy core ml backend

test:
	$(PYTHON) -m pytest core/tests ml/tests backend/tests

test-all:
	$(PYTHON) -m pytest

data:
	$(PYTHON) -m phishguard_ml.data.fetch

train:
	$(PYTHON) -m phishguard_ml.training.train_lgbm

serve:
	$(PYTHON) -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

ext:
	@echo "Building Chrome extension..."
	cd extension && npm run build

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache dist build *.egg-info
