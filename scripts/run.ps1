param (
    [Parameter(Position=0)]
    [string]$Target = "test"
)

$PythonExe = ".venv\Scripts\python.exe"

switch ($Target) {
    "setup" {
        Write-Host "Setting up virtual environment and installing dependencies via uv..."
        python -m uv venv .venv --python 3.11
        python -m uv pip install -e ".[dev]"
    }
    "lint" {
        Write-Host "Running Ruff linter..."
        & $PythonExe -m ruff check core ml backend
        Write-Host "Running Mypy type checker..."
        & $PythonExe -m mypy core ml backend
    }
    "test" {
        Write-Host "Running Pytest..."
        & $PythonExe -m pytest core/tests ml/tests backend/tests
    }
    "serve" {
        Write-Host "Starting FastAPI server..."
        & $PythonExe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
    }
    default {
        Write-Host "Unknown target: $Target. Supported: setup, lint, test, serve"
        exit 1
    }
}
