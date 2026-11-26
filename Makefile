.PHONY: install dev lint typecheck test test-cov format run dashboard init clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install package in editable mode
	pip install -e .

dev: ## Install with dev dependencies
	pip install -e ".[dev]"

lint: ## Run ruff linter
	ruff check src/ tests/

typecheck: ## Run mypy type checker
	mypy src/ --ignore-missing-imports

format: ## Auto-format with ruff
	ruff format src/ tests/
	ruff check --fix src/ tests/

test: ## Run unit tests
	pytest tests/unit/ -v --tb=short

test-cov: ## Run tests with coverage report
	pytest tests/unit/ -v --cov=deceptenv --cov-report=term-missing --cov-report=html

run: ## Start the active deception monitor
	deceptenv run

dashboard: ## Launch the web dashboard
	deceptenv dashboard

init: ## Deploy canary tripwires
	deceptenv init

clean: ## Remove deployed canary files
	deceptenv clean
