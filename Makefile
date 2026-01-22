.PHONY: help install dev clean test lint format ruff type-check build publish publish-test version sync-defaults docs docs-serve mcp-inspector

# Default target
help:
	@echo "IAM Policy Auditor - Makefile Commands"
	@echo ""
	@echo "Development:"
	@echo "  make install          Install production dependencies"
	@echo "  make dev              Install development dependencies"
	@echo "  make clean            Clean build artifacts and cache"
	@echo "  make sync-defaults    [DEPRECATED] Defaults are now in Python modules"
	@echo ""
	@echo "Quality:"
	@echo "  make test             Run tests"
	@echo "  make lint             Run linting checks"
	@echo "  make format           Format code with ruff"
	@echo "  make ruff             Format code with ruff (alias for format)"
	@echo "  make type-check       Run mypy type checking"
	@echo "  make check            Run all checks (lint + type + test)"
	@echo ""
	@echo "Build & Publish:"
	@echo "  make build            Build distribution packages"
	@echo "  make publish-test     Publish to TestPyPI"
	@echo "  make publish          Publish to PyPI"
	@echo "  make version          Show current version"
	@echo ""
	@echo "Examples:"
	@echo "  make validate-example Run validator on example policies"
	@echo ""
	@echo "Documentation:"
	@echo "  make docs             Build documentation"
	@echo "  make docs-serve       Serve documentation locally (http://localhost:8000)"
	@echo ""
	@echo "MCP Server:"
	@echo "  make mcp-inspector    Start MCP Inspector for debugging"
	@echo ""
	@echo "AWS Services Backup:"
	@echo "  make download-aws-services Download all AWS service definitions"

# Installation
install:
	uv sync --no-dev

dev:
	uv sync

# Sync defaults.py from YAML config [DEPRECATED]
# Defaults are now defined in Python modules at iam_validator/core/data/
# This target is kept for backward compatibility but is no longer needed
sync-defaults:
	@echo "⚠️  DEPRECATED: Defaults are now defined in Python modules"
	@echo "   Location: iam_validator/core/data/"
	@echo "   See: docs/modular-configuration.md"
	@echo ""
	@echo "   Running legacy sync script for reference..."
	@uv run python scripts/sync_defaults_from_yaml.py || echo "   (Script may fail - this is expected)"

# Clean
clean:
	@rm -rf build/
	@rm -rf dist/
	@rm -rf *.egg-info
	@rm -rf .pytest_cache/
	@rm -rf .mypy_cache/
	@rm -rf .ruff_cache/
	@rm -rf .benchmarks
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete
	@find . -type f -name "*.pyo" -delete
	@find . -type f -name "*.orig" -delete

# Testing
test:
	@uv run pytest tests/ -v

# Linting and formatting
lint:
	@uv run ruff check iam_validator/

format:
	@uv run ruff format iam_validator/
	@uv run ruff check --fix iam_validator/

ruff: format

type-check:
	uv run mypy iam_validator/

# Run all checks
check: lint type-check test
	echo "✓ All checks passed!"

# Building
build: clean
	uv build

# Version management
version:
	@grep '^version = ' pyproject.toml | cut -d'"' -f2

# Publishing to TestPyPI (for testing)
publish-test: build
	@echo "Publishing to TestPyPI..."
	uv publish --publish-url https://test.pypi.org/legacy/

# Publishing to PyPI (production)
publish: build
	@echo "Publishing to PyPI..."
	@read -p "Are you sure you want to publish to PyPI? (yes/no): " confirm && \
	if [ "$$confirm" = "yes" ]; then \
		uv publish; \
	else \
		echo "Publish cancelled."; \
	fi

# Example validation
validate-example:
	uv run iam-validator validate --path examples/iam-test-policies/sample_policy.json --config examples/configs/basic-config.yaml

validate-invalid:
	uv run iam-validator validate --path examples/iam-test-policies/insecure_policy.json --config examples/configs/basic-config.yaml || true

# Download AWS service definitions for backup
download-aws-services:
	@echo "Downloading AWS service definitions..."
	@uv run python scripts/download_aws_services.py

# CI/CD simulation
ci: check build
	@echo "✓ CI checks complete!"

# Documentation
docs:
	@uv run --extra docs mkdocs build

docs-serve:
	@uv run --extra docs mkdocs serve -w docs/

# MCP Server debugging
mcp-inspector:
	@npx @modelcontextprotocol/inspector uv run --directory $(CURDIR) --extra mcp iam-validator-mcp
