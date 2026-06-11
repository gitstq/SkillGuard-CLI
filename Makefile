.PHONY: install install-dev test lint clean build dist upload help

PYTHON := python3
PIP := pip3

help:
	@echo "SkillGuard Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  install      Install SkillGuard"
	@echo "  install-dev  Install with development dependencies"
	@echo "  test         Run unit tests"
	@echo "  lint         Run code linting (flake8/pylint if available)"
	@echo "  clean        Clean build artifacts"
	@echo "  build        Build distribution packages"
	@echo "  dist         Alias for build"

install:
	$(PIP) install -e .

install-dev:
	$(PIP) install -e ".[dev]"

test:
	$(PYTHON) -m unittest discover -v tests/

lint:
	-$(PYTHON) -m flake8 skillguard/ tests/ || true
	-$(PYTHON) -m pylint skillguard/ || true

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf __pycache__/
	rm -rf .pytest_cache/
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete

build: clean
	$(PYTHON) -m build

dist: build

run-example:
	$(PYTHON) -m skillguard scan ./tests/ --no-tui
