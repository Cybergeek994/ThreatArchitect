.PHONY: format format-check lint typecheck test coverage quality

format:
	python -m ruff check . --fix
	python -m ruff format .

format-check:
	python -m ruff format --check .

lint: format-check
	python -m ruff check .

typecheck:
	python -m mypy threatmodeler tests

test:
	python -m pytest

coverage:
	python -m pytest

quality: format-check lint typecheck test
