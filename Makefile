# Development tasks. Config lives in pyproject.toml so every entry point here,
# the pre-commit hooks, and CI all read the same settings.

VENV := .venv
BIN  := $(VENV)/bin
PY   := $(BIN)/python
SRC  := tools tests
APP  := tools

.DEFAULT_GOAL := help

.PHONY: help
help:  ## show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

$(BIN)/ruff:
	python3 -m venv $(VENV)
	$(BIN)/pip install --quiet --upgrade pip
	$(BIN)/pip install --quiet ruff pyink pylint bandit debugpy pytest

.PHONY: dev
dev: $(BIN)/ruff  ## create .venv and install the dev tools

.PHONY: format
format: dev  ## rewrite code to Google style
	$(BIN)/pyink $(SRC)

.PHONY: lint
lint: dev  ## ruff + pyink --check (the gate)
	$(BIN)/ruff check $(SRC)
	$(BIN)/pyink --check $(SRC)

.PHONY: pylintrc
pylintrc:  ## fetch Google's pylintrc for the full rule set
	curl -sSfo pylintrc https://google.github.io/styleguide/pylintrc

.PHONY: pylint
pylint: dev  ## pylint using pyproject settings
	$(BIN)/pylint --rcfile=pyproject.toml $(SRC) || true

.PHONY: security
security: dev  ## bandit scan; fails on MEDIUM+ only
	# The LOW findings are all B404/B603/B607: this tool's entire job is
	# driving the AWS CLI through subprocess, so importing it and calling it
	# without shell=True is correct, not a defect. Gate on MEDIUM and above.
	$(BIN)/bandit -q -r $(APP) --severity-level medium

.PHONY: test
test: dev  ## unit tests; no AWS calls, no credentials needed
	$(BIN)/pytest -q

.PHONY: integration
integration: dev  ## read-only tests against real AWS (needs credentials)
	$(BIN)/pytest -q --integration

.PHONY: integration-destructive
integration-destructive: dev  ## also deploy and delete a one-resource stack
	$(BIN)/pytest -q --integration-destructive

.PHONY: check
check: lint security test  ## everything CI runs

.PHONY: clean
clean:  ## remove caches and the venv
	rm -rf $(VENV) .ruff_cache .mypy_cache .pytest_cache
	rm -rf $(addsuffix /__pycache__,$(SRC))
