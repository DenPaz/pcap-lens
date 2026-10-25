# Developer tasks for PCAP Lens (Linux/macOS; GNU make). `make` lists them.
# Each target is a thin wrapper around the uv / pnpm commands in CLAUDE.md.

UV ?= uv
PNPM ?= pnpm
NCU ?= $(PNPM) dlx npm-check-updates
# VS Code needs a display: use xvfb-run on headless Linux when it's installed.
XVFB ?= $(if $(DISPLAY)$(WAYLAND_DISPLAY),,$(if $(shell command -v xvfb-run 2>/dev/null),xvfb-run -a,))
LARGE ?= test/fixtures/large-1m.pcap
PACKETS ?= 1000000
# The documented timings use --no-tcp-analysis (see "Performance" in README.md).
PERF_ARGS ?= --no-tcp-analysis

.DEFAULT_GOAL := help
.PHONY: help install update outdated compile watch lint format test test-backend realworld \
	test-acceptance test-unit test-extension coverage check fixtures large-fixture perf evals package \
	release-prepare icon screenshots clean

help: ## List the targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---------------------------------------------------------------- dependencies

install: ## Install the Python and Node dev dependencies (uv sync, pnpm install)
	$(UV) sync
	$(PNPM) install

update: ## Upgrade all dev dependencies (ncu -u within .ncurc.cjs limits, uv lock --upgrade)
	$(NCU) -u
	$(PNPM) install
	$(PNPM) run codicons
	$(PNPM) run worldmap
	$(UV) lock --upgrade
	$(UV) sync
	@echo "Dependencies updated: review the diff and run 'make check'."

outdated: ## Show available updates without changing anything
	$(NCU)
	$(UV) tree --outdated --depth 1

# ---------------------------------------------------------------- build and checks

compile: ## Build the extension (tsc -> out/)
	$(PNPM) run compile

watch: ## Rebuild the extension on changes
	$(PNPM) run watch

lint: ## ESLint, webview type check, Prettier --check, ruff, ruff format --check and mypy
	$(PNPM) run lint
	$(PNPM) run format:check
	$(UV) run ruff check
	$(UV) run ruff format --check
	$(UV) run mypy

format: ## Fix what the linters can fix (ruff format, ruff --fix, eslint --fix, Prettier)
	$(UV) run ruff check --fix
	$(UV) run ruff format
	$(PNPM) exec eslint --fix src test
	$(PNPM) run format

test: test-backend test-unit ## Backend tests plus TS unit and webview tests

test-backend: ## Python backend tests, incl. acceptance scenarios (uv run pytest)
	$(UV) run pytest

test-acceptance: ## Only the pytest-bdd acceptance scenarios
	$(UV) run pytest test/backend/acceptance

test-unit: ## TS unit tests and the Chromium webview tests (stale out/ removed first)
	rm -rf out
	$(PNPM) run test:unit

test-extension: ## VS Code smoke test (downloads VS Code; uses xvfb-run when headless)
	$(XVFB) $(PNPM) run test:extension

coverage: ## Backend and TS unit tests with coverage: summaries here, HTML in coverage/
	rm -rf out coverage
	mkdir -p coverage
	$(UV) run pytest --cov --cov-report=term --cov-report=html
	$(PNPM) run test:coverage

check: lint test ## Everything CI runs except the VS Code smoke test

# ---------------------------------------------------------------- fixtures, perf, packaging

fixtures: ## Regenerate the small test captures
	$(UV) run python test/fixtures/generate.py

large-fixture: ## Generate a large synthetic capture (PACKETS=1000000, LARGE=path)
	$(UV) run python test/fixtures/generate.py --large $(PACKETS) $(LARGE)

perf: ## Benchmark the backend on the large capture (made if missing; PERF_ARGS=...)
	@test -f $(LARGE) || $(MAKE) --no-print-directory large-fixture
	$(UV) run python -u test/perf/bench.py $(LARGE) $(PERF_ARGS)

realworld: ## Run every backend feature over Wireshark's and tcpdump's test captures (downloaded; REALWORLD_ARGS=...)
	$(UV) run python -u test/realworld/run.py --fetch wireshark $(REALWORLD_ARGS)
	$(UV) run python -u test/realworld/run.py --fetch tcpdump --quick $(REALWORLD_ARGS)

evals: compile ## Ask a model the AI cases in test/evals and grade the answers (costs API calls; EVAL_ARGS=...)
	node scripts/evals/run.mjs $(EVAL_ARGS)

package: ## Build the .vsix (vsce package)
	$(PNPM) run package

release-prepare: ## Bump the version and date the CHANGELOG (VERSION=x.y.z); then tag and push vx.y.z
	@test -n "$(VERSION)" || { echo "usage: make release-prepare VERSION=x.y.z"; exit 1; }
	node scripts/release.mjs prepare $(VERSION)

icon: ## Render media/icon.svg to media/icon.png
	node scripts/render-icon.js

screenshots: compile ## Render media/screenshots/*.png from the webviews and the sample capture
	node scripts/screenshots.js

clean: ## Remove build output, test downloads, caches and .vsix files
	rm -rf out .vscode-test .pytest_cache .ruff_cache .mypy_cache coverage *.vsix
	find backend test -name __pycache__ -type d -prune -exec rm -rf {} +
