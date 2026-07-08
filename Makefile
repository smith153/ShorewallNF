# Dev workflow for ShorewallNF. Mirrors CI: the first `make` bootstraps a
# per-worktree .venv (editable install), so later runs are instant.
#
#   make check   lint + type + test (as your user)
#   make netns   privileged behavioral tier (uses sudo)
#   make nft     privileged nft --check dry-run tier (uses sudo)
#   make clean   remove the .venv
#
# The venv is created with --system-site-packages so the system `python3-nftables`
# is importable, and the editable install means the netns child process
# (`ip netns exec ... python -c "import shorewallnf"`) resolves with no PYTHONPATH.

VENV   := .venv
PY     := $(VENV)/bin/python
ABS_PY := $(CURDIR)/$(VENV)/bin/python
# sudo's secure_path drops the venv; name PY explicitly and put nft/ip (/sbin) on PATH.
SUDO_PATH := $(CURDIR)/$(VENV)/bin:/usr/sbin:/sbin:/usr/bin:/bin

.DEFAULT_GOAL := check

$(VENV): pyproject.toml
	python3 -m venv --system-site-packages $(VENV)
	$(PY) -m pip install --upgrade --quiet pip
	$(PY) -m pip install --quiet -e ".[dev]"
	@touch $(VENV)

.PHONY: venv lint type test check netns nft all clean
venv: $(VENV)

lint: $(VENV)
	$(PY) -m ruff check .

type: $(VENV)
	$(PY) -m mypy

test: $(VENV)
	$(PY) -m pytest -m "not nft"

check: lint type test

netns: $(VENV)
	sudo env "PATH=$(SUDO_PATH)" $(ABS_PY) -m pytest -m netns -o addopts=

nft: $(VENV)
	sudo env "PATH=$(SUDO_PATH)" $(ABS_PY) -m pytest -m nft -o addopts=

all: check nft netns

clean:
	rm -rf $(VENV)
