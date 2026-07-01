# CLAUDE.md — guidance for AI agents working in this repo

This file orients any AI agent (and human) doing work *inside* ShorewallNF. If you are here
to run a **pipeline role** (Epic Author, Implementer, Code Reviewer, …), start at
[`pipeline/README.md`](pipeline/README.md) and your role file in `pipeline/roles/`.

## What this project is

An nftables-native reimplementation of Shorewall, in Python. See [`README.md`](README.md) and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Architecture (the north star)

A compiler pipeline with an explicit, nftables-agnostic **intermediate representation (IR)**:

```
config dir → Reader → Parser → IR/model → Validator → nft Generator → Applier
```

Keep changes in the correct stage: parsing never knows about nftables; the generator consumes
the IR and emits nftables **JSON** (via `python3-nftables`). The IR is **family-aware**
(IPv4/IPv6) so one config produces family-correct `inet` output. Full detail:
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Standards

- **Python ≥ 3.11**, full type hints. `mypy` runs in **strict** mode.
- Lint/format with **`ruff`**; test with **`pytest`**.
- **Minimal runtime dependencies** — stdlib plus the system `python3-nftables`. Do not add
  PyPI runtime deps without an ADR.
- **TDD**: write a failing test, watch it fail, write the minimal code, watch it pass. No
  implementation without a test first.

## Working agreement

- **All work happens on a branch → pull request. Never commit to `master`.** Use a worktree
  for isolation.
- One task per PR; reference the issue with `Closes #NN`.
- **Conventional Commits** (`feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `test:`). End each
  commit message with the repo's `Co-Authored-By:` trailer.
- Humans approve epics and merges; agents do everything in between. Never self-approve a PR
  to satisfy branch protection.

## Where project state lives

- [`STATUS.md`](STATUS.md) — current snapshot + the seed backlog (read this first).
- The GitHub issue tracker — the living backlog (epics/tasks).
- [`docs/`](docs/) and [`docs/adr/`](docs/adr/) — durable design decisions.

There is no separate "AI memory" — the tracker and these docs are the shared state.

## Dev setup

```bash
python -m pip install -e ".[dev]"
python -m ruff check . && python -m mypy && python -m pytest -v
```
