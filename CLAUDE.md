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

The foundational decisions are recorded as ADRs in [`docs/adr/`](docs/adr/): IR modeling
([ADR-0001](docs/adr/0001-ir-modeling.md)), unified `inet` dual-stack
([ADR-0002](docs/adr/0002-unified-inet-dual-stack.md)), overall design approach — functional
core ([ADR-0003](docs/adr/0003-design-approach.md)), and error handling
([ADR-0004](docs/adr/0004-error-handling.md)). The concrete stage→module map is
[`docs/module-layout.md`](docs/module-layout.md).

## Standards

- **Python ≥ 3.11**, full type hints. `mypy` runs in **strict** mode.
- Lint/format with **`ruff`**; test with **`pytest`**.
- **Minimal runtime dependencies** — stdlib plus the system `python3-nftables`. Do not add
  PyPI runtime deps without an ADR.
- **TDD**: write a failing test, watch it fail, write the minimal code, watch it pass. No
  implementation without a test first.

## Code philosophy

- **YAGNI.** Build only what a current task needs. No speculative abstractions, config knobs,
  or "might need it later" code paths — add them when a real requirement arrives.
- **Fail fast, exit gracefully.** Validate up front and stop with one clear, actionable error;
  don't scatter defensive `if`s trying to survive every conceivable state. A compiler that
  emits wrong firewall rules is worse than one that refuses to run.
- **Be brief.** Comment only what the code can't say itself. Keep commit messages, PR
  summaries, and issue comments short and to the point.

## Working agreement

- **All code work happens in its own git worktree — never in the primary checkout, and never
  on `master`.** Multiple agents share this repo concurrently, so each task is isolated in a
  worktree (branch → PR). The primary checkout stays on `master` and is only ever pulled, never
  committed to.
- One task per PR; reference the issue with `Closes #NN`.
- **Conventional Commits** (`feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `test:`), kept brief. Do
  **not** add AI or `Co-Authored-By:` trailers — the human running the session is the sole author.
- Humans approve epics and merges; agents do everything in between. Never self-approve a PR
  to satisfy branch protection.
- **Raise issues freely.** If you notice something off — a bug, shortcoming, tech debt, risky
  pattern — file a brief GitHub issue for it (`type:bug`/`type:*` + `status:proposed`), even if
  it's unrelated to what you're working on. File it and move on; don't fix out-of-scope things
  inline.

## Handling `my_shorewall/` (private reference config)

`my_shorewall/` is a gitignored, private reference — used **only** to decide *which* features
to build. It is never part of the public record:

- **Never** reproduce its addresses, hostnames, interface names, or config lines verbatim in
  any public artifact — issues, PR/commit text, comments, code, docs, or test fixtures.
- **Never** describe it as anyone's personal or production firewall. Refer to it neutrally as
  "the reference config."
- Describe capabilities abstractly ("port-forward a TCP service to an internal host"), and use
  RFC 5737 / RFC 3849 documentation ranges in tests and examples: `192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`.

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
