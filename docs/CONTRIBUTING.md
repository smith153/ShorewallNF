# Contributing to ShorewallNF

Both humans and AI agents are welcome. ShorewallNF is built by a pipeline of AI agents
coordinated through GitHub, but ordinary human contributions (issues, PRs, reviews) work
exactly as you'd expect.

## How the work is organized

Work flows through two phases (full detail in [`../pipeline/workflow.md`](../pipeline/workflow.md)):

1. **Refinement** — an **Epic Author** proposes epics; a human approves them; an **Epic
   Decomposer** breaks each into tasks; a **Task Groomer** validates tasks to
   `implementation-ready`.
2. **Delivery** — an **Implementer** picks up a ready task, an open PR gets a **Code Review**,
   a **Fixer** addresses feedback, and the **reconcile Action** flags green + approved PRs for a
   human to merge.

Labels track type and status — see [`../pipeline/labels.md`](../pipeline/labels.md).

## Volunteer an AI agent for a session

This is the primary contribution model. Point your own AI agent at the repo and have it play
one role for a session:

1. `gh auth login` (the roles drive GitHub through the `gh` CLI).
2. Pick a role from [`../pipeline/README.md`](../pipeline/README.md).
3. Run it: in Claude Code, `/‹role›` (e.g. `/implementer`); in any other runtime, follow
   `pipeline/roles/‹role›.md` directly.

## Contributing by hand

- **Dev setup:**
  ```bash
  python -m pip install -e ".[dev]"
  python -m ruff check . && python -m mypy && python -m pytest -v
  ```
  That is the fast, hermetic tier (golden-file snapshots + `nft -c`, no root); it runs on every
  PR as the `lint-type-test` CI job. A second, privileged **netns** tier also runs in CI — see
  [Running the behavioral netns tier](#running-the-behavioral-netns-tier).
- **Standards:** Python ≥ 3.11, full type hints, `mypy --strict`, `ruff`, TDD. Minimal runtime
  deps (an ADR is required to add one). See [`../CLAUDE.md`](../CLAUDE.md).
- **Workflow:** **all code work happens in its own git worktree — never on the local `master`
  checkout** (many agents share the repo, so each task is isolated). Branch → PR, one task per
  PR, referenced with `Closes #NN`. Conventional Commit messages.

### Running the behavioral netns tier

CI runs a second, privileged tier alongside the hermetic run above — the `netns-integration`
job in [`../.github/workflows/ci.yml`](../.github/workflows/ci.yml) — which loads a generated
ruleset into a throwaway Linux network namespace and drives real packets to prove packet-path
behavior (policy DROP, DNAT/SNAT, dual-stack ICMP). These tests carry the `netns` marker and
skip cleanly when their requirements are absent, so the hermetic run stays green without
privileges.

To reproduce it locally you need:

- **root / `CAP_NET_ADMIN`** — to create network namespaces and load nftables rules;
- the **`nft`** binary (nftables) and the **`ip`** binary (iproute2); and
- a **Linux** host (network namespaces are Linux-only).

Then run just the behavioral tier:

```bash
sudo -E python -m pytest -m netns
```

`-E` preserves your environment so the editable install and the `nft`/`ip` binaries stay on
`PATH`; if `sudo`'s `secure_path` strips them, prefix the command with `env "PATH=$PATH"` (as
the CI job does).

## Human gates

Two steps always require a human, by design:

1. **Approving epics** — a maintainer moves an epic to `status:implementation-ready` before it
   is decomposed.
2. **Merging to `master`** — branch protection requires green CI **and** a human approving
   review (via [`../.github/CODEOWNERS`](../.github/CODEOWNERS)). An AI review never satisfies
   this on its own.
