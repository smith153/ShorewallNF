# ADR-0067: Safe-apply auto-revert model

- **Status:** Accepted
- **Date:** 2026-07-12

## Context

Applying a firewall config to a *remote* host is a lockout risk: a rule that drops the operator's
own management traffic takes effect atomically (ADR-0010) and, once loaded, there is no way back
in to undo it. Shorewall solves this with `safe-*` verbs that load a candidate ruleset, then
**auto-revert** to the previous state unless the operator confirms from the still-connected
session — so a change that severs access reverts itself and the operator reconnects.

ShorewallNF already ships every primitive this needs (epics #202/#400):
`list_ruleset`/`firewall_loaded` read the running state; `save_ruleset(ruleset, path)` /
`restore_ruleset(path)` / `clear_ruleset` are the fail-closed snapshot/revert operations;
`compile_config` → `check_ruleset` → `apply_ruleset` is the compile → dry-run → atomic-load path
the lifecycle verbs already use; and `parse_timeout` (#436) is the sole timeout-duration parser.
What is missing is the **policy** that wires them into a snapshot → apply → revert flow.

Task #437 builds that as one reusable primitive and exposes the first verb on it, `try DIR
[timeout]` (apply, and auto-revert on error or after a timeout). The interactive-confirmation
siblings (`safe-reload`/`safe-start`) and the netns lockout-recovery behavioural proof are separate
tasks (#440). This ADR fixes the auto-revert model those siblings also build on.

Forces:

- A compiler that emits a wrong firewall is worse than one that refuses to run
  ([ADR-0004](0004-error-handling.md)): every failure path here must fail closed, never wide open.
- Reboot persistence ([ADR-0030](0030-reboot-persistence-model.md)) owns `DEFAULT_RULESET_PATH` as
  the save-on-`apply` state; a transient `try` must not disturb it.
- The stopped safe state ([ADR-0021](0021-stopped-safe-state.md)) is the project's canonical
  "firewall down but not open" fallback — the natural landing spot when a revert cannot complete.
- Reuse, not reinvention: no second snapshot/restore implementation
  ([ADR-0003](0003-design-approach.md) functional-core / imperative-shell).

## Decision

1. **One reusable primitive, `applier.safe_apply(candidate, stopped, *, timeout, snapshot_path,
   wait)`**, wraps the existing building blocks — it introduces **no** new snapshot or restore
   logic. It captures the running ruleset, checks and atomically loads `candidate`, and, when a
   `timeout` is given, reverts after the window. The `try` verb is a thin CLI shell over it
   (compile `candidate` and the `stopped` fallback, parse the timeout, dispatch); the
   confirmation-based siblings will reuse the same primitive.

2. **Snapshot source & revert target: the *running* ruleset, never a stale file.** The snapshot is
   `list_ruleset()` captured *before* the candidate loads. If a firewall was running
   (`firewall_loaded` true) the revert restores that snapshot; if nothing was running the revert
   target is `clear` (the empty state it started from) — never the last-saved on-disk ruleset,
   which may be arbitrarily old and is not the state the operator is protecting.

3. **Snapshot storage is off `DEFAULT_RULESET_PATH`.** The pre-`try` snapshot is written to its own
   path (`SAFE_APPLY_SNAPSHOT_PATH`), never the persisted ruleset. A `try` is **non-persisting**
   (like `start`/`reload`): neither the candidate nor the snapshot becomes the saved ruleset, so
   the ADR-0030 save-on-`apply` state is untouched and a reboot after a `try` still restores the
   last *applied* ruleset.

4. **Timeout / confirm policy.** `try DIR timeout` reverts **unconditionally** once the window
   elapses — there is no interactive confirmation in this verb. The timeout is parsed only by
   `parse_timeout` (#436): a bare number of seconds or an `s`/`m`/`h` suffix. `try DIR` with no
   timeout simply applies the candidate (a compile/check/apply failure fails fast, leaving running
   and saved state unchanged because the load is atomic). The wait is an **injectable seam** so the
   revert is unit-testable without sleeping — and that same seam is where the `safe-reload`/
   `safe-start` siblings plug a "wait for confirmation, else revert" hook, so the shared primitive
   anticipates confirmation without building it here (YAGNI).

5. **Fail-closed revert target: the stopped safe state.** If the snapshot restore itself fails, the
   primitive loads the `stopped` ruleset ([ADR-0021](0021-stopped-safe-state.md)) rather than
   leaving the host wide open — the same never-flush-to-empty guarantee `restore` makes, tied to
   ADR-0004 fail-fast error handling. The stopped ruleset is compiled up front and passed in, so a
   config that cannot even produce a safe state fails before the firewall is touched.

## Consequences

- The applier gains one function (`safe_apply`) and one constant (`SAFE_APPLY_SNAPSHOT_PATH`); the
  CLI gains the `try` verb (a required `config_dir` plus an optional `timeout` positional). No
  existing primitive changes, so the save/restore and stopped-state suites stay green.
- `try` protects a remote apply immediately; the confirmation siblings (#440) and the netns
  lockout-recovery proof build on this primitive without revisiting the model.
- Trade-off accepted: `safe_apply` compiles the `stopped` fallback even for a no-timeout `try` that
  will never revert. This keeps the primitive's contract uniform and fails a broken safe-state
  config fast; the extra compile is cheap on an interactive verb.

## Alternatives considered

- **Snapshot the last-*saved* ruleset (`DEFAULT_RULESET_PATH`) instead of the running one.**
  Rejected: the saved ruleset can be arbitrarily stale (or absent), so reverting to it would not
  restore the state the operator is actually protecting, and reading/writing that path would
  entangle a transient `try` with the ADR-0030 persistence contract.
- **Revert to `clear` on any restore failure.** Rejected: `clear` leaves traffic unfiltered (wide
  open) — the exact outcome ADR-0021 exists to avoid. The stopped safe state is the correct
  fail-closed landing spot when a running firewall's snapshot cannot be restored. (`clear` remains
  correct only for the *nothing-was-running* revert target, which is the state that already
  existed.)
- **A second, purpose-built snapshot/restore path for safe-apply.** Rejected: `save_ruleset` takes
  an explicit `path` precisely so a caller can snapshot elsewhere, and `restore_ruleset` already
  re-applies through the atomic applier fail-closed. Reusing them keeps one round-trip contract
  (ADR-0003), not two that can drift.
- **Build the interactive confirmation now.** Rejected (YAGNI): `try`'s unconditional
  timeout-revert is the smaller, independently useful primitive; the injectable wait seam leaves
  the confirmation variants (#440) a clean insertion point without speculative code today.
