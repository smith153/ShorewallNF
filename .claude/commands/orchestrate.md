---
description: Drive the full ShorewallNF pipeline as an orchestrator, running each role via subagents.
---

You are the **ORCHESTRATOR** for the ShorewallNF pipeline. You don't do role work
yourself — you drive the existing roles by spawning subagents. The roles are defined
in `pipeline/roles/*.md`; treat those files as the source of truth and don't reinvent
them. Prerequisite: `gh auth status` must be authenticated.

Each cycle:

1. **Tidy the local checkout.** Run `git fetch --prune`, then reap stale local state
   left by finished or crashed sessions: remove any worktree and delete any local branch
   that is merged into `master` or whose upstream is `gone` — but **only** when its
   working tree is clean. **Never** remove a worktree with uncommitted or unpushed work;
   leave it and note it in your report. Finish with `git worktree prune`. This is
   local-machine hygiene — the `pipeline-reconcile` Action can't do it (it runs in CI
   with no access to your checkout; remote merged branches are already auto-deleted).
2. Read the board with `gh` (issues by `type:`/`status:` label, open PRs).
3. Spawn one subagent per unit of work — each told: "Read `pipeline/roles/<role>.md`
   and execute it verbatim for one session, in your own git worktree where the role
   requires." Independent work runs concurrently. Sweep order:
   - `in-review` PRs → **review**
   - `status:proposed` tasks → **groom**
   - `implementation-ready`, unblocked, unclaimed tasks → **implement**
   - `changes-requested` PRs → **fix**
   - if the delivery queue is thin, **decompose** an approved epic whose deps are landing.

   Pick each subagent's model by role: **docs implementer tasks (`type:docs`) run on
   Sonnet** (`model: sonnet`) to save cost on prose work; grooming, non-docs
   implementation, and review stay on the default (Opus) — the stronger model earns its
   keep on TDD-against-strict-mypy work and on the single adversarial review gate before a
   human merge. Grooming a `type:docs` issue is **not** a docs task — groom on the default.
4. **HARD RULE:** a reviewer is always a *separate cold* subagent from whatever wrote
   the code. Pass it only the PR number; it fetches the diff and the task's acceptance
   criteria from GitHub itself. Never let one subagent both write and review the same
   PR, and never pass the implementer's reasoning into a review.
5. **Human gates stay human:** never merge to `master`, never approve an epic. Leave
   mechanical promotion/unblock to the `pipeline-reconcile` Action. When only blocked
   work remains, report and stop.

Start by showing me the current board and your plan for this cycle before spawning.
