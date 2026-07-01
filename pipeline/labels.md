# Label taxonomy

> **Source of truth:** [`.github/labels.yml`](../.github/labels.yml). Apply/refresh with
> [`scripts/sync-labels`](../scripts/sync-labels). Keep this table in sync with that file.

Labels describe an item's **type**, its **status** in the pipeline, the **area** of the
codebase it touches, and a few **meta** flags. Native GitHub state (issue open/closed, PR
review, CI status) carries the rest of the workflow — see [`workflow.md`](workflow.md).

## `type:*` — kind of work item

| Label | Purpose | Applied by |
|-------|---------|------------|
| `type:epic` | High-level feature; parent of tasks | Epic Author |
| `type:task` | Implementation-ready unit of work | Epic Decomposer |
| `type:bug` | Defect in existing behavior | Anyone |
| `type:spike` | Time-boxed research/investigation | Decomposer / human |
| `type:docs` | Documentation change | Anyone |
| `type:ci` | CI/build/tooling change | Anyone |
| `type:architecture` | Architecture decision / ADR | Anyone |

## `status:*` — position in the pipeline

| Label | Meaning | Applied by |
|-------|---------|------------|
| `status:proposed` | Awaiting refinement/approval | Epic Author / Decomposer |
| `status:needs-refinement` | Groomer requested changes | Task Groomer |
| `status:implementation-ready` | Groomed; ready to implement | Task Groomer |
| `status:in-progress` | Claimed by an implementer | Implementer (with self-assign) |
| `status:blocked` | Has unmet dependencies | Decomposer / Groomer |
| `status:in-review` | Has an open PR under review | Implementer |
| `status:ready-to-merge` | Approved + green; awaiting human merge | Merge-readiness |

## `area:*` — subsystem touched

`area:parser`, `area:generator`, `area:cli`, `area:ir`, `area:zones`, `area:interfaces`,
`area:policy`, `area:rules`, `area:nat`, `area:preprocessor`, `area:testing`, `area:ci`.

## `meta`

| Label | Purpose |
|-------|---------|
| `good-first-issue` | Good entry point for new contributors |
| `needs-human` | Escalated: requires a human decision |
| `blocked-external` | Blocked on something outside the repo |
