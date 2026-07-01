# Pipeline workflow

ShorewallNF is built by a pipeline of AI agents coordinated through GitHub. Work flows
through two phases: an upstream **Refinement** phase that grooms ideas into well-formed,
`implementation-ready` tasks, then a standard GitHub **Delivery** phase that turns tasks
into merged code.

Labels ([`labels.md`](labels.md)) describe an item's type/status/area; native GitHub
state (issues, PRs, reviews, CI) carries the rest.

## Roles

**Refinement**
1. **Epic Author** — surveys project state and proposes epics.
2. **Epic Decomposer** — breaks an approved epic into ordered, testable tasks.
3. **Task Groomer** — validates proposed tasks and gates them to `implementation-ready`.

**Delivery**
4. **Implementer** — implements one task via TDD and opens a PR.
5. **Code Reviewer** — reviews open PRs (cannot authorize merge).
6. **Fixer** — addresses requested changes on a PR.
7. **Merge-readiness** — flags approved + green PRs for a human to merge.

## Lifecycle

```
Epic Author ─► epic:proposed ─►(human approve)─► Decomposer ─► task:proposed
     ─► Groomer ──(≤2 rounds)──► implementation-ready
     ─► Implementer (assignee + in-progress) ─► PR (Closes #N) ─► in-review
     ─► Code Reviewer ⇄ Fixer ─► approved + green CI
     ─► Merge-readiness ─► ready-to-merge ─►(human merge)─► closed
```

## Status transitions

| Status | Meaning | Applied by | Moves next when |
|--------|---------|------------|-----------------|
| `status:proposed` | Awaiting refinement/approval | Epic Author (epics), Decomposer (tasks) | Human approves epic / Groomer accepts task |
| `status:needs-refinement` | Groomer requested changes | Task Groomer | Decomposer/author revises → back to `proposed` |
| `status:implementation-ready` | Groomed & startable (epics: approved for decomposition) | Human (epics), Task Groomer (tasks) | Implementer claims it |
| `status:in-progress` | Claimed by an implementer | Implementer (with self-assign) | PR opened |
| `status:blocked` | Has unmet dependencies (`blocked-by`) | Decomposer/Groomer | Dependency closes |
| `status:in-review` | Has an open PR under review | Implementer | Review approved + CI green |
| `status:ready-to-merge` | Approved + green; awaiting human merge | Merge-readiness | Human merges |

## Collision avoidance

Volunteers run agents concurrently (often overnight), so claiming must be atomic:

- An agent **claims a task by self-assigning AND adding `status:in-progress`** in the same step.
- Agents only pick tasks that are **unassigned**, `status:implementation-ready`, and **not**
  `status:blocked`.
- One task per PR; one PR per branch. Never commit to `master`.

## Human gates

Only two human interventions are required; everything between them is autonomous.

1. **Epic approval (direction).** A human approves an epic by removing `status:proposed`
   and adding `status:implementation-ready` to the `type:epic` issue. The Decomposer only
   picks up epics in that approved state.
2. **Merge (final look).** Branch protection on `master` requires green CI **and** a human
   approving review (via [`CODEOWNERS`](../.github/CODEOWNERS)). The AI Code Reviewer's
   approval must never satisfy this gate on its own.

## Escalation

The Refinement churn is bounded. The Task Groomer allows at most **2 rounds** of
request-changes on a task; if it still isn't right, the Groomer adds `needs-human` and
stops, leaving the decision to a maintainer. Any agent that is uncertain or blocked on a
judgment call should add `needs-human` rather than guess.
