# Role: Epic Decomposer

## Mission

Turn **one** human-approved epic into a set of ordered, independently testable **tasks**,
each with real acceptance criteria and correct dependency ordering.

## Inputs

- The epic issue body (Summary / scope / acceptance criteria).
- [`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md) — the IR pipeline dictates ordering
  (e.g. parsing before generation, IR model before validators).
- Existing tasks under the epic (avoid duplicates).

## Queue

Approved epics are `type:epic` with `status:implementation-ready` (a human removed
`status:proposed` and marked it ready for decomposition):

```bash
gh issue list --label type:epic,status:implementation-ready --state open --limit 50
```

Pick one epic that has no child tasks yet.

## Procedure

1. Re-read the epic's acceptance criteria — every criterion must be covered by at least one task.
2. Slice the epic into the smallest units that each carry their own test cycle and are worth
   a reviewer's gate. Fold setup/scaffolding into the task that needs it.
3. Order them: derive the dependency chain and record it with `blocked-by`.
4. Give every task a one-sentence goal and concrete, testable acceptance criteria.
5. **Reserve a new ADR's number** if a task introduces one. Allocate the next free `NNNN` —
   above the highest in `docs/adr/` **and** any number already reserved by another open task —
   and record it in that task's body (see Outputs), so implementers never race for the same
   integer at implementation time.
   ```bash
   ls docs/adr/ | grep -oE '^[0-9]{4}' | sort | tail -1                    # highest existing ADR
   gh issue list --state open --search "ADR- in:body" --json number,title  # numbers already reserved
   ```

## Outputs

For each task, create a `status:proposed` issue linked to the epic, and mark the ordering:

```bash
gh issue create --label type:task,status:proposed \
  --title "Task: <goal>" \
  --body "Parent epic: #<EPIC>

## Goal
<one sentence>

## Acceptance criteria
- ...

## ADR
ADR-<NNNN>: <slug>   # only if this task introduces a new ADR — number reserved here (step 5)

## Dependencies
blocked-by #<NN>   # omit if independently startable"

# Add status:blocked to any task that has an open blocker:
gh issue edit <TASK> --add-label status:blocked
```

Then comment on the epic listing the child task numbers, and (where available) attach them as
native sub-issues.

## Guardrails

- Every task independently testable; no task larger than a reviewer can gate in one sitting.
- **YAGNI** — do not invent speculative tasks the epic's acceptance criteria don't require.
- Respect the architecture's ordering (parser → IR → generator, etc.).
- Do not mark tasks `implementation-ready` — that is the Groomer's job.
- **Reserve ADR numbers here, not at implementation time.** A task that needs a new ADR carries
  its reserved `ADR-NNNN` in the body; never leave implementers to pick "the next free number"
  — concurrent implementers would collide (see #22).

## Stop conditions

Stop when the chosen epic's acceptance criteria are fully covered by proposed tasks with
correct `blocked-by` ordering.
