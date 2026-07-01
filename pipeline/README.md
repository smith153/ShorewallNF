# The ShorewallNF pipeline ("the factory")

ShorewallNF is built almost entirely by AI agents, coordinated through GitHub issues and
pull requests. This directory defines that pipeline: a set of **provider-agnostic role
prompts** that any AI agent (Claude Code, Codex, Aider, a plain API script, …) can execute.

Volunteers contribute by pointing their *own* agent at the repo and having it play one
**role** for a session — for example, "tonight my agent is the code reviewer." The pipeline
is designed so many people's agents can work concurrently without colliding.

- **Canonical roles:** [`roles/`](roles/) — these files are the source of truth.
- **Lifecycle & rules:** [`workflow.md`](workflow.md).
- **Labels:** [`labels.md`](labels.md).
- **Claude Code users** also get thin slash-command wrappers in [`../.claude/commands/`](../.claude/commands/) — they just load the matching role file.

## Volunteer a session

1. **Authenticate the GitHub CLI:** `gh auth status` (run `gh auth login` if needed).
2. **Pick a role** for the session from the table below.
3. **Run it.** In Claude Code: `/‹role›` (e.g. `/implementer`). In any other runtime: open
   `roles/‹role›.md` and follow it verbatim.
4. The role reads its own queue, does its bounded job, and stops at its stop conditions.
   Respect the guardrails — especially: only humans approve epics and merge to `master`.

## Roles at a glance

| Role | Prompt | Reads (queue) |
|------|--------|---------------|
| Epic Author | [`roles/epic-author.md`](roles/epic-author.md) | `gh issue list --label type:epic --state open` |
| Epic Decomposer | [`roles/epic-decomposer.md`](roles/epic-decomposer.md) | approved epics (`type:epic` + `status:implementation-ready`) |
| Task Groomer | [`roles/task-groomer.md`](roles/task-groomer.md) | `gh issue list --label type:task,status:proposed` |
| Implementer | [`roles/implementer.md`](roles/implementer.md) | `type:task,status:implementation-ready`, unassigned, unblocked |
| Code Reviewer | [`roles/code-reviewer.md`](roles/code-reviewer.md) | `gh pr list --state open --search "-review:approved -review:changes_requested"` |
| Fixer | [`roles/fixer.md`](roles/fixer.md) | `gh pr list --search "review:changes_requested"` |
| Merge-readiness | [`roles/merge-readiness.md`](roles/merge-readiness.md) | `gh pr list --state open` |

## Why provider-agnostic?

This is a public project and volunteers use different tools. Keeping the role definitions as
plain Markdown means no one is locked into a single agent runtime; the `.claude/` wrappers
are a convenience, not a requirement.
