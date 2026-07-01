# Claude Code adapter

The **canonical** ShorewallNF pipeline roles live in [`../../pipeline/roles/`](../../pipeline/roles/)
as provider-agnostic Markdown. They are the source of truth and work with any AI agent runtime.

This `.claude/` directory is a thin convenience layer for **Claude Code** users:

- [`../commands/`](../commands/) — one slash command per role. Each command just loads and
  follows the matching `pipeline/roles/<role>.md` verbatim. Run a role for a session with,
  e.g., `/implementer` or `/code-reviewer`.

There are intentionally no bespoke subagent definitions here — the role prompts *are* the
definitions, and keeping a single source avoids drift.

**Using a different runtime?** Ignore this directory entirely and read
`pipeline/roles/<role>.md` directly. See [`../../pipeline/README.md`](../../pipeline/README.md)
for the volunteer quickstart.
