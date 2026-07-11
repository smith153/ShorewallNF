# ADR-0065: operational-visibility output format and read-only introspection seam

- **Status:** Accepted
- **Date:** 2026-07-11

## Context

Epic #404 adds operational-visibility verbs — a `show`/`list`/`ls` group whose objects report the
**live** firewall state (`show rules`, and the siblings #411–#415: `show zones`, `show policies`,
`show connections`, `show log`, `dump`). This first task (#410) builds `show rules` end-to-end and,
because it is the first consumer, owns two conventions the whole tree inherits: **how live state is
queried** and **how it is rendered**. Deciding them once, grounded in running code, keeps five
siblings from each inventing their own.

Forces:

- **Functional core / imperative shell** ([ADR-0003](0003-design-approach.md)) — all `nft`
  invocation already lives in the applier; a renderer that is a pure function is golden-testable
  without root.
- **Safety** — an introspection command must never be able to change the firewall it is inspecting.
- **Audience** — the target users are Shorewall migrators. `nft list ruleset` output exposes nft
  mechanics (handles, raw expression syntax, `inet` family plumbing) that a Shorewall operator does
  not think in.
- **YAGNI vs. a real requirement** — a bespoke format is more code to own than mirroring nft's own
  output; the maintainer accepted that cost for a migrator-friendly view (human steer on #410).

## Decision

### 1. Read-only introspection seam: `list`-only, in the applier shell

Live state is read through **one query function in the applier** (`list_ruleset`) that shells
`nft --json list ruleset` and returns the parsed JSON. It sits beside `check_ruleset`/`apply_ruleset`
in the imperative shell. **The query path is read-only by construction:** `nft list` has no mutating
form, and the seam streams nothing on stdin, so introspection can never alter the ruleset. Every
`show` verb reads through this seam — no verb shells `nft` for itself, and no `show` path ever calls
an `add`/`delete`/`flush`/`--file`/`--check` form. The invariant is asserted structurally (argv
capture) and behaviorally (a netns test snapshots the ruleset before and after `show rules` and
requires it byte-for-byte unchanged).

### 2. Output format: **Option B — annotated, columnar, grouped** (not raw `nft list`)

`show` verbs render a **curated, columnar report** — grouped into human-labelled sections, one row
per rule, with `TARGET` verdict labels and `any` placeholders — rather than mirroring native
`nft list` output. The renderer is a **pure function** (`renderer.py`) consuming the query JSON, so
it is golden-tested against committed fixtures without root.

For `show rules`, the format is:

- A **table banner**: `Table: inet <table>`.
- One **section per chain**, headed `Chain <name> (policy <policy>)`.
- Within a non-empty chain, a **fixed-column table** with a header row and one row per rule, rules
  **numbered from 1** within the chain (the annotation a raw `nft list` lacks):

  ```
  Table: inet filter

  Chain input (policy drop)
    NUM  TARGET  PROTO  SOURCE         DESTINATION  DETAIL
      1  ACCEPT  all    any            any          ct state {established,related}
      2  ACCEPT  tcp    192.0.2.0/24   any          dport {80,443}
      3  DROP    all    2001:db8::/32  any

  Chain forward (policy drop)
    (no rules)
  ```

  Columns: **NUM** (rule index), **TARGET** (human verdict label — `ACCEPT`/`DROP`/`REJECT`/
  `RETURN`/`DNAT`/…, or the target chain for a jump/goto), **PROTO**, **SOURCE**, **DESTINATION**
  (address/prefix/set, or `any` when unconstrained), and **DETAIL** (the remaining match tokens —
  interfaces, ports, ct state, NAT target). Column widths are computed per chain so each section
  self-aligns; example rows use RFC 5737/3849 documentation ranges only.

- **Empty is valid, never a crash.** An empty chain renders `(no rules)`; a table with no chains —
  the firewall is stopped or cleared — renders the banner plus `(no chains — firewall stopped or
  cleared)`. This is the graceful-degradation contract every `show` verb follows.

### 3. Errors follow ADR-0004

A name that cannot exist against a **present** table (e.g. `show rules <typo>`) fails fast with one
`ShorewallNFError` on stderr and a non-zero exit — no stack trace. When the table is **absent**
(firewall down) there is nothing to validate a name against, so the command degrades to empty output
and exit 0 rather than erroring.

## Consequences

- **Easier:** siblings #411–#415 inherit a settled query seam, a pure renderer to extend, and a
  fixed look — a banner + per-group columnar sections with `any`/empty conventions — instead of each
  re-deciding. The read-only guarantee is structural, so no visibility verb can regress into a
  mutation.
- **Trade-off (accepted):** the annotated format is bespoke rendering the project must own and keep
  stable, and it does not surface every nft expression form verbatim — an unrecognised match lands
  in the DETAIL column rather than getting a dedicated column. Mirroring `nft list` would have been
  less code but exposes nft mechanics to Shorewall migrators. The maintainer chose the migrator view.
- **Follow-up:** #411–#415 add objects (`zones`/`policies`/`connections`/`log`) and `dump` under the
  same `show` group and the same conventions; `show connections` reads conntrack, still via a
  `list`-only seam.

## Alternatives considered

- **Option A — mirror `nft list` native output.** Lowest-cost and familiar to nft users; rejected by
  human steer because the audience is Shorewall migrators, for whom nft handles/family/expression
  syntax are noise.
- **Rendering in the shell rather than a pure module.** Would couple formatting to `nft` and forfeit
  golden testing without root. Rejected — the pure core / imperative shell split (ADR-0003) keeps the
  renderer testable.
- **A machine-readable-only `--json` passthrough as the default.** Useful later for scripting, but
  the verbs' purpose is a human-readable operational view; a JSON mode is deferred (YAGNI) and can be
  added without disturbing this convention.
