# ADR-0061: `shorewallnf.conf` global-settings file, frozen `Settings` model, and option scope

- **Status:** Accepted
- **Date:** 2026-07-08

> **Numbering:** `0061` is reserved by task #314 (this ADR). The parent epic is #309; the
> feature-gated option groups land in #310 (interface protective checks) and #311 (generator
> global modes), and settings-value validation is shared with #312 (validator hardening).

## Context

ShorewallNF today has no home for **whole-ruleset behaviour** — logging level/prefix, sysctl-adjacent
toggles (IP forwarding, martian logging, reverse-path filtering), generator-wide modes. Every existing
config file is **tabular**: `zones`, `interfaces`, `policy`, `rules`, … are rows of columns, one record
per line, parsed by the shared `parse()` tokenizer into `Record`s. Global knobs are not rows of a
table; upstream Shorewall keeps them in a separate `shorewall.conf` of `KEY=value` assignments. The
reader deliberately ignores any such file today — `KNOWN_CONFIG_FILES` (`reader.py`) lists only the
tabular files, and its own comment cites `shorewall.conf` as an example of a file that is *not* read.

We need to decide the shape of ShorewallNF's global-settings file **before** several epics start
consuming it, because they disagree only on *which keys* exist, not on *how the file works*:

- #309 (this epic's parent) wires the options that have a real target **today** — `LOG_LEVEL`,
  `LOGFORMAT` into the generator's existing `log` emission (`generator.py:_log`, currently a
  hard-coded level), and `IP_FORWARDING`/`LOG_MARTIANS`/`ROUTE_FILTER` into a new applier sysctl step.
- #310 adds the disposition + log-level keys for interface protective checks (`RPFILTER_*`,
  `TCP_FLAGS_*`, `SFILTER_*`, `BLACKLIST_*`) — but *only once the checks they configure exist in the
  generator*.
- #311 adds `CLAMPMSS` and `DISABLE_IPV6` — generator global modes.
- #312 (validator hardening) owns the shared enum/range/format checking of settings values.

Forces:

- **Not tabular, and never a shell script.** Upstream `shorewall.conf` is *sourced by the shell*, so its
  values undergo variable expansion, command substitution, and word-splitting. ShorewallNF is a pure
  Python compiler ([ADR-0003](0003-design-approach.md)) over untrusted, multi-file user input
  ([ADR-0004](0004-error-handling.md)); sourcing config as shell is both an injection surface and a
  parsing model we don't want. The format must be a *data* format, parsed by us.
- **Absent file must reproduce today's output byte-for-byte.** Adding a settings concept must not change
  any existing golden output; an absent file, or an absent key, must resolve to a default that *is*
  today's hard-coded behaviour. This is the compatibility contract the epic's acceptance criteria pin.
- **Fail fast on the unknown ([ADR-0004](0004-error-handling.md)).** A firewall compiler that emits a
  wrong ruleset is worse than one that refuses to run. A typo'd key, a legacy `shorewall.conf` knob we
  don't implement, or a malformed value must **stop the compile** with one located `ConfigError`, never
  warn-and-ignore — silently dropping `IP_FORWARDING=Off` could leave a box routing when the operator
  believed it wouldn't.
- **Frozen, typed core ([ADR-0001](0001-ir-modeling.md), [ADR-0003](0003-design-approach.md)).** The IR
  is immutable frozen dataclasses; a settings object must fit that model — typed fields, not a raw
  `dict[str, str]` the generator re-parses.
- **One decision, several consumers.** The keys arrive across four epics; the *file format, the model,
  and the fail-fast rule* must be settled once so those epics only add fields.

## Decision

We will introduce an **optional** global-settings file **`shorewallnf.conf`**, parsed into a **frozen,
typed `Settings` dataclass** in the IR, threaded through `compile_config` to the generator (pure core)
and applier (shell). Unknown keys and malformed values **fail fast** ([ADR-0004](0004-error-handling.md)).
This ADR fixes the *format, model, and scope*; each option's behaviour is built by its owning epic.

### 1. The file: optional, added to the reader

`shorewallnf.conf` becomes a known config file. The reader picks it up when present in the config
directory; **its absence is normal and silent** (no error, all defaults). It is added to the reader's
allow-list but is **not** a tabular file — it does not flow through the row/column `parse()` path. It is
handled by a dedicated settings parser that returns the `Settings` object (see §3), keeping the tabular
tokenizer and the `KEY=value` parser cleanly separate.

### 2. Syntax: `KEY=value`, never shell-sourced

The file is a flat list of assignments — deliberately a **subset** of what a shell would accept, so a
file that happens to be valid `shorewall.conf` syntax either parses to the same meaning or fails fast:

- **`KEY=value`** or **`KEY="value"`** (single or double quotes), one assignment per line. Quotes are
  stripped; they exist only to preserve surrounding whitespace or an empty value.
- **`KEY` is uppercase** `[A-Z0-9_]+`. An unknown but well-formed key is a `ConfigError` (§4), not a
  syntax error — the distinction sharpens the message ("unknown setting" vs. "malformed line").
- **`#` comments** — a `#` begins a comment to end of line; blank lines are ignored.
- **No `export`, no line continuations, no `$VAR` / `` `cmd` `` / `$(cmd)` expansion, no word-splitting.**
  The file is **never** passed to a shell and never `eval`'d. A `$` in a value is a literal `$`.
- Values carry no location-free semantics of their own here — the *typed* meaning (enum/bool/int) is
  applied by the `Settings` parser (§3) against the known-key table, not by the syntax layer.

Variable expansion is explicitly **out of scope** (deferred, see §6). The tabular files' existing
`params`/`INCLUDE` mechanisms are unaffected and unrelated.

### 3. The model: a frozen `Settings` dataclass with typed, defaulted fields

A new **`@dataclass(frozen=True, slots=True)` `Settings`** lives in `ir.py` alongside the other IR
records and hangs off `Ruleset` (a `settings: Settings` field defaulting to `Settings()` — every
existing `Ruleset` construction keeps working, and an absent file yields the all-defaults instance).

- **Each supported key is one typed field** — a Python `Enum` for tri-state/choice keys, `bool` for
  Yes/No, `int` for numerics, `str` for free-form — with a **documented default equal to today's
  behaviour.** Absent file ⇒ `Settings()`; absent key ⇒ that field's default. There is no "unset vs.
  default" tri-state at the type level except where the *option itself* is tri-state (e.g. a `Keep`
  member that means "don't touch the kernel value").
- **The parser converts strings to typed fields** and is the point where a **malformed value** for a
  *known* key becomes a `ConfigError` (§4). Cross-field/range niceties beyond basic parsing are shared
  with the validator (#312) so the check lives in one place.
- **YAGNI on fields:** `Settings` starts with **only** the keys #309 wires (§5). #310/#311 *add fields*
  as they build the behaviour; a key with no consumer yet is **not** a silent-accept field — it is an
  unknown key and fails fast (§4). This is the crux of the scope split: a setting exists in the model
  exactly when something reads it.

Illustratively (final field set is each epic's to grow):

```python
class OnOffKeep(Enum):   # IP_FORWARDING
    ON = "On"; OFF = "Off"; KEEP = "Keep"

class YesNoKeep(Enum):   # LOG_MARTIANS, ROUTE_FILTER
    YES = "Yes"; NO = "No"; KEEP = "Keep"

@dataclass(frozen=True, slots=True)
class Settings:
    log_level: str = "info"          # LOG_LEVEL — feeds generator._log (today hard-coded)
    logformat: str = "..."           # LOGFORMAT — prefix template; %s slots from chain/disposition
    ip_forwarding: OnOffKeep = OnOffKeep.KEEP
    log_martians: YesNoKeep = YesNoKeep.KEEP
    route_filter: YesNoKeep = YesNoKeep.KEEP
```

The concrete defaults are pinned by #309's "byte-for-byte" test, not asserted here.

### 4. Fail fast on the unknown or malformed ([ADR-0004](0004-error-handling.md))

The settings parser is **strict**, in the core, and raises — never warns:

- An **unknown key** — a typo, or a legacy `shorewall.conf` knob ShorewallNF doesn't implement (e.g.
  `STARTUP_ENABLED`, `IPTABLES`, `FW`) — is a `ConfigError` naming **file, line, and key**, e.g.
  `shorewallnf.conf:12: unknown setting 'STARTUP_ENABLED'`.
- A **malformed value** for a known key — a non-enum member, a non-integer where an int is expected, a
  `LOGFORMAT` whose rendered prefix exceeds the kernel log-prefix limit — is a `ConfigError` with the
  same file/line/key context.
- A **malformed line** (no `=`, empty key, bad key charset) is a `ConfigError` (a `ParseError` subclass
  is used only if a stage needs to distinguish kinds — YAGNI, per ADR-0004 §3).
- **No warn-and-ignore, no partial acceptance.** Consistent with ADR-0004 §6 the compile stops at the
  first offending setting. Migrating an existing `shorewall.conf` therefore surfaces every unsupported
  knob explicitly, which is the safe behaviour for a firewall compiler.

### 5. Option scope — what this epic (#309) wires vs. what is feature-gated vs. deferred

`shorewallnf.conf` keys divide by **whether a target for the setting exists today.** This ADR fixes the
scope table; each row is delivered by the epic named, and the key is an *unknown key that fails fast*
until then.

| Setting key(s) | Type | Target today? | Owner | Notes |
|---|---|---|---|---|
| `LOG_LEVEL` | str (syslog level) | **Yes** — `generator._log` (hard-coded) | **#309** | Fills the currently-fixed level |
| `LOGFORMAT` | str template | **Yes** — log-prefix emission | **#309** | `%s` slots from chain/disposition; length checked vs. kernel prefix limit |
| `IP_FORWARDING` | `On`/`Off`/`Keep` | **Yes** — new applier sysctl step | **#309** | First applier mutation outside nft; fail-closed/rollback (ADR-0010/0021) |
| `LOG_MARTIANS` | `Yes`/`No`/`Keep` | **Yes** — applier sysctl | **#309** | `Keep` leaves the sysctl untouched |
| `ROUTE_FILTER` | `Yes`/`No`/`Keep` | **Yes** — applier sysctl | **#309** | rp_filter; `Keep` untouched |
| `RPFILTER_DISPOSITION` / `_LOG_LEVEL` | enum/level | **No** — no rpfilter check yet | **#310** | Added with the check it configures |
| `TCP_FLAGS_DISPOSITION` / `_LOG_LEVEL` | enum/level | **No** | **#310** | |
| `SFILTER_DISPOSITION` / `_LOG_LEVEL` | enum/level | **No** | **#310** | |
| `BLACKLIST_DISPOSITION` / `_LOG_LEVEL` | enum/level | **No** | **#310** (blacklist subsystem) | Its own future epic |
| `CLAMPMSS` | `Yes`/`No`/`<pmtu>` | **No** — no MSS-clamp emission | **#311** | Generator forward-path mode |
| `DISABLE_IPV6` | `Yes`/`No` | **No** — no family-gate mode | **#311** | Generator family-gate (ADR-0002) |
| `REJECT_ACTION`, default-policy actions, `MULTICAST`, `OPTIMIZE`, `DYNAMIC_BLACKLIST`, variable expansion | — | **Deferred** | — | Not modeled until a real need arrives (YAGNI) |

**Self-contained / "target exists"** (the top five rows) is exactly #309's cut. **Feature-gated** rows
are added by the epic that builds their behaviour — the key is accepted *there*, not here, so shipping
#309 doesn't have to accept a key nothing reads. **Deferred** keys are not modeled at all; if one is
found in a file it fails fast like any unknown key, and adopting it is a future ADR/epic.

### 6. Sharing and boundaries

- **Validation is shared with #312.** The `Settings` parser does the *string→type* conversion and the
  minimal well-formedness needed to build the object; consistent enum/range/format checks (and the
  actionable messages) are consolidated in the validator hardening epic so settings validation isn't a
  second, divergent code path.
- **Threading.** `compile_config` (`cli.py`) gains `Settings` on the `Ruleset` it builds; the **pure
  generator** reads it for emission-time settings (`LOG_LEVEL`/`LOGFORMAT`, later `CLAMPMSS`/
  `DISABLE_IPV6`), and the **applier** reads it for kernel-state settings (`IP_FORWARDING` etc.). No new
  side effects in the core — the generator only *reads* `Settings`.
- **Variable expansion stays out.** No `$VAR`/params-style substitution in `shorewallnf.conf`; revisit
  under a dedicated ADR only if a concrete need appears.

## Consequences

- ShorewallNF gains a **settings concept**: whole-ruleset behaviour has a typed home, and the four
  consuming epics (#309–#312) share one file format, one model, and one fail-fast rule — they only add
  fields.
- **Backward-compatible by construction:** an absent file (or absent key) is the all-defaults `Settings`,
  which #309 pins to today's output byte-for-byte. Adopting the file is opt-in.
- **Migration is loud, not silent:** dropping an old `shorewall.conf` in place fails fast on the first
  unsupported knob rather than silently ignoring it — correct for a firewall compiler, but it means a
  user migrating from Shorewall must translate their file, not copy it. The scope table (§5) is the
  translation guide for what is/isn't supported yet.
- **A non-tabular parser** now lives beside the tabular one; a small amount of parsing machinery is not
  reused. Accepted — forcing `KEY=value` through the row/column tokenizer would be worse.
- **The generator becomes settings-aware** where it was hard-coded (the `_log` level, later the log
  prefix and global modes). Its purity is preserved: it *reads* `Settings`, emits data, does no I/O.
- **The applier gains its first non-nftables kernel mutation** (sysctls, in #309). That is flagged here
  as a boundary the sysctl work must honour under the fail-closed/rollback contract
  ([ADR-0010](0010-atomic-scoped-replace.md)/[ADR-0021](0021-stopped-safe-state.md)) — this ADR only
  scopes it; #309 designs it.
- **Field growth is gated on consumers:** because a key exists in `Settings` only when something reads
  it, the model can't drift ahead of behaviour, and every accepted key is testable end-to-end when it
  lands.

## Alternatives considered

- **Source the file as shell (upstream `shorewall.conf` behaviour).** Rejected: variable expansion and
  command substitution are an injection surface, and shell word-splitting is a parsing model we can't
  make fail-fast or type-check. A pure data format we parse ourselves is safer and fits the functional
  core (ADR-0003).
- **Reuse the tabular `parse()` path** (treat each setting as a two-column `KEY value` row). Rejected:
  it overloads the row/column tokenizer with a different grammar (quoting, `=`, comments-to-EOL) and
  blurs "a setting" with "a record." A dedicated `KEY=value` parser is clearer and keeps each grammar
  small.
- **A raw `dict[str, str]` of settings threaded through the pipeline.** Rejected: it defers every
  type/enum/range decision to each read site (the generator re-parsing strings), contradicts the typed,
  frozen IR (ADR-0001), and scatters validation. A typed frozen `Settings` centralizes it.
- **Warn-and-ignore unknown keys** (accept a legacy `shorewall.conf` verbatim, skip what we don't know).
  Rejected: it violates fail-fast (ADR-0004) and can silently drop a security-relevant knob
  (`IP_FORWARDING=Off`), leaving the operator's intent unmet. Failing fast forces an explicit migration.
- **Accept all ADR-0061 keys now, no-op the ones without behaviour.** Rejected: a key that parses but
  does nothing is a silent lie to the operator (`CLAMPMSS=Yes` that clamps nothing). Gating each key on
  the epic that gives it an effect (§5) keeps "accepted" and "does something" the same set.
- **Add variable expansion / `$VAR` up front.** Rejected (YAGNI): no current setting needs it; adopt
  under its own ADR if a concrete case arrives.
