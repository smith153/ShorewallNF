# ADR-0051: Transparent-proxy mark reservation and local-delivery routing

- **Status:** Proposed
- **Date:** 2026-07-08

> **PROPOSAL — awaiting owner approval.** This ADR frames one architecture decision with an
> explicit **fork** the owner must resolve (see *Decision → the open fork*). It is not accepted;
> nothing downstream should be built until it is. Numbering `0051` is provisional; confirm it is
> not reserved by another in-flight task before merge.

## Context

The mangle transparent-proxy compilation ([ADR-0042](0042-mangle-compilation.md)) lowers
`DIVERT`/`TPROXY(<port>[,<mark>])` into a `prerouting` chain, and the policy-routing artifact
channel ([ADR-0050](0050-policy-routing-artifact-model.md)) lowers `providers` into
`ip rule`/`ip route`. But a compiled transparent proxy is **not self-sufficient**: the ruleset can
redirect a packet to a TPROXY socket, yet nothing it emits makes the kernel *deliver* that packet
to the local listener. Two concrete gaps, surfaced by the #231 netns test (which had to fall back to
an `iif <iface>` routing workaround instead of the idiomatic fwmark glue):

1. **DIVERT can't carry a mark.** `parser.py:_parse_mangle_action` returns `("DIVERT", None, None,
   None)` for the bare `DIVERT` token, so `MangleRule.mark` is always `None` for DIVERT. The
   generator's DIVERT branch (`generator.py`: `if rule.mark is not None: stmts.append(_mark_set(
   "meta", rule.mark, None))`) is therefore **unreachable dead code**, and ADR-0042 §4's "optional
   `meta mark set`" for DIVERT is never produced.

2. **No local-delivery routing for TPROXY.** The only routing channel is `generate_routing` →
   `RoutingArtifact`, which lowers a **provider** into a *default-route-via-gateway* (`table_id`,
   `fwmark`, `gateway`, `interface`). Transparent-proxy local delivery is a **different route type
   from a different source** — `ip route add local 0.0.0.0/0 dev lo table <t>` + `ip rule fwmark <m>
   lookup <t>` — and does not fit that record.

The canonical nftables tproxy idiom marks **both** the DIVERT rule and the TPROXY rule with one
shared mark (`socket transparent … meta mark set N accept` / `tproxy to :P meta mark set N accept`),
so a single `ip rule fwmark N lookup T` delivers **new** *and* **established/half-open** packets to
the local stack. Both gaps are two facets of one undecided item: **which mark, and the routing that
consumes it.**

Forces:

- **One owner for the mark ([ADR-0050](0050-policy-routing-artifact-model.md) §4, "One owner for
  the mark").** Provider fwmarks consume `meta mark` to select routing tables; the validator already
  rejects two providers sharing a fwmark (`validator.py`). A tproxy mark that can equal a provider
  fwmark would make the packet select the *provider's* table instead of the local-delivery table —
  silent misroute. Collision-safety against provider marks is the crux.
- **Non-functional in isolation (YAGNI / fail-fast, [ADR-0004](0004-error-handling.md)).** A DIVERT
  mark's only consumer is fwmark policy routing. Shipping mark-carrying DIVERT syntax without the
  routing that consumes it is a half-feature; the mark model and the routing model must land
  together.
- **Pure functional core ([ADR-0003](0003-design-approach.md)).** Local-delivery routing is inert
  data emitted by the generator and applied by the Applier ([ADR-0050](0050-policy-routing-artifact-model.md),
  #235) — never side effects or pre-rendered shell.
- **Family-aware ([ADR-0002](0002-unified-inet-dual-stack.md)).** A `local` route + `ip rule` are
  per-family (`ip -4`/`ip -6`); an `inet` TPROXY already selects `ip`/`ip6` by rule family.
- **Fail closed ([ADR-0004](0004-error-handling.md)).** Never emit routing that can't be a concrete
  entry, and never silently mark/route more than written.

## Decision

Two parts. Part B (the routing-artifact model) is stable and recommended as written; **Part A is an
open fork the owner must choose.**

### Part A — reserving the tproxy mark (THE OPEN FORK)

A transparent proxy needs a mark that DIVERT and TPROXY both set and one `ip rule fwmark` consumes,
which must be **collision-safe against provider fwmarks** (ADR-0050's single-owner rule). Three
options, each a different point on the simplicity ↔ flexibility ↔ coexistence-with-providers axis:

**Option 1 — a single reserved constant `TPROXY_MARK` (Shorewall's analogue).**
One fixed value (e.g. `0x1`), a named constant in the generator; `DIVERT` and `TPROXY(<port>)` both
set it, one emitted `ip rule fwmark 0x1 lookup <tproxy-table>`. The parser stops accepting a
per-rule mark entirely — `DIVERT` and `TPROXY(<port>)` are markless in surface syntax; the compiler
supplies the mark.
- *Pros:* simplest; matches Shorewall; nothing for the operator to get wrong; one obvious value to
  document as reserved. Collision-safety reduces to "the validator rejects any provider using the
  reserved value."
- *Cons:* a bare integer can still collide with the *full* 32-bit provider fwmark if a provider
  picks it; must reserve it globally and validate. Inflexible if two independent tproxy setups ever
  need distinct marks (no current requirement — YAGNI).

**Option 2 — a reserved high-bit / mask carved out of the mark space.**
Partition `meta mark`: reserve one high bit (e.g. `0x80000000`, or a small top mask) for tproxy,
leave the low bits to providers. TPROXY/DIVERT set the reserved bit with a masked write
(`mark & ~M | bit`); the `ip rule` matches `fwmark 0x80000000/0x80000000`; the validator constrains
provider fwmarks to the un-reserved range.
- *Pros:* structurally collision-proof — tproxy and provider marks live in disjoint bit ranges and
  can coexist on the same packet (a packet can be both provider-marked and tproxy-marked). No shared
  scalar to accidentally reuse.
- *Cons:* shrinks the provider fwmark space and imposes a mask convention providers must obey;
  masked reads/writes are more machinery than any current config needs (masks already exist for
  MARK/CONNMARK, so not foreign, but still added surface). Over-engineered if tproxy and providers
  are never used together in the reference config.

**Option 3 — a configurable mark with validation against provider marks.**
Keep `TPROXY(<port>,<mark>)`/`DIVERT(<mark>)` per-rule (or a single global setting), but add a
validator pass that rejects any tproxy mark equal to a provider fwmark (extend the existing
`validator.py` uniqueness check to span both sources).
- *Pros:* flexible; no reserved constant baked in; reuses the validator's existing mark-uniqueness
  machinery, just widening its scope.
- *Cons:* pushes correctness onto the operator + a cross-cutting validation rule; is exactly the
  "per-rule values that can collide with provider fwmarks" model the #272 reporter warns against;
  more moving parts for a feature with one known shape.

**Recommendation: Option 1 (single reserved `TPROXY_MARK` constant), with the mask mechanics of
Option 2 held in reserve.** It is the least machinery for the only shape the project needs today
(YAGNI), matches the well-understood Shorewall model, and makes collision-safety a one-line
validator rule ("no provider may use the reserved tproxy mark"). If a real need for provider +
tproxy coexistence on the same packet ever arrives, Option 2's reserved-bit scheme is the clean
upgrade and can supersede this ADR then. Option 3 is declined: it bakes in the collision-prone
per-rule model the report explicitly cautions against.

*Owner decision required:* pick 1, 2, or 3 (and, if 1/2, the concrete reserved value/bit and the
tproxy routing-table id). The rest of this ADR assumes the chosen mark is a single value the
generator knows.

### Part B — the local-delivery routing artifact (recommended as written)

We will emit the transparent-proxy local delivery as an **inert routing artifact on the existing
second channel** ([ADR-0050](0050-policy-routing-artifact-model.md)), applied and torn down exactly
like provider routing:

- **Shape.** A provider `RoutingArtifact` is a *default route via a gateway*; a tproxy artifact is a
  *`local` route out `lo`*. These are different enough that a **new frozen dataclass**
  (`TproxyRoutingArtifact`, in `ir.py`) is cleaner than overloading `RoutingArtifact` with optional
  gateway/`local` fields (ADR-0050 chose one record *per provider* precisely to avoid a union;
  a distinct source and route type here argues for a sibling type, not a widened one). It carries:
  `table_id` (the dedicated tproxy routing table), `fwmark` (the reserved tproxy mark from Part A),
  and `family`. It renders to `ip -N rule add fwmark <fwmark> table <table_id>` +
  `ip -N route add local 0.0.0.0/0 dev lo table <table_id>` (v6: `::/0`).
- **Generation.** `generate_routing` (or a sibling `generate_tproxy_routing`) emits **one artifact
  per family that has any TPROXY rule** — not one per rule (all tproxy rules share the one reserved
  mark and one local table). Pure `IR → data`, no I/O.
- **Family.** v4 TPROXY → a v4 `local 0.0.0.0/0` artifact; v6 → `::/0`; a dual-stack config with
  both yields one per family. Consistent with ADR-0050's per-family routing tables and ADR-0042's
  fail-closed `both`-family TPROXY.
- **Application / teardown.** The Applier installs the fwmark rule + local route and tears them down
  idempotently, in the same install-after-nft-load / teardown-before-reinstall order as
  provider routing (`applier.py` `routing_install_argv`/`routing_teardown_argv`), so stop/clear
  removes them cleanly (fail-closed rollback on a rejected `ip`, [ADR-0004](0004-error-handling.md)).
- **Table-id collision-safety.** The tproxy table id must not collide with a provider table id
  (= provider number). Reserve a dedicated id (paired with the Part A decision) and extend the
  validator's table-id uniqueness check to cover it.

## Consequences

- Transparent proxy becomes **self-sufficient**: `DIVERT` + `TPROXY(<port>)` compile to both the nft
  redirect *and* the fwmark local-delivery routing, so a TPROXY'd packet reaches the local listener
  with no hand-installed glue. The #231 netns test can **drop its `iif <iface>` workaround** and
  assert the idiomatic fwmark path end to end.
- The generator's dead DIVERT-mark branch becomes live (fed by the compiler-supplied reserved mark,
  not a user integer under Options 1/2).
- A reserved tproxy mark **and** table id are carved out of the provider space; the validator gains
  one cross-source collision rule. Providers and tproxy coexist safely only to the degree the chosen
  option guarantees (Option 2 fully; Options 1/3 by validation).
- A second routing artifact type lives alongside `RoutingArtifact`; `generator.py`'s routing channel
  now lowers two sources. Acceptable (ADR-0050 already anticipated the channel growing); split into a
  package later if it grows unwieldy.

### Post-approval mechanical follow-ups (NOT part of this ADR; decompose after acceptance)

Once the owner picks an option, these fall out as small, individually-testable tasks — filed by the
Epic Decomposer, not here:

1. **Parser:** accept `DIVERT(<mark>)` (and drop/keep per-rule TPROXY mark per the chosen option);
   wire the reserved mark through so `MangleRule.mark` is populated for DIVERT.
2. **Generator (nft):** the existing DIVERT-mark branch goes live; TPROXY sets the reserved mark;
   both use the single `TPROXY_MARK`.
3. **Generator (routing):** emit the `TproxyRoutingArtifact`(s) (one per family with any TPROXY).
4. **Applier:** install/tear down the fwmark rule + `local` route, ordered like provider routing.
5. **Validator:** reject a provider fwmark / table id that collides with the reserved tproxy
   mark / table (and, for Option 2, enforce the mask partition).
6. **Netns test (#231 follow-up):** drop the `iif` workaround; assert TPROXY delivery via the
   compiled fwmark local-delivery routing.

## Alternatives considered

- **Overload `RoutingArtifact` with optional gateway/`local` fields** rather than a sibling type.
  Rejected: it reintroduces the tagged-union shape ADR-0050 deliberately avoided; a `local`-out-`lo`
  route and a default-via-gateway route share almost no fields.
- **Ship Gap 1 alone (accept `DIVERT(<mark>)`, wire the branch) as a bounded fix.** Rejected (and
  this is why #272 is architecture, not a bug): a DIVERT mark's only consumer is the fwmark routing
  that doesn't exist yet, so it is a non-functional half-feature, and an arbitrary per-rule integer
  prejudges the mark model against ADR-0050's single-owner rule — exactly the fork this ADR exists
  to resolve.
- **Match tproxy ingress by interface (`ip rule iif <iface> lookup <t>`)** — the #231 test's
  workaround. Rejected as the product model: it needs the operator to name the ingress interface,
  doesn't generalise across interfaces, and isn't the canonical fwmark idiom; it was a test scaffold,
  not a design.
- **Emit no routing and document the glue as operator responsibility** (status quo). Rejected: it
  leaves transparent proxy non-self-sufficient — the exact defect #272 reports.
