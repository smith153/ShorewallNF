# ADR-0051: Transparent-proxy mark reservation and local-delivery routing

- **Status:** Accepted
- **Date:** 2026-07-08

> **Decision:** the owner (Sam) approved **Option (a) — a single reserved `TPROXY_MARK` constant**
> on 2026-07-08. The mark-model fork below is settled in its favour; the other options are recorded
> under *Alternatives considered*. The `#272` issue stays open — it closes when the implementation
> lands, not this ADR. Numbering `0051` is provisional; confirm it is not reserved by another
> in-flight task before merge.

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

Two parts: Part A reserves the tproxy mark and table id; Part B is the routing-artifact model.

### Part A — a single reserved `TPROXY_MARK` constant (Option a, chosen)

We will use **one compiler-supplied reserved mark** that `DIVERT` and `TPROXY(<port>)` both set and
a single `ip rule fwmark` consumes — Shorewall's `TPROXY_MARK` analogue. The mark is **not** a
per-rule operator value: `DIVERT` and `TPROXY(<port>)` are markless in surface syntax (`DIVERT` gains
an optional `DIVERT(<mark>)` form only for symmetry/overrides if a later need arises — not required
here), and the generator injects `TPROXY_MARK`. This keeps the [ADR-0050](0050-policy-routing-artifact-model.md)
single-owner-of-the-mark rule intact: exactly one well-known value belongs to tproxy, and the
validator forbids any provider from claiming it.

**Concrete reserved constants.** The provider space is *open-ended* — the validator today accepts a
provider `fwmark` of `1..0xFFFFFFFF` (`_MAX_U32`) and a routing-table `number` of `1..0xFFFFFFFF`
excluding the kernel-reserved `{0, 253, 254, 255}` (`validator.py` `_reject_reserved_or_out_of_range`).
There is no low "reserved end" to slot into, so we reserve the **top** of each space and shrink the
provider ranges by one:

- **`TPROXY_MARK = 0xFFFFFFFF`** — the maximum 32-bit fwmark. TPROXY and DIVERT emit
  `meta mark set 0xffffffff` (a plain full-width set, matching ADR-0042's existing plain
  `meta mark set` for these actions); the routing rule matches `fwmark 0xffffffff`.
- **`TPROXY_TABLE_ID = 0xFFFFFFFF`** — the maximum 32-bit routing-table id, not one of the
  kernel-reserved ids `{0, 253, 254, 255}`, so teardown's `ip route flush table 0xffffffff` can never
  wipe a system table. (The mark and the table id share the numeral but live in disjoint namespaces —
  fwmark vs. routing-table id — so they cannot collide with *each other*.)

**Why these are provably collision-safe (this becomes the validator rule).** Provider fwmarks and
table ids are matched by *exact* value (no masks), so a collision is possible only if some provider
is assigned the identical value. The follow-up validator change (§follow-ups) narrows the accepted
provider ranges to exclude the reserved constants:
- provider `fwmark`: `1..0xFFFFFFFE` (was `1..0xFFFFFFFF`) — `0xFFFFFFFF` now reserved for tproxy;
- provider `number` (table id): `1..0xFFFFFFFE` excluding `{253, 254, 255}` (was `1..0xFFFFFFFF`) —
  `0xFFFFFFFF` now reserved for tproxy, alongside the existing kernel reservations.

With those two range caps, no valid provider can ever carry `TPROXY_MARK` or use `TPROXY_TABLE_ID`,
so a tproxy'd packet (mark `0xffffffff`) is selected *only* by the tproxy `ip rule` into
`TPROXY_TABLE_ID`, never a provider table — collision-safety by construction, enforced fail-closed
([ADR-0004](0004-error-handling.md)) at validate time. Reserving the extreme top end also makes an
accidental clash astronomically unlikely in practice (provider numbers are realistically small), so
the range cap is a backstop, not a routine rejection.

**Note on same-packet coexistence.** A plain `meta mark set 0xffffffff` overwrites any prior mark, so
a packet cannot be *both* provider-marked and tproxy-marked — acceptable here (transparent proxy and
provider routing on the same packet is not a supported combined scenario). If that need ever arrives,
a reserved-*bit*/mask partition of the mark space (see *Alternatives*) is the clean upgrade and would
supersede this ADR.

### Part B — the local-delivery routing artifact

We will emit the transparent-proxy local delivery as an **inert routing artifact on the existing
second channel** ([ADR-0050](0050-policy-routing-artifact-model.md)), applied and torn down exactly
like provider routing:

- **Shape.** A provider `RoutingArtifact` is a *default route via a gateway*; a tproxy artifact is a
  *`local` route out `lo`*. These are different enough that a **new frozen dataclass**
  (`TproxyRoutingArtifact`, in `ir.py`) is cleaner than overloading `RoutingArtifact` with optional
  gateway/`local` fields (ADR-0050 chose one record *per provider* precisely to avoid a union;
  a distinct source and route type here argues for a sibling type, not a widened one). It carries:
  `table_id` (= `TPROXY_TABLE_ID`, `0xFFFFFFFF`), `fwmark` (= `TPROXY_MARK`, `0xFFFFFFFF`), and
  `family`. It renders to `ip -N rule add fwmark 0xffffffff table 0xffffffff` +
  `ip -N route add local 0.0.0.0/0 dev lo table 0xffffffff` (v6: `::/0`).
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
- **Table-id collision-safety.** The tproxy table id is the reserved `TPROXY_TABLE_ID` (`0xFFFFFFFF`,
  Part A); the validator caps provider table ids at `1..0xFFFFFFFE` so no provider can claim it.

## Consequences

- Transparent proxy becomes **self-sufficient**: `DIVERT` + `TPROXY(<port>)` compile to both the nft
  redirect *and* the fwmark local-delivery routing, so a TPROXY'd packet reaches the local listener
  with no hand-installed glue. The #231 netns test can **drop its `iif <iface>` workaround** and
  assert the idiomatic fwmark path end to end.
- The generator's dead DIVERT-mark branch becomes live (fed by the compiler-supplied `TPROXY_MARK`,
  not a user integer).
- `TPROXY_MARK` (`0xFFFFFFFF`) and `TPROXY_TABLE_ID` (`0xFFFFFFFF`) are carved out of the top of the
  provider mark/table-id space; the validator's accepted provider ranges shrink to `1..0xFFFFFFFE`
  (mark) and `1..0xFFFFFFFE` excluding `{253, 254, 255}` (table id). A tproxy'd packet is thereby
  guaranteed to select only the tproxy table, never a provider's — collision-safe by construction.
  Same-packet provider+tproxy marking is not supported (the plain full-width `meta mark set`
  overwrites); a mask partition would be the upgrade if ever needed.
- A second routing artifact type lives alongside `RoutingArtifact`; `generator.py`'s routing channel
  now lowers two sources. Acceptable (ADR-0050 already anticipated the channel growing); split into a
  package later if it grows unwieldy.

### Mechanical follow-ups (NOT part of this ADR; the Epic Decomposer files these)

Now the decision is settled, these fall out as small, individually-testable tasks — filed by the
Epic Decomposer, not here:

1. **Parser:** the generator injects `TPROXY_MARK` for DIVERT/TPROXY (no per-rule value needed);
   populate `MangleRule.mark` for DIVERT so the generator branch fires. (An optional `DIVERT(<mark>)`
   surface form is not required by this ADR — add only if a real override need appears.)
2. **Generator (nft):** the existing DIVERT-mark branch goes live; TPROXY sets the mark; both use
   the single `TPROXY_MARK = 0xFFFFFFFF`.
3. **Generator (routing):** emit the `TproxyRoutingArtifact`(s) (one per family with any TPROXY),
   `fwmark`/`table_id` = `0xFFFFFFFF`.
4. **Applier:** install/tear down the fwmark rule + `local` route, ordered like provider routing.
5. **Validator:** cap provider `fwmark` at `1..0xFFFFFFFE` and provider table `number` at
   `1..0xFFFFFFFE` excluding `{253, 254, 255}`, reserving `0xFFFFFFFF` for tproxy (extend
   `_reject_reserved_or_out_of_range`).
6. **Netns test (#231 follow-up):** drop the `iif` workaround; assert TPROXY delivery via the
   compiled fwmark local-delivery routing.

## Alternatives considered

The mark-model fork the owner resolved in favour of Option (a) above:

- **(b) A reserved high-bit / mask carved out of the mark space** (e.g. reserve `0x80000000`;
  TPROXY/DIVERT set the bit with a masked write, `ip rule` matches `fwmark 0x80000000/0x80000000`,
  providers keep the low bits). Structurally collision-proof and lets a packet be *both*
  provider-marked and tproxy-marked — but shrinks the provider space and imposes a mask convention
  that no current config needs (YAGNI). Held in reserve: this is the clean upgrade if same-packet
  provider+tproxy coexistence is ever required, and would supersede this ADR then.
- **(c) A configurable per-rule mark validated against provider marks** (`TPROXY(<port>,<mark>)` /
  `DIVERT(<mark>)` plus a cross-source uniqueness check). Rejected: it bakes in exactly the
  per-rule model the #272 reporter cautions against, pushing collision-safety onto the operator and
  a cross-cutting validation rule for a feature with one known shape.

On the routing artifact:

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
