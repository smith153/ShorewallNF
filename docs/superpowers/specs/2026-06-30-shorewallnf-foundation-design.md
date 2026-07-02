# ShorewallNF — Foundation & AI Pipeline Design

- **Date:** 2026-06-30
- **Status:** Draft — awaiting user review
- **Scope of this spec:** the project *foundation* and the *AI development pipeline* ("the factory"). It does **not** design the firewall compiler's internals — that is the pipeline's job, and this spec seeds the epics that will drive it.

---

## 1. Summary

ShorewallNF is a from-scratch reimplementation of [Shorewall](https://shorewall.org) that targets **nftables** instead of iptables, written in **Python**. It reads Shorewall-style configuration files and emits an nftables ruleset.

The project is developed almost entirely by **AI agents** coordinated through **GitHub**. Human maintainers steer direction (approve epics) and gate merges to `master`; everything in between is autonomous. Volunteers contribute by pointing *their own* AI agents at the repo — picking a pipeline *role* for a session (e.g. "tonight my agent is the code reviewer").

This session produces the repository scaffolding, the pipeline's role definitions and coordination machinery, the contributor/architecture docs, and the seed backlog. No compiler logic is written here.

## 2. Goals & non-goals

**Goals of this session**
- A repository foundation: `README.md`, `CLAUDE.md`, `STATUS.md`, `LICENSE` (GPLv2), `pyproject.toml`, `.gitignore`, `docs/`.
- A complete, provider-agnostic **AI pipeline**: role prompts, label taxonomy, lifecycle/workflow doc, GitHub issue/PR templates, CODEOWNERS, CI skeleton, label-sync tooling.
- A thin **Claude Code adapter** (slash commands / subagents) over the canonical role prompts.
- The **seed backlog** documented (epics derived from the reference config), created as *files/docs* — not yet pushed to the GitHub tracker.

**Non-goals of this session**
- Writing the compiler (parser, IR, generator, applier). That is produced *by* the pipeline.
- Creating GitHub issues/labels on the remote (files only for now; the user will trigger population later).
- Downloading original Shorewall source (tracked as a task; `orig_source/` is gitignored when it lands).

## 3. Definition of "done" for the product (MVP)

**MVP = basic, stateful, dual-stack (IPv4 + IPv6) routing and port-forwarding**, modeled on a documented subset of the reference config.

- **In scope:** zones, interfaces (+ basic/family-appropriate options), inter-zone policy, basic rules (`ACCEPT`/`DROP`/`REJECT` with proto/ports/port-ranges and `zone:host` qualifiers), stateful base (`ct state established,related accept` and Shorewall `?SECTION`s), DNAT/port-forwarding (v4), SNAT/`MASQUERADE` (v4), and the v6 equivalent (direct-accept to global addresses, no NAT).
- **Out of scope (post-MVP backlog):** macros & custom actions (`Ping`, `Invalid`, `AwsDrop`), conntrack *helpers* (the `conntrack` file), mangle/`TPROXY`/`DIVERT`, providers/policy-routing, QoS/traffic-shaping (`tc*`), advanced interface hardening options.
- **Success criterion:** the generated ruleset is **functionally equivalent** to what the reference config produces, **verified behaviorally** (see §7). Byte-identical output is explicitly *not* a goal — the original emits iptables, we emit nftables.

### 3.1 IPv4/IPv6 reconciliation (the interesting part)

The v4 and v6 configs express the **same intent through different mechanisms**. The unified model must reconcile:

| Concern | IPv4 (`shorewall`) | IPv6 (`shorewall6`) |
|---|---|---|
| Service exposure | `DNAT` (+ `MASQUERADE`) | plain `ACCEPT` to global address (no NAT) |
| ICMP | `icmp` | `ipv6-icmp` |
| Interface options | `routefilter`, `logmartians` (v4 sysctls) | `forward=1` |
| Rule sections | implicit | explicit `?SECTION ESTABLISHED/RELATED/INVALID/NEW…` |
| Zones | `net/loc/dmz` typed `ipv4` | same names typed `ipv6` |

This is why the architecture is **unified `inet` with a family-aware IR** (§5): one config intent, family-correct nftables output.

## 4. Key decisions (with rationale)

| # | Decision | Rationale |
|---|---|---|
| D1 | **Language: Python** (≥3.11) | First-class nftables JSON API via `python3-nftables`; static typing (`mypy`) keeps AI-written code consistent; far larger contributor pool than Perl. |
| D2 | **Architecture: IR-centered compiler pipeline** | Decouples parsing from codegen; enables unit-testing the parser and golden-testing the generator independently. |
| D3 | **Unified `inet`, dual-stack, family-aware IR** | nftables' `inet` family removes iptables' reason for the v4/v6 split; one config model, generator emits family-correct rules. Recorded as ADR-0002. |
| D4 | **Coordination: native GitHub flow + light labels** | PRs already are a review/merge queue with states + CI gates; labels describe *type/status*, not the whole engine. An upstream *refinement* pipeline feeds the standard flow. |
| D5 | **Autonomy posture: human approves epics + final merge** | Humans steer direction and do the last look; branch protection + CODEOWNERS ensure the AI reviewer's approval cannot by itself unlock merge. |
| D6 | **Roles: provider-agnostic prompts + thin Claude Code adapter** | Canonical role definitions any agent runtime can consume; Claude Code users get ergonomic slash commands on top. Inclusive for a public volunteer project. |
| D7 | **Testing: pyramid (golden-file + `nft -c` → netns → corpus spike)** | Fast hermetic base for TDD; behavioral proof via network namespaces; the nft↔iptables/Shorewall-corpus comparison is a non-blocking research spike. |
| D8 | **License: GPLv2** | Matches original Shorewall; safe if original logic is ever referenced. |
| D9 | **Project state = tracker + docs + STATUS.md** | No bespoke "AI memory" side-channel (it drifts). Issues are the living backlog; `docs/`+ADRs are durable decisions; `STATUS.md` is the snapshot agents read first. |

## 5. Product architecture (the north star for `docs/ARCHITECTURE.md`)

```
config dir ─► Reader ─► Parser ─► IR / model ─► Validator ─► nft Generator ─► Applier
                          ▲                                        │
             params + ?if/?FORMAT/?SECTION                   nftables JSON
                 preprocessor resolved here                (python3-nftables)
```

- **Reader** — locates and loads the config directory's files.
- **Preprocessor** — resolves `params`, `?if/?elsif/?else/?endif`, `?FORMAT`, `?SECTION`.
- **Parser** — turns each file into structured, **nftables-agnostic** IR objects.
- **IR / model** — typed, **family-aware** representation of zones, interfaces, policies, rules, NAT. Knows nothing about nftables. (dataclasses vs pydantic → ADR-0001.)
- **Validator** — semantic checks (unknown zones, bad refs, ordering/dependency correctness).
- **Generator** — consumes IR, emits nftables **JSON** for libnftables (family-correct: `icmp` vs `icmpv6`, DNAT vs direct-accept, etc.).
- **Applier** — loads/validates the ruleset (`nft -c`, then apply).

**Standards baseline (`CLAUDE.md`):** Python ≥3.11, full type hints, `ruff` + `mypy` + `pytest`, minimal runtime deps (stdlib + `python3-nftables`). Deeper choices (IR modeling lib, module boundaries, error-handling conventions) are decided by the **Architecture epic** as ADRs before significant code lands.

## 6. The factory (AI development pipeline)

Two phases: an upstream **Refinement** pipeline that grooms work to `implementation-ready`, then the standard GitHub **Delivery** flow.

### 6.1 Roles

| # | Role | Phase | Reads | Produces | Guardrails |
|---|------|-------|-------|----------|------------|
| 1 | **Epic Author** | Refine | `STATUS.md`, `docs/`, reference config, open epics | `type:epic` issues as `status:proposed` | Human approves before decomposition |
| 2 | **Epic Decomposer** | Refine | one approved epic | child `type:task` issues, `status:proposed`, native sub-issues + `blocked-by` links | Tasks must have acceptance criteria |
| 3 | **Task Groomer** | Refine | `status:proposed` tasks | `implementation-ready` \| request-changes \| reject-with-reason | Necessity/YAGNI check; **max 2 churn rounds** then escalate `needs-human` |
| 4 | **Implementer** | Deliver | unblocked `implementation-ready` | worktree + PR (`Closes #N`), TDD | Claims via assignee + `status:in-progress`; work in own worktree |
| 5 | **Code Reviewer** | Deliver | open PRs | review (comment / request-changes) | **Cannot** authorize merge (CODEOWNERS) |
| 6 | **Fixer** | Deliver | PRs with requested changes | pushes fixes | — |
| 7 | **Merge-readiness** | Deliver | approved + green PRs | `status:ready-to-merge` | **Human clicks merge** |

Symmetry to notice: there is a reviewer on *both* halves — one reviews **tickets** (are they necessary/well-formed), one reviews **code** (is it correct).

### 6.2 Labels (canonical taxonomy → `pipeline/labels.md` + `.github/labels.yml`)

- **type:** `epic`, `task`, `bug`, `spike`, `docs`, `ci`, `architecture`
- **status:** `proposed`, `needs-refinement`, `implementation-ready`, `in-progress`, `blocked`, `in-review`, `ready-to-merge`
- **area:** `parser`, `generator`, `cli`, `ir`, `zones`, `interfaces`, `policy`, `rules`, `nat`, `preprocessor`, `testing`, `ci`
- **meta:** `good-first-issue`, `needs-human`, `blocked-external`

### 6.3 Lifecycle (→ `pipeline/workflow.md`)

```
Epic Author ─► epic:proposed ─►(human approve)─► Decomposer ─► task:proposed
     ─► Groomer ──(≤2 rounds)──► implementation-ready
     ─► Implementer (assignee + in-progress) ─► PR (Closes #N) ─► in-review
     ─► Code Reviewer ⇄ Fixer ─► approved + green CI
     ─► Merge-readiness ─► ready-to-merge ─►(human merge)─► closed
```

**Collision avoidance:** an agent claims a task by self-assigning **and** adding `status:in-progress` atomically; agents only pick tasks that are unassigned, `implementation-ready`, and unblocked.

**Human gates:** (a) approve `epic:proposed` → enters pipeline; (b) merge to `master` (branch protection: green CI + human review via CODEOWNERS).

## 7. Testing & CI

Testing pyramid (→ `docs/ARCHITECTURE.md` + CI):

1. **Base — golden-file snapshots + `nft -c`** (every PR, no root). For a given config, assert generated nft ruleset matches a checked-in expected file; `nft -c` validates syntax. This is the TDD workhorse.
2. **Middle — network-namespace integration** (privileged CI job). Load the ruleset into `ip netns`, assert packet-path behavior for policy DROP, DNAT, SNAT, dual-stack ICMP. Proves "equivalent to the reference config."
3. **Aspirational — Shorewall-corpus comparison spike.** The nft↔iptables comparison idea, tracked as its own epic/spike; non-blocking; may only ever cover a subset.

**CI (`.github/workflows/ci.yml`):** `ruff` + `mypy` + `pytest` on every PR; a separate privileged job for the netns tier.

## 8. Repository layout (deliverables of this session)

```
README.md              CLAUDE.md              STATUS.md              LICENSE (GPLv2)
pyproject.toml         .gitignore             .editorconfig
docs/
  ARCHITECTURE.md      CONTRIBUTING.md        adr/0001-…  adr/0002-…
  superpowers/specs/2026-06-30-shorewallnf-foundation-design.md
pipeline/
  README.md  workflow.md  labels.md
  roles/ epic-author.md epic-decomposer.md task-groomer.md
         implementer.md code-reviewer.md fixer.md merge-readiness.md
.claude/
  commands/*.md         agents/*.md         (thin wrappers → pipeline/roles/*)
.github/
  workflows/ci.yml      ISSUE_TEMPLATE/{epic.yml,task.yml}
  pull_request_template.md   CODEOWNERS   labels.yml
src/shorewallnf/__init__.py   (package stub only — no compiler logic)
tests/                        (harness layout + golden-file dirs)
scripts/sync-labels           (create/update GH labels from labels.yml)
```

`.gitignore` excludes `my_shorewall/` and `orig_source/`.

## 9. Seed backlog (epics derived from the reference config)

Documented in `STATUS.md`; created on the tracker later by the Epic Author (human-approved). Ordered by dependency.

**MVP core**
0. **Architecture & Code Standards** — ADR-0001 (IR modeling), ADR-0002 (unified `inet` dual-stack), module layout, error handling.
1. **Project & CLI scaffolding** — package/CLI entrypoint; `params` + `?if/?FORMAT/?SECTION` preprocessor.
2. **Config-parsing framework + family-aware IR model.**
3. **Zones & interfaces + base nft skeleton** — `inet` tables/base-chains, stateful base, loopback, basic + family-appropriate interface options.
4. **Policy** — inter-zone default policies + logging.
5. **Basic rules engine** — `ACCEPT/DROP/REJECT`, proto/ports/ranges, `zone:host`, `?SECTION`s, `icmp`/`ipv6-icmp`.
6. **DNAT / port-forwarding (v4) + v6 direct-accept equivalent.**
7. **SNAT / `MASQUERADE` (v4).**
8. **Test harness** — golden-file infra + netns integration tier.
9. **CI/CD** — Actions: `ruff`/`mypy`/`pytest` + privileged netns job.

**Backlog (post-MVP)**
- Macros & custom actions (`Ping`, `Invalid`, `AwsDrop`) · conntrack helpers · mangle/`TPROXY`/`DIVERT` · providers/policy-routing · QoS/traffic-shaping · advanced interface hardening · Shorewall-corpus comparison spike · import original source into `orig_source/`.

## 10. Deferred to ADR / open

- **ADR-0001:** dataclasses vs pydantic for the IR.
- **ADR-0002:** confirm unified `inet` details (how a rule scopes to a family; zone typing across families).
- Exact CLI command name/verbs (`compile`/`check`/`start`…) — decided in epic #1.
- Minimum Python floor confirmation (3.11 proposed) — epic #0.

## 11. Glossary

- **Epic** — a high-level feature (e.g. "SNAT support"); `type:epic`.
- **Task** — an implementation-ready unit of work under an epic; `type:task`.
- **Refinement** — the upstream grooming phase (epic → decompose → groom).
- **Delivery** — the standard GitHub flow (implement → review → merge).
- **IR** — the nftables-agnostic in-memory model between Parser and Generator.
- **The factory** — the AI pipeline that builds the product.
