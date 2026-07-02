# Package / module layout

Where each stage of the compiler pipeline lives under `src/shorewallnf/`. This is the map an
implementer follows so code lands in the right module. It refines [ARCHITECTURE.md](ARCHITECTURE.md)
(the stages) with the coding structure from [ADR-0003](adr/0003-design-approach.md) (functional
core / imperative shell), the IR from [ADR-0001](adr/0001-ir-modeling.md), and the error model
from ADR-0004 (error-handling conventions, task #11).

```
config dir ─► Reader ─► Preprocessor ─► Parser ─► IR ─► Validator ─► Generator ─► Applier
             └──────── shell ────────┘  └──────────── pure core ───────────┘  └── shell ──┘
```

## Stage → module

| Stage | Module | Layer | Status |
|-------|--------|-------|--------|
| Reader | `shorewallnf/reader.py` | shell (reads the config dir) | planned |
| Preprocessor | `shorewallnf/preprocessor.py` | core (pure: text → text) | planned |
| Parser | `shorewallnf/parser.py` | core (pure: text → IR) | planned |
| IR / model | `shorewallnf/ir.py` | core (immutable data) | **present** |
| Validator | `shorewallnf/validator.py` | core (pure: IR → IR, or raises) | **present** (semantic checks; e.g. the ESTABLISHED/RELATED base-accept shadow, [ADR-0005](adr/0005-nftables-base-chain-layout.md)) |
| Generator | `shorewallnf/generator.py` | core (pure: IR → nftables JSON) | **present** (base skeleton [ADR-0005](adr/0005-nftables-base-chain-layout.md); inter-zone policy rules [ADR-0006](adr/0006-inter-zone-policy-compilation.md); per-connection rules [ADR-0007](adr/0007-rules-compilation.md); IPv4 DNAT nat compilation [ADR-0008](adr/0008-nat-compilation.md); IPv4 SNAT/MASQUERADE postrouting [ADR-0009](adr/0009-snat-compilation.md)) |
| Applier | `shorewallnf/applier.py` | shell (runs `nft -c`, then applies) | planned |

Cross-cutting:

| Concern | Module | Status |
|---------|--------|--------|
| CLI entrypoint | `shorewallnf/cli.py` | planned |
| Error types | `shorewallnf/errors.py` | planned |

## Boundaries (why this split)

- **Functional core, imperative shell** ([ADR-0003](adr/0003-design-approach.md)). The core —
  Preprocessor → Parser → IR → Validator → Generator — is pure functions over immutable data:
  no I/O, no globals. All side effects live in the shell: `reader.py` (reads files),
  `applier.py` (invokes `nft`), and `cli.py` (argument parsing, exit). This is what makes the
  parser and generator golden-file-testable in isolation.
- **`cli.py` is the one catch point** (ADR-0004, error-handling). The core raises
  `ShorewallNFError`; `cli.py` catches it once → clean stderr message + non-zero exit. Its
  `main` is wired as the `shorewallnf` entry point in `pyproject.toml` (added by the
  CLI-scaffolding epic, #4).
- **`ir.py` is nftables-agnostic data** ([ADR-0001](adr/0001-ir-modeling.md)): frozen
  dataclasses, family-aware. Only the Generator knows nftables.

## Dispatch and growth (YAGNI)

`parser.py` and `generator.py` start as **single modules**, each holding a dispatch registry
(a dict keyed by file/rule kind, per [ADR-0003](adr/0003-design-approach.md)) rather than an
inheritance tree. Split a module into a package (`parser/`, `generator/`) only when the number
of per-file parsers or per-rule generators makes one file unwieldy — not before. New stages get
a new module here and a row in the table above.
