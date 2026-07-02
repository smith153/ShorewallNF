# ShorewallNF Foundation & Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lay down the ShorewallNF repository foundation and the provider-agnostic AI development pipeline ("the factory"), with no compiler logic.

**Architecture:** A Python package skeleton (`src/shorewallnf`) governed by `ruff`/`mypy`/`pytest`; a set of canonical, provider-agnostic pipeline **role prompts** under `pipeline/roles/` with a thin Claude Code adapter under `.claude/`; GitHub coordination via labels + issue/PR templates + CODEOWNERS + a CI skeleton; and top-level docs (README, CLAUDE.md, STATUS.md, ARCHITECTURE, CONTRIBUTING, ADR stubs) that make project state legible to agents.

**Tech Stack:** Python ≥3.11, `ruff`, `mypy`, `pytest`, GitHub Actions, `gh` CLI, GitHub issue-forms YAML, Bash.

## Global Constraints

- **License:** GPLv2 (`LICENSE` = full GPL-2.0 text; SPDX id `GPL-2.0-only`). Copied verbatim from spec §4/D8.
- **Language floor:** Python **3.11** minimum (`requires-python = ">=3.11"`).
- **Runtime deps:** minimal — stdlib only for now; `python3-nftables` is a *system* package, not a PyPI dep. Dev deps: `ruff`, `mypy`, `pytest`.
- **No compiler logic this session** — `src/shorewallnf` is a stub package only.
- **Canonical role prompts are provider-agnostic** (`pipeline/roles/*.md`); `.claude/` only *references* them.
- **Ignored dirs:** `my_shorewall/` and `orig_source/` must be git-ignored.
- **Autonomy gates:** humans approve epics and merges; the AI Code Reviewer's approval must NOT satisfy branch protection (enforced via CODEOWNERS).
- **Commit style:** Conventional Commits (`feat:`, `docs:`, `chore:`, `ci:`). Every commit message ends with the Co-Authored-By trailer used by this repo.
- **Branch:** all work lands on a `foundation` branch → single PR (never commit to `master`).

---

## Execution note: worktree & the design spec

This plan is executed in an isolated worktree/branch `foundation` created via `superpowers:using-git-worktrees`. The design spec `docs/superpowers/specs/2026-06-30-shorewallnf-foundation-design.md` was authored during brainstorming in the main workspace; ensure it is present in the worktree (copy it in) and commit it as part of **Task 1** so the PR is self-contained.

---

## Task 1: Repository meta (gitignore, license, editorconfig, spec)

**Files:**
- Create: `.gitignore`
- Create: `LICENSE`
- Create: `.editorconfig`
- Ensure present + commit: `docs/superpowers/specs/2026-06-30-shorewallnf-foundation-design.md`

**Interfaces:**
- Consumes: nothing.
- Produces: an ignored `my_shorewall/` and `orig_source/`; the committed design spec.

- [ ] **Step 1: Write `.gitignore`**

```gitignore
# User/private inputs — never commit
my_shorewall/
orig_source/

# Python
__pycache__/
*.py[cod]
.venv/
venv/
*.egg-info/
build/
dist/
.mypy_cache/
.ruff_cache/
.pytest_cache/
.coverage
htmlcov/

# Editors / OS
.DS_Store
*.swp
```

- [ ] **Step 2: Create `LICENSE`**

Write the full, verbatim **GNU General Public License version 2** text (the canonical `https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt`). Do not summarize or truncate.

- [ ] **Step 3: Create `.editorconfig`**

```ini
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space
indent_size = 4

[*.{md,yml,yaml}]
indent_size = 2

[*.md]
trim_trailing_whitespace = false
```

- [ ] **Step 4: Verify the ignores work**

Run: `git check-ignore my_shorewall/ orig_source/`
Expected: both paths printed (they are ignored). Then `git status --porcelain` must NOT list any `my_shorewall/` path.

- [ ] **Step 5: Ensure the design spec is present**

Run: `test -f docs/superpowers/specs/2026-06-30-shorewallnf-foundation-design.md && echo OK`
Expected: `OK`. If missing, copy it from the main workspace.

- [ ] **Step 6: Commit**

```bash
git add .gitignore LICENSE .editorconfig docs/superpowers/specs/2026-06-30-shorewallnf-foundation-design.md
git commit -m "chore: repo meta (gitignore, GPLv2 license, editorconfig) + design spec"
```

---

## Task 2: Python packaging, package stub & tooling

**Files:**
- Create: `pyproject.toml`
- Create: `src/shorewallnf/__init__.py`
- Create: `tests/__init__.py`
- Test: `tests/test_smoke.py`

**Interfaces:**
- Consumes: nothing.
- Produces: importable package `shorewallnf` with `__version__: str`; a passing `pytest`/`ruff`/`mypy` baseline that CI (Task 3) invokes.

- [ ] **Step 1: Write the failing smoke test**

```python
# tests/test_smoke.py
import shorewallnf


def test_package_exposes_version() -> None:
    assert isinstance(shorewallnf.__version__, str)
    assert shorewallnf.__version__
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python -m pytest tests/test_smoke.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'shorewallnf'`.

- [ ] **Step 3: Create the package stub**

```python
# src/shorewallnf/__init__.py
"""ShorewallNF — an nftables-native reimplementation of Shorewall.

This is a package stub. Compiler components (reader, parser, IR, generator,
applier) are delivered by the development pipeline, not this scaffolding.
"""

__version__ = "0.0.0"
```

Also create empty `tests/__init__.py`.

- [ ] **Step 4: Write `pyproject.toml`**

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "shorewallnf"
version = "0.0.0"
description = "An nftables-native reimplementation of Shorewall, written in Python."
readme = "README.md"
requires-python = ">=3.11"
license = { text = "GPL-2.0-only" }
authors = [{ name = "ShorewallNF contributors" }]
dependencies = []

[project.optional-dependencies]
dev = ["ruff>=0.5", "mypy>=1.10", "pytest>=8"]

[tool.setuptools.packages.find]
where = ["src"]

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B"]

[tool.mypy]
python_version = "3.11"
strict = true
files = ["src", "tests"]

[tool.pytest.ini_options]
addopts = "-ra"
testpaths = ["tests"]
pythonpath = ["src"]
```

- [ ] **Step 5: Run the full baseline and verify it passes**

Run: `python -m pytest -v && python -m ruff check . && python -m mypy`
Expected: pytest PASS, ruff "All checks passed!", mypy "Success: no issues found". (Install dev deps first if needed: `python -m pip install -e ".[dev]"`.)

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml src/shorewallnf/__init__.py tests/__init__.py tests/test_smoke.py
git commit -m "feat: python package skeleton with ruff/mypy/pytest baseline"
```

---

## Task 3: CI skeleton (GitHub Actions)

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the `pyproject.toml` dev extras and `pytest`/`ruff`/`mypy` from Task 2.
- Produces: a `lint-type-test` job on every PR; a placeholder `netns-integration` job (documented, not yet wired to real tests).

- [ ] **Step 1: Write `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  pull_request:
  push:
    branches: [master]

jobs:
  lint-type-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: python -m pip install -e ".[dev]"
      - run: python -m ruff check .
      - run: python -m mypy
      - run: python -m pytest -v

  # Behavioral (network-namespace) tier — enabled once the test-harness epic
  # lands golden configs + netns assertions. Requires CAP_NET_ADMIN.
  netns-integration:
    runs-on: ubuntu-latest
    if: false # TODO(epic:test-harness): flip on when netns tests exist
    steps:
      - uses: actions/checkout@v4
      - run: echo "netns integration placeholder"
```

- [ ] **Step 2: Verify the YAML parses**

Run: `python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('ok')"`
Expected: `ok`. (If `actionlint` is available, also run `actionlint .github/workflows/ci.yml`.)

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: lint/type/test workflow with placeholder netns job"
```

---

## Task 4: Label taxonomy (machine + human) & sync script

**Files:**
- Create: `.github/labels.yml`
- Create: `pipeline/labels.md`
- Create: `scripts/sync-labels`

**Interfaces:**
- Consumes: nothing.
- Produces: the canonical label set consumed by issue/PR templates (Task 5), role prompts (Tasks 7–8), and the workflow doc (Task 6). `scripts/sync-labels` reads `.github/labels.yml`.

- [ ] **Step 1: Write `.github/labels.yml`** (each entry: `name`, `color`, `description`)

```yaml
# Canonical ShorewallNF labels. Apply with scripts/sync-labels.
# type:*
- { name: "type:epic",         color: "5319e7", description: "High-level feature; parent of tasks" }
- { name: "type:task",         color: "1d76db", description: "Implementation-ready unit of work" }
- { name: "type:bug",          color: "d73a4a", description: "Defect in existing behavior" }
- { name: "type:spike",        color: "c5def5", description: "Time-boxed research/investigation" }
- { name: "type:docs",         color: "0075ca", description: "Documentation change" }
- { name: "type:ci",           color: "bfd4f2", description: "CI/build/tooling change" }
- { name: "type:architecture", color: "6f42c1", description: "Architecture decision / ADR" }
# status:*
- { name: "status:proposed",             color: "ededed", description: "Awaiting refinement/approval" }
- { name: "status:needs-refinement",     color: "fbca04", description: "Groomer requested changes" }
- { name: "status:implementation-ready", color: "0e8a16", description: "Groomed; ready to implement" }
- { name: "status:in-progress",          color: "fef2c0", description: "Claimed by an implementer" }
- { name: "status:blocked",              color: "b60205", description: "Has unmet dependencies" }
- { name: "status:in-review",            color: "d4c5f9", description: "Has an open PR under review" }
- { name: "status:ready-to-merge",       color: "0e8a16", description: "Approved + green; awaiting human merge" }
# area:*
- { name: "area:parser",       color: "c2e0c6", description: "Config parsing" }
- { name: "area:generator",    color: "c2e0c6", description: "nftables generation" }
- { name: "area:cli",          color: "c2e0c6", description: "CLI / entrypoint" }
- { name: "area:ir",           color: "c2e0c6", description: "Intermediate representation / model" }
- { name: "area:zones",        color: "c2e0c6", description: "Zones" }
- { name: "area:interfaces",   color: "c2e0c6", description: "Interfaces" }
- { name: "area:policy",       color: "c2e0c6", description: "Policy" }
- { name: "area:rules",        color: "c2e0c6", description: "Rules" }
- { name: "area:nat",          color: "c2e0c6", description: "DNAT/SNAT" }
- { name: "area:preprocessor", color: "c2e0c6", description: "params / ?if / ?FORMAT / ?SECTION" }
- { name: "area:testing",      color: "c2e0c6", description: "Test harness" }
- { name: "area:ci",           color: "c2e0c6", description: "CI/CD" }
# meta
- { name: "good-first-issue",  color: "7057ff", description: "Good entry point for new contributors" }
- { name: "needs-human",       color: "e99695", description: "Escalated: requires a human decision" }
- { name: "blocked-external",  color: "b60205", description: "Blocked on something outside the repo" }
```

- [ ] **Step 2: Write `pipeline/labels.md`** — a human-readable table mirroring `labels.yml` exactly (columns: Label, Purpose, Applied by). Group by `type:` / `status:` / `area:` / `meta`. State at top: "Source of truth is `.github/labels.yml`; keep this table in sync."

- [ ] **Step 3: Write `scripts/sync-labels`** (idempotent create-or-update via `gh`)

```bash
#!/usr/bin/env bash
# Create/update GitHub labels from .github/labels.yml. Requires: gh, python3.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY' | while IFS=$'\t' read -r name color desc; do
import yaml
for l in yaml.safe_load(open(".github/labels.yml")):
    print(f"{l['name']}\t{l['color']}\t{l['description']}")
PY
  if gh label create "$name" --color "$color" --description "$desc" 2>/dev/null; then
    echo "created: $name"
  else
    gh label edit "$name" --color "$color" --description "$desc" >/dev/null
    echo "updated: $name"
  fi
done
```

- [ ] **Step 4: Verify**

Run: `python -c "import yaml; print(len(yaml.safe_load(open('.github/labels.yml'))), 'labels')"` (expect the count > 0 and no exception), then `bash -n scripts/sync-labels` (expect no output = valid syntax), then `chmod +x scripts/sync-labels`.

- [ ] **Step 5: Commit**

```bash
git add .github/labels.yml pipeline/labels.md scripts/sync-labels
git commit -m "feat: canonical label taxonomy + gh sync script"
```

---

## Task 5: GitHub issue/PR templates & CODEOWNERS

**Files:**
- Create: `.github/ISSUE_TEMPLATE/epic.yml`
- Create: `.github/ISSUE_TEMPLATE/task.yml`
- Create: `.github/pull_request_template.md`
- Create: `.github/CODEOWNERS`

**Interfaces:**
- Consumes: label names from Task 4.
- Produces: structured epic/task creation forms the Epic Author/Decomposer target; a PR template the Implementer fills; CODEOWNERS enforcing human merge approval.

- [ ] **Step 1: Write `.github/ISSUE_TEMPLATE/epic.yml`** (GitHub issue form)

```yaml
name: Epic
description: A high-level feature (e.g. "SNAT support"). Created by the Epic Author; approved by a human.
labels: ["type:epic", "status:proposed"]
body:
  - type: textarea
    id: summary
    attributes: { label: Summary, description: What capability and why (altitude ~ "SNAT support"). }
    validations: { required: true }
  - type: textarea
    id: scope
    attributes: { label: In scope / Out of scope }
    validations: { required: true }
  - type: textarea
    id: acceptance
    attributes: { label: Acceptance criteria, description: Observable outcomes that mean this epic is done. }
    validations: { required: true }
  - type: textarea
    id: refs
    attributes: { label: References, description: Relevant docs, ADRs, and prior issues. Do not paste private reference-config contents. }
```

- [ ] **Step 2: Write `.github/ISSUE_TEMPLATE/task.yml`**

```yaml
name: Task
description: An implementation-ready unit of work under an epic. Created by the Decomposer; groomed before implementation.
labels: ["type:task", "status:proposed"]
body:
  - type: input
    id: epic
    attributes: { label: Parent epic, description: "Issue number, e.g. #12" }
    validations: { required: true }
  - type: textarea
    id: goal
    attributes: { label: Goal, description: One-sentence deliverable. }
    validations: { required: true }
  - type: textarea
    id: acceptance
    attributes: { label: Acceptance criteria, description: Testable conditions (given/when/then where possible). }
    validations: { required: true }
  - type: textarea
    id: deps
    attributes: { label: Dependencies, description: "blocked-by #NN, if any." }
```

- [ ] **Step 3: Write `.github/pull_request_template.md`**

```markdown
## What & why
<!-- Link the task: "Closes #NN" -->
Closes #

## How it was tested
<!-- Golden-file/unit tests added; `nft -c` clean; netns assertions if applicable -->

## Checklist
- [ ] `ruff`, `mypy`, `pytest` pass locally
- [ ] Tests added/updated (TDD)
- [ ] Docs/STATUS.md updated if behavior or scope changed
- [ ] Follows the IR-pipeline architecture (docs/ARCHITECTURE.md)
```

- [ ] **Step 4: Write `.github/CODEOWNERS`**

```
# Merges to master require review from a human maintainer.
# The AI Code Reviewer's approval alone must NOT satisfy branch protection.
# Replace @ShorewallNF/maintainers with the real team/handle before enabling protection.
*       @ShorewallNF/maintainers
```

- [ ] **Step 5: Verify the issue forms parse**

Run: `python -c "import yaml; [yaml.safe_load(open(f)) for f in ['.github/ISSUE_TEMPLATE/epic.yml','.github/ISSUE_TEMPLATE/task.yml']]; print('ok')"`
Expected: `ok`.

- [ ] **Step 6: Commit**

```bash
git add .github/ISSUE_TEMPLATE/epic.yml .github/ISSUE_TEMPLATE/task.yml .github/pull_request_template.md .github/CODEOWNERS
git commit -m "feat: issue/PR templates + CODEOWNERS (human merge gate)"
```

---

## Task 6: Pipeline overview & workflow docs

**Files:**
- Create: `pipeline/README.md`
- Create: `pipeline/workflow.md`

**Interfaces:**
- Consumes: labels (Task 4).
- Produces: the shared vocabulary + lifecycle referenced by every role prompt (Tasks 7–8) and by CONTRIBUTING (Task 10).

- [ ] **Step 1: Write `pipeline/workflow.md`** — must contain, concretely:
  - The two phases (Refinement, Delivery) and the 7 roles (one-line each).
  - The full lifecycle diagram (copy the ASCII from spec §6.3).
  - **State transition table**: for each `status:*` label — who applies it, what it means, what moves it next.
  - **Collision avoidance** rule verbatim: claim = self-assign **and** add `status:in-progress`; only pick tasks that are unassigned + `status:implementation-ready` + not `status:blocked`.
  - **Human gates:** (a) approve `type:epic status:proposed`; (b) merge to `master`.
  - **Escalation:** Groomer max 2 churn rounds → `needs-human`.

- [ ] **Step 2: Write `pipeline/README.md`** — must contain:
  - One-paragraph "what the factory is."
  - **"Volunteer a session"** quickstart: prerequisites (`gh auth login`, any AI runtime), how to pick a role for the night, and a pointer to `pipeline/roles/`.
  - A table of the 7 roles → their prompt file → the queue each reads (the `gh` filter).
  - A note that `pipeline/roles/*.md` are canonical/provider-agnostic and `.claude/` is a convenience wrapper.

- [ ] **Step 3: Verify internal links resolve**

Run: `grep -oE '\]\(([^)]+\.md)\)' pipeline/README.md pipeline/workflow.md` and confirm each referenced path exists (roles files may not exist yet — note them; they arrive in Tasks 7–8).

- [ ] **Step 4: Commit**

```bash
git add pipeline/README.md pipeline/workflow.md
git commit -m "docs: pipeline overview + lifecycle/workflow"
```

---

## Task 7: Refinement role prompts

**Files:**
- Create: `pipeline/roles/epic-author.md`
- Create: `pipeline/roles/epic-decomposer.md`
- Create: `pipeline/roles/task-groomer.md`

**Interfaces:**
- Consumes: labels (Task 4), workflow (Task 6), templates (Task 5).
- Produces: three canonical role prompts. Each role prompt MUST use this shared structure (sections): `# Role: <name>` · **Mission** (1–2 sentences) · **Inputs / what to read** · **Queue (exact `gh` command)** · **Procedure (numbered)** · **Outputs (exact labels/state changes + `gh` commands)** · **Guardrails** · **Stop conditions**.

- [ ] **Step 1: Write `pipeline/roles/epic-author.md`** with, concretely:
  - **Mission:** survey project state and propose the next epics (altitude ≈ "SNAT support"), not too abstract, not too granular.
  - **Inputs:** `STATUS.md`, `docs/ARCHITECTURE.md`, `docs/adr/`, existing open epics, and (if present) the reference config.
  - **Queue:** `gh issue list --label type:epic --state open` (to avoid duplicates).
  - **Procedure:** identify gaps vs the seed backlog in `STATUS.md`; for each proposed epic, draft summary/scope/acceptance/refs.
  - **Outputs:** create issues via the epic form → they land as `type:epic status:proposed`; do NOT decompose (human approves first). Example: `gh issue create --label type:epic,status:proposed --title "..." --body "..."`.
  - **Guardrails:** one capability per epic; never auto-approve; cap at N proposals per run (default 5).
  - **Stop conditions:** no gaps found, or N reached.

- [ ] **Step 2: Write `pipeline/roles/epic-decomposer.md`** with:
  - **Mission:** turn ONE human-approved epic into ordered, testable tasks.
  - **Inputs:** the epic issue body; `docs/ARCHITECTURE.md`.
  - **Queue:** approved epics = `gh issue list --label type:epic --state open` filtered to those NOT `status:proposed` (i.e. human-approved). Document that "human approval" = removal of `status:proposed` / addition of `status:implementation-ready` on the epic (state the exact convention and keep it consistent with workflow.md).
  - **Procedure:** derive tasks with acceptance criteria; set `blocked-by` ordering; link as sub-issues of the epic.
  - **Outputs:** `gh issue create` per task with `type:task,status:proposed`; add `blocked-by` references in the body; comment on the epic linking children.
  - **Guardrails:** every task independently testable; YAGNI — no speculative tasks; respect the dependency chain from ARCHITECTURE (parser before generator, etc.).
  - **Stop conditions:** epic fully covered by proposed tasks.

- [ ] **Step 3: Write `pipeline/roles/task-groomer.md`** with:
  - **Mission:** gate `status:proposed` tasks to `status:implementation-ready`.
  - **Queue:** `gh issue list --label type:task,status:proposed --state open`.
  - **Procedure / checklist:** necessity (YAGNI), correct altitude, no duplication, real/testable acceptance criteria, dependency correctness.
  - **Outputs (three-way):** approve → swap `status:proposed`→`status:implementation-ready`; request-changes → `status:needs-refinement` + a comment checklist; reject → close with reason. Show the exact `gh issue edit --add-label/--remove-label` and `gh issue comment` commands.
  - **Guardrails:** **max 2 churn rounds** (count comments/labels), then add `needs-human` and stop.
  - **Stop conditions:** queue empty.

- [ ] **Step 4: Verify structure**

Run: `for f in pipeline/roles/epic-author.md pipeline/roles/epic-decomposer.md pipeline/roles/task-groomer.md; do echo "== $f"; grep -E '^(# Role|## (Mission|Inputs|Queue|Procedure|Outputs|Guardrails|Stop))' "$f" || echo MISSING; done`
Expected: each file shows the required section headers; none print MISSING.

- [ ] **Step 5: Commit**

```bash
git add pipeline/roles/epic-author.md pipeline/roles/epic-decomposer.md pipeline/roles/task-groomer.md
git commit -m "docs: refinement-phase role prompts (epic author, decomposer, groomer)"
```

---

## Task 8: Delivery role prompts

**Files:**
- Create: `pipeline/roles/implementer.md`
- Create: `pipeline/roles/code-reviewer.md`
- Create: `pipeline/roles/fixer.md`
- Create: `pipeline/roles/merge-readiness.md`

**Interfaces:**
- Consumes: labels (Task 4), workflow (Task 6), PR template (Task 5), architecture (Task 10 defines it, but reference the path).
- Produces: four role prompts using the SAME shared structure as Task 7.

- [ ] **Step 1: Write `pipeline/roles/implementer.md`** with:
  - **Mission:** implement ONE unblocked `status:implementation-ready` task via TDD and open a PR.
  - **Queue:** `gh issue list --label type:task,status:implementation-ready --state open --search "no:assignee -label:status:blocked"`.
  - **Procedure:** claim (self-assign + add `status:in-progress`) → create a git worktree/branch → TDD (failing test → minimal code → pass) → keep changes on the IR-pipeline architecture → open PR with `Closes #NN`.
  - **Outputs:** `gh issue edit #NN --add-assignee @me --add-label status:in-progress`; branch `task/NN-slug`; `gh pr create --fill --body "Closes #NN"`; add `status:in-review` to the issue.
  - **Guardrails:** one task per PR; never touch `master`; tests required; respect Global Constraints.
  - **Stop conditions:** PR opened, or no unblocked ready tasks.

- [ ] **Step 2: Write `pipeline/roles/code-reviewer.md`** with:
  - **Mission:** review open PRs for correctness, tests, architecture fit.
  - **Queue:** `gh pr list --state open --search "-review:approved"`.
  - **Procedure:** check CI status, diff, tests, ARCHITECTURE conformance; leave inline comments.
  - **Outputs:** `gh pr review --comment` or `--request-changes` (with specifics). **Never `--approve` as the merge-authorizing review** — state explicitly that a human's approval is what unlocks merge; the reviewer's job is to find issues and iterate with the Fixer.
  - **Guardrails:** cannot merge; cannot approve-to-merge.
  - **Stop conditions:** review queue empty.

- [ ] **Step 3: Write `pipeline/roles/fixer.md`** with:
  - **Mission:** address `--request-changes` feedback on a PR.
  - **Queue:** `gh pr list --state open --search "review:changes_requested"`.
  - **Procedure:** read review comments; reproduce; fix via TDD; push to the PR branch; reply to threads.
  - **Outputs:** commits on the PR branch; `gh pr comment` summarizing fixes; re-request review.
  - **Guardrails:** stay within the PR's scope; don't expand.
  - **Stop conditions:** requested changes addressed.

- [ ] **Step 4: Write `pipeline/roles/merge-readiness.md`** with:
  - **Mission:** surface PRs that are ready for a human to merge.
  - **Queue:** `gh pr list --state open`.
  - **Procedure:** verify green CI + rebased on `master` + no unresolved change requests; apply `status:ready-to-merge` to the linked issue.
  - **Outputs:** `gh issue edit #NN --add-label status:ready-to-merge`; `gh pr comment` noting readiness. **Does NOT merge** — a human clicks merge.
  - **Guardrails:** never merge; never bypass branch protection.
  - **Stop conditions:** no more mergeable PRs.

- [ ] **Step 5: Verify structure** (same check as Task 7, Step 4, over the four delivery files).

- [ ] **Step 6: Commit**

```bash
git add pipeline/roles/implementer.md pipeline/roles/code-reviewer.md pipeline/roles/fixer.md pipeline/roles/merge-readiness.md
git commit -m "docs: delivery-phase role prompts (implementer, reviewer, fixer, merge-readiness)"
```

---

## Task 9: Claude Code adapter

**Files:**
- Create: `.claude/commands/epic-author.md`, `epic-decomposer.md`, `task-groomer.md`, `implementer.md`, `code-reviewer.md`, `fixer.md`, `merge-readiness.md`
- Create: `.claude/agents/README.md`

**Interfaces:**
- Consumes: `pipeline/roles/*.md` (Tasks 7–8).
- Produces: 7 slash commands that each just load and follow the canonical role prompt.

- [ ] **Step 1: Write each `.claude/commands/<role>.md`** as a thin wrapper. Template (fill `<role>` and the matching filename):

```markdown
---
description: Run the ShorewallNF <role> pipeline role for one session.
---

You are acting as the ShorewallNF **<role>**. Read and follow the canonical,
provider-agnostic role definition verbatim:

@pipeline/roles/<role-file>.md

Prerequisites: `gh auth status` must be authenticated. Work only within the
queue and guardrails that file specifies. Stop when its stop conditions are met.
```

- [ ] **Step 2: Write `.claude/agents/README.md`** — explain that the canonical roles live in `pipeline/roles/`, the slash commands in `.claude/commands/` are the Claude Code entrypoints, and how a volunteer runs one (e.g. `/implementer`). Note that non-Claude runtimes read `pipeline/roles/*.md` directly.

- [ ] **Step 3: Verify each command references an existing role file**

Run: `for f in .claude/commands/*.md; do ref=$(grep -oE '@pipeline/roles/[a-z-]+\.md' "$f" | sed 's/@//'); test -f "$ref" && echo "$f -> ok" || echo "$f -> MISSING $ref"; done`
Expected: every line ends `-> ok`.

- [ ] **Step 4: Commit**

```bash
git add .claude/commands .claude/agents/README.md
git commit -m "feat: Claude Code adapter (slash commands wrapping canonical roles)"
```

---

## Task 10: Top-level docs (README, CLAUDE, STATUS, ARCHITECTURE, CONTRIBUTING, ADRs)

**Files:**
- Create: `README.md` (overwrite the empty tracked one)
- Create: `CLAUDE.md`
- Create: `STATUS.md`
- Create: `docs/ARCHITECTURE.md`
- Create: `docs/CONTRIBUTING.md`
- Create: `docs/adr/0000-template.md`
- Create: `docs/adr/0001-ir-modeling.md`
- Create: `docs/adr/0002-unified-inet-dual-stack.md`

**Interfaces:**
- Consumes: everything above (references pipeline, labels, architecture).
- Produces: the human/agent-facing entry docs and the ADR skeleton.

- [ ] **Step 1: Write `README.md`** — must contain: one-paragraph project pitch (nftables-native Shorewall reimplementation in Python, AI-driven); project status (pre-MVP scaffolding); the MVP goal (functionally-equivalent dual-stack routing + port-forwarding, behaviorally verified); a "How this project is built" section linking `pipeline/README.md`; a "Contributing / volunteer a session" pointer to `docs/CONTRIBUTING.md`; license (GPLv2); links to shorewall.org and the gitlab source.

- [ ] **Step 2: Write `CLAUDE.md`** — guidance for agents working IN the repo: the IR-pipeline architecture (link ARCHITECTURE.md); standards (Python ≥3.11, type hints, `ruff`/`mypy`/`pytest`, minimal deps); TDD expectation; commit style (Conventional Commits + Co-Authored-By trailer); "all work on a branch → PR, never `master`"; where project state lives (STATUS.md + tracker + docs); pointer to `pipeline/` for role work.

- [ ] **Step 3: Write `STATUS.md`** — the living snapshot the Epic Author reads first: current state (foundation only, no compiler yet); the **seed backlog** verbatim from spec §9 (MVP core epics 0–9 + post-MVP backlog); the MVP definition-of-done; a "how to update this file" note.

- [ ] **Step 4: Write `docs/ARCHITECTURE.md`** — the north star: the pipeline diagram (copy spec §5), each stage's responsibility, the family-aware IR + unified `inet` decision (link ADR-0002), the v4/v6 reconciliation table (copy spec §3.1), and the testing pyramid (copy spec §7).

- [ ] **Step 5: Write `docs/CONTRIBUTING.md`** — for humans and agents: how the two-phase pipeline works (link pipeline/workflow.md); how to volunteer a role session; the label taxonomy (link pipeline/labels.md); the human gates (epic approval, merge); dev setup (`pip install -e ".[dev]"`, run `ruff`/`mypy`/`pytest`); worktree+PR rule.

- [ ] **Step 6: Write the ADRs.**
  - `docs/adr/0000-template.md`: a standard ADR template (Context / Decision / Status / Consequences).
  - `docs/adr/0001-ir-modeling.md`: **Status: Proposed** — the open question dataclasses vs pydantic for the IR; list the trade-offs; decision deferred to the Architecture epic.
  - `docs/adr/0002-unified-inet-dual-stack.md`: **Status: Accepted** — record the unified `inet`, family-aware IR, dual-stack decision (rationale from spec §3.1/§4-D3).

- [ ] **Step 7: Verify links & presence**

Run: `for f in README.md CLAUDE.md STATUS.md docs/ARCHITECTURE.md docs/CONTRIBUTING.md docs/adr/0000-template.md docs/adr/0001-ir-modeling.md docs/adr/0002-unified-inet-dual-stack.md; do test -s "$f" && echo "$f ok" || echo "$f EMPTY"; done`
Expected: all `ok`. Then re-run the Task 6 link grep over README/CONTRIBUTING and confirm referenced `.md` paths now exist.

- [ ] **Step 8: Commit**

```bash
git add README.md CLAUDE.md STATUS.md docs/ARCHITECTURE.md docs/CONTRIBUTING.md docs/adr/
git commit -m "docs: top-level README/CLAUDE/STATUS + architecture, contributing, ADRs"
```

---

## Task 11: Final verification & open the PR

**Files:** none (integration check).

- [ ] **Step 1: Full local gate**

Run: `python -m ruff check . && python -m mypy && python -m pytest -v`
Expected: all pass.

- [ ] **Step 2: Confirm ignores still hold**

Run: `git status --porcelain` — expect a clean tree (no `my_shorewall/`/`orig_source/` entries, nothing uncommitted).

- [ ] **Step 3: Structural sanity**

Run: `test -d pipeline/roles && ls pipeline/roles | wc -l` (expect 7) and `ls .claude/commands | wc -l` (expect 7).

- [ ] **Step 4: Push and open the PR**

```bash
git push -u origin foundation
gh pr create --fill --title "Foundation & AI development pipeline" \
  --body "Implements docs/superpowers/specs/2026-06-30-shorewallnf-foundation-design.md. Scaffolding + factory only; no compiler logic."
```

Expected: PR created against `master`.

---

## Self-Review (completed by plan author)

**Spec coverage:** §2 deliverables → Tasks 1–10; §3/§3.1 MVP + v4/v6 → STATUS.md (T10.3) + ARCHITECTURE.md (T10.4); §4 decisions → recorded across CLAUDE/ARCHITECTURE/ADRs; §5 IR pipeline → ARCHITECTURE (T10.4); §6 factory (roles/labels/lifecycle) → Tasks 4,6,7,8; §7 testing/CI → CI (T3) + ARCHITECTURE (T10.4); §8 file tree → all tasks; §9 seed backlog → STATUS.md (T10.3); §10 ADRs → T10.6. No uncovered spec sections.

**Placeholder scan:** Config/code steps show exact content. Prose deliverables (docs, role prompts) specify exact required sections + the exact `gh` commands and label transitions — not vague "write docs" instructions. The only intentional `TODO` is the disabled `netns-integration` CI job, gated `if: false` and labelled for the test-harness epic.

**Type/name consistency:** label names, `status:*` transitions, the role→queue `gh` filters, and file paths are consistent across Tasks 4/6/7/8/9. Package name `shorewallnf`, `__version__` string used consistently in Task 2 and its test.
