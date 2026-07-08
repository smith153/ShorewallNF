# Security policy

ShorewallNF is a public project developed largely by AI agents through GitHub issues and pull
requests (see [`pipeline/README.md`](pipeline/README.md)). This document covers two things:
**how to report a vulnerability**, and **the CI/token controls that keep the project safe to
collaborate on in the open**. The second half doubles as the maintainer checklist — the controls
are mostly repository *settings* (owner-only, invisible in the tree), so they are recorded here
so they don't silently drift.

## Reporting a vulnerability

Please report security issues **privately**, not as a public issue or PR:

- Use GitHub's **"Report a vulnerability"** button under the repository **Security** tab (Private
  Vulnerability Reporting). This opens a private advisory visible only to maintainers.

Include what you found, how to reproduce it, and the impact. We aim to acknowledge within a few
days. Please give us a reasonable window to fix before any public disclosure. There is no bounty
— this is a volunteer project — but credit is gladly given.

## What a contributor's pull request can and cannot reach

The most important fact, and the reason opening a PR here is safe for everyone:

- Both workflows trigger on **`pull_request`** (never `pull_request_target`). For a PR from a
  **fork**, GitHub gives the CI run a **read-only `GITHUB_TOKEN`** and **no access to repository
  secrets**. So even though CI builds and tests your code, there is no write-scoped credential or
  secret in the job for that code to steal.
- **Fork-PR workflows require maintainer approval to run at all.** A maintainer reviews the diff
  before clicking "Approve and run," so untrusted code doesn't execute unattended.

If you are contributing: fork, open a PR, and expect a maintainer to approve your first CI run.
You never need — and will never be asked for — any secret or token.

## Maintainer controls (baseline — keep these in effect)

These are the settings that make the above true. A repository owner must apply and periodically
verify them; they are not enforced by anything in this repo.

1. **Require CI approval for all outside collaborators.**
   *Settings → Actions → General → "Fork pull request workflows from outside collaborators" →
   Require approval for all outside collaborators.* No fork PR runs a workflow until a maintainer
   approves it — not just first-time contributors.

2. **Default workflow token is read-only.**
   *Settings → Actions → General → Workflow permissions → "Read repository contents and packages
   permission."* Workflows request more only where they explicitly need it (e.g.
   `pipeline-reconcile` scopes `issues`/`pull-requests`/`contents: write`; `ci.yml` is
   `contents: read`).

3. **Protect `master` and restrict branch pushes.**
   A ruleset/branch protection on `master` requiring PR review before merge, and restricting who
   may push `task/*` branches. Direct pushes to the repo are the one path that yields a
   *write-scoped* token, so keep that path limited to trusted collaborators.

4. **Secrets for publishing/deploying go in a protected Environment — never a plain repo secret.**
   The project has **no** release/publish tokens today. When one is ever added (PyPI, a package
   registry, a deploy key), it MUST live in a GitHub **Environment** with a **required reviewer**
   and be restricted to `master`. That way a merged or approved PR still cannot reach the token
   without an explicit human approval on the deployment. This is the single most important rule
   for the day the project starts shipping artifacts.

5. **Pin Actions to a commit SHA.**
   Third-party (and first-party) Actions are referenced by full commit SHA, not a moving tag, so
   a hijacked/retargeted tag cannot silently inject code into CI. Keep them current (a
   `github-actions` Dependabot config can automate the bumps).

## The pipeline's trusted-author invariant

The reconcile pipeline includes a **batch test-merge gate** that merges promote-eligible PR
branches together and runs the test suite on the combined tree — i.e. it *executes* contributor
code, and on the scheduled run the job holds a write-scoped token. This is acceptable because of
a load-bearing invariant:

> **`status:review-passed` is gated to trusted authors.** External / non-collaborator PRs are
> not promoted under automated review alone, so untrusted contributor code never becomes a batch
> candidate and never runs in the write-token job.

Today this gate is a matter of pipeline convention. **If it is ever loosened** — e.g. external
PRs made mergeable under AI-only review — the batch gate must first be moved to token-less
execution (no write-scoped token in the process tree while contributor code runs). Do not relax
the trusted-author gate without that containment in place.
