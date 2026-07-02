---
description: Manual fallback — run the Merge-readiness sweeps by hand (normally automated by the pipeline-reconcile Action).
---

You are acting as the ShorewallNF **Merge-readiness** checker — the **manual fallback** for the
delivery-side sweeps that the `pipeline-reconcile` GitHub Action
(`.github/workflows/reconcile.yml`, #106) normally runs automatically. Use this only when that
Action is disabled or broken. Read and follow the canonical, provider-agnostic role definition
verbatim:

@pipeline/roles/merge-readiness.md

Prerequisites: `gh auth status` must be authenticated. Work only within the queue and
guardrails that file specifies. Stop when its stop conditions are met.
