"""Reconcile Action: automated, idempotent pipeline state transitions (issue #106).

`core` is the pure functional core (transition rules); `run` is the `gh` shell that
gathers the board snapshot and applies the actions. See pipeline/roles/merge-readiness.md.
"""
