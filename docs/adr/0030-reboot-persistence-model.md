# ADR-0030: reboot-persistence model — on-disk state and save-on-apply

- **Status:** Accepted
- **Date:** 2026-07-02

## Context

An applied ruleset lives only in kernel memory (ADR-0010): a reboot wipes it and the host comes
up with no ShorewallNF firewall — "a firewall that vanishes on reboot is not a firewall"
(epic #202). To survive a reboot the effective ruleset must be persisted to disk and restored at
boot before the network is up. This ADR fixes the persistence model those two halves share: where
state lives on disk, when it is written, and the boot-time restore lifecycle.

Task #205 delivers the **save** half — persist the exact applied nftables JSON. The restore unit
is separate follow-up work in the same epic; this ADR records its intended shape so the save half
is designed against a known contract.

Forces:

- **Round-trip fidelity.** What is saved must be exactly what re-applies: the saved artifact is the
  same JSON object handed to `apply_ruleset` — the generated ruleset *before* the atomic-load
  prelude wrapping (ADR-0010), which is a load-time detail, not part of the persisted state. Restore
  re-derives the prelude by running the saved ruleset back through the applier.
- **Crash-safe write.** A reboot or crash mid-save must never leave a truncated file that a
  boot-time restore would then load. The published file is always complete or absent.
- **Confidential state.** A ruleset can encode network topology; the file must not be world-readable.
- **Fail-closed (ADR-0004).** A save failure must surface as a clear error, and a boot restore of a
  corrupt/rejected ruleset must abort loudly rather than leave an empty (wide-open) ruleset.

## Decision

1. **State location.** The effective ruleset is stored at a single stable path,
   `/var/lib/shorewallnf/ruleset.json` (`applier.DEFAULT_RULESET_PATH`) — `/var/lib` is the FHS
   home for persistent application state. It holds the generated nftables JSON verbatim.
2. **Save-on-apply default.** A successful `apply` persists the exact ruleset it loaded, right after
   the live load succeeds. This is the documented default and the epic's only auto-save policy — no
   broader "save on every mutation" behaviour (YAGNI). Save runs *after* apply, so a rejected load
   never overwrites a good saved ruleset.
3. **Atomic, owner-only write.** `applier.save_ruleset` serialises to a temp file in the target
   directory (created `0o600`), `fsync`s it, then `os.replace`s it onto the stable path — an atomic
   rename on the same filesystem. A reader sees either the old file or the new one, never a partial;
   a failed write unlinks the temp and leaves any prior copy intact.
4. **Failure is loud.** Any I/O error is wrapped as `ShorewallNFError`, caught once in the CLI shell
   (ADR-0004); the save never passes silently.
5. **Restore-at-boot lifecycle (follow-up).** A systemd unit ordered before `network-pre.target`
   (`Wants=/Before=`) loads the saved JSON through the applier before interfaces come up, so there
   is no unprotected window. It is fail-closed: if the saved file is missing, unreadable, or rejected
   by nft, the unit fails loudly and does not leave an empty ruleset. That unit is separate work in
   epic #202; this ADR fixes the contract it consumes (path, format, round-trip guarantee).

## Consequences

- **Easier:** the applied firewall now has a durable, machine-readable record at one known path,
  and the round-trip guarantee means restore is just "re-apply the saved JSON" — no separate restore
  format or parser.
- **Trade-off:** save-on-apply couples persistence to the `apply` verb. A future `--no-save` flag or
  a standalone `save` verb can be added when a real need arrives; until then apply always persists.
- **Follow-up:** the boot-time restore unit and its fail-closed ordering test (epic #202).

## Alternatives considered

- **Persist the atomic-load payload (with the create/delete prelude)** instead of the bare ruleset —
  couples the on-disk format to a load-time transaction detail and does not round-trip to "the
  ruleset that was applied". Rejected; save the generated ruleset, re-derive the prelude on restore.
- **`nft list ruleset` text dump** (Shorewall/`nftables.service` style) — a text format that must be
  re-parsed and cannot round-trip to our JSON IR, and would capture co-resident tables we do not own.
  Rejected in favour of persisting our own generated JSON.
- **Write in place (open + truncate + write)** — a crash mid-write leaves a truncated file the boot
  restore would load. The temp-then-rename is what makes the publish atomic. Rejected.
- **Save on every apply *and* a periodic autosave** — speculative; the epic scopes auto-save to the
  apply default only. Rejected (YAGNI).
