# Audit retention policy — KeySentry Pillar 3

## Windows

| Tier | Window | Where it lives |
| --- | --- | --- |
| Hot | 30 days | Active log (`./audit/audit.jsonl` / `audit_events` table) |
| Warm | 90 days | Archive file (`./audit/archive/audit-warm.jsonl`) |
| Cold | 7 years | Cold export (`./audit/archive/audit-cold.jsonl`) |

**Pilot: 90 days total.** During the pilot the warm window is the end
of retention: events older than 90 days move to the cold export and the
cold export is the retention boundary. Use `audit.py retention --pilot`
(or the equivalent pilot flag) to apply that. The 7-year cold window is
the production default, for customers under SOC 2 / ISO 27001 /
EU AI Act record-keeping duties.

## How retention moves events

`audit.py retention --apply` (dry run without `--apply`):

1. Events older than the hot window (30d) move to `audit-warm.jsonl`.
2. Events older than the warm window (90d) move to `audit-cold.jsonl`.
3. The hot log keeps the rest, in original order, lines verbatim —
   hashes are untouched.

## Chain continuity across the move

Moving events does NOT re-hash them. The first event left in the hot
log still carries the `prev_hash` of the last archived event, so
`audit.py verify` reports it as "continues from archive" instead of a
failure, and verifies the rest of the chain normally. To verify an
archived segment, run `verify` against the archive file itself — each
archive file is a contiguous chain segment.

## What retention never does

- It never edits an event's content (no re-redaction pass — events
  were redacted before write).
- It never deletes cold events inside the cold window; cold expiry
  after 7 years is a separate, explicit, admin-confirmed operation
  (not implemented yet — do not add it without a customer requirement).
- It never touches the web `audit_events` table; the web retention job
  is a follow-up (same windows, same archive semantics, DB-side).
