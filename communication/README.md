# communication/

Written agreements between members. Chat is for pings only. Anything that changes what another member builds goes here.

## Files

| Name | Meaning | Edited by |
|---|---|---|
| `M<a>M<b>agreement.md` | Items between two members. Lower number first. | Author edits the items. Everyone appends replies. |
| `M<n>toAll.md` | What member n delivers, needs and promises. | Only member n. |

## Item format (exactly this)

```
### M1M4-01 | By H1
Ask: one sentence.
Why: one sentence.
Preference: ...
Fallback: ...
```

- ID is `<file prefix>-<two digits>`. IDs are never reused or renumbered.
- `By H<n>`: n is hours since kickoff (H0). One number per item.

## Reply format (exactly this)

Append one row per item to the Replies table at the bottom of the file.

`| ID | From | Hour | Status | Note |`

Status is one of:

| Status | Meaning |
|---|---|
| AGREED | Preference accepted as written. |
| CHANGED | Accepted with a change. Note states the change. |
| REJECTED | Not accepted. Note states why. |

An item without a row is OPEN.

## Rules

1. Do not edit another member's text. Reply by appending a row.
2. An item is settled when the replier from the other side writes AGREED or CHANGED. REJECTED is not settled.
3. After a REJECTED, the author edits the item to a new Preference and keeps the old row. The other side replies again.
4. Silence is not agreement. If an item is OPEN after its deadline, the author pings once in chat. If still OPEN at the next stand-up, it is decided there and the decision is written as a reply row by the author with the note `stand-up`.
5. When an item is settled, the author adds one line to `docs/DECISIONS.md`: a row in the existing table format `| <date> | <member> | <ID>: <final decision> |`.
6. `models.py` is frozen. Any change, including a new optional field, needs AGREED from all four members.
7. Never edit another member's code. Write an item instead.
8. Be concrete: name files, fields and values.
9. No secrets. Plain text. No em dashes. No emojis.

## Alignment round

1. Each member writes `M<n>toAll.md` using the template in `M4toAll.md`.
2. Each member replies in the other three files' Replies tables, one row per checklist line, with status AGREED, CHANGED or REJECTED. The ID is the checklist ID.
3. The round is complete when every checklist line in all four files has AGREED or CHANGED. The author then writes `Status: ALIGNED` at the top of their file.
4. Repeat at H6 and H12.

## Index

| File | Between | Status |
|---|---|---|
| `AlltoAll.md` | M1, M2, M3, M4 | FINAL |
| `M1M2agreement.md` | M1, M2 | FINAL |
| `M1M3agreement.md` | M1, M3 | FINAL |
| `M1M4agreement.md` | M1, M4 | FINAL |
| `M2M3agreement.md` | M2, M3 | FINAL |
| `M2M4agreement.md` | M2, M4 | FINAL |
| `M3M4agreement.md` | M3, M4 | FINAL |
| `M1toAll.md` | M1 to all | FINAL |
| `M2toAll.md` | M2 to all | FINAL |
| `M3toAll.md` | M3 to all | FINAL |
| `M4toAll.md` | M4 to all | FINAL |

Add a row here when you create a file.

## User workflow update (2026-10-10)

The user made docs/DECISIONS.md local-only and Git-ignored. Its working-tree copy
is preserved, but it must never be staged or force-added. This supersedes rule 5's
requirement to publish decision rows there. Accepted reply rows and docs/PLAN.md
now carry shared conclusions; authors can keep their own optional local ledger.

Latest user override: M1 uses one persistent `m1` branch for implementation;
no new branch per task. All members publish communications and associated shared
plan updates directly to main after reconciling upstream and running applicable
checks. Implementation reaches main at important milestones (PLAN section 11).
Task completion and implementation integration are recorded separately.

## Final status (2026-10-10)

All four members accepted the communication files as final. `AlltoAll.md` is the
single summary and wins over any older text it contradicts, except a settled reply
row, which wins over everything. The index above is authoritative: a `Status: OPEN`
line left inside a file whose author has not edited it does not reopen that file.
Rule 5 is superseded: settled items live in reply rows, in the toAll files and in
`docs/PLAN.md`. This round is complete. Step 4 of the alignment round ("Repeat at H6
and H12") is unchanged.
A promise that changes after this point is written as a new item with a new ID in
the pair file, and `AlltoAll.md` is corrected in the same commit.
