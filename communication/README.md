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
5. When an item is settled, the author adds one line to `docs/DECISIONS.md`: `H<hour> | <ID> | <final decision>`.
6. After H1, changes to `models.py` are only new optional fields. No renaming, no removing.
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
| `M1M4agreement.md` | M1, M4 | OPEN |
| `M2M4agreement.md` | M2, M4 | OPEN |
| `M3M4agreement.md` | M3, M4 | OPEN |
| `M4toAll.md` | M4 to all | OPEN |

Add a row here when you create a file.
