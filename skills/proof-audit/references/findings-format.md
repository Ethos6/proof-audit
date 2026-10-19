# Findings format (version 1)

One JSON document per run. `proof-audit validate` enforces the structural rules below, including path syntax and quote length; whether each quote actually appears in the target is checked by `proof-audit verify`.

```json
{
  "version": 1,
  "target": { "name": "vulnapp", "source_ref": "3f2c1ab" },
  "coverage": [
    { "unit": "u01-http-injection", "status": "hunted", "checked": ["GET /users", "GET /files/:name"] },
    { "unit": "u02-deps", "status": "skipped", "note": "no lockfile in repo" }
  ],
  "findings": [
    {
      "id": "sqli-users-name",
      "unit": "u01-http-injection",
      "verdict": "confirmed",
      "title": "SQL injection in GET /users via the name query parameter",
      "summary": "The name parameter is concatenated into SQL, so an unauthenticated caller can read every user's email.",
      "severity": "critical",
      "cwe": "CWE-89",
      "boundary": { "attacker": "unauthenticated HTTP client", "asset": "users table" },
      "locations": [
        { "role": "entrypoint", "file": "src/server.js", "line": 9,
          "quote": "const name = req.query.name;", "note": "attacker-controlled" },
        { "role": "sink", "file": "src/server.js", "line": 10,
          "quote": "db.query(\"SELECT id, email FROM users WHERE name = '\" + name + \"'\")" }
      ],
      "remediation": "Use a bound parameter: db.query('... WHERE name = $1', [name])."
    }
  ]
}
```

## Top level

| Field | Required | Notes |
|---|---|---|
| `version` | yes | Always `1`. |
| `target.name` | no | Shown in the report. |
| `target.source_ref` | no, recommended | Commit the findings were written against. `verify` warns if the target's HEAD differs, and says so when the target is not a git checkout and the ref could not be checked. |
| `coverage` | no, recommended | The hunt plan and what happened to each unit. `report` turns it into the Coverage section. |
| `findings` | yes | Array of records below. |

## Coverage entries

| Field | Required | Notes |
|---|---|---|
| `unit` | yes | Unique id, same pattern as finding ids, e.g. `u01-http-injection`. |
| `status` | yes | `hunted`, `skipped`, or `out_of_scope`. |
| `note` | required unless `hunted` | Why it was skipped or out of scope. |
| `checked` | no | Short list of what the hunter examined, including leads it dismissed. |

## Every finding

| Field | Required | Notes |
|---|---|---|
| `id` | yes | Stable, unique, `[A-Za-z0-9][A-Za-z0-9._:/@+-]*`. Same root cause keeps the same id across runs. |
| `verdict` | yes | `confirmed`, `needs_validation`, or `rejected`. |
| `title`, `summary` | yes | Plain language. |
| `cwe` | no | Like `CWE-79`. |
| `unit` | no | The coverage unit that produced it. |
| `locations` | yes, non-empty | See below. |

Verdict-specific:

| Verdict | Must have | Must not have |
|---|---|---|
| `confirmed` | `severity` (`critical`/`high`/`medium`/`low`/`info`), `boundary.attacker`, `boundary.asset`, `remediation`, at least one `entrypoint` and one `sink` location | |
| `needs_validation` | `blocker`: the exact fact the source cannot show | `severity` |
| `rejected` | `reason`: the control or evidence that disproved it | `severity` |

## Locations

| Field | Required | Notes |
|---|---|---|
| `role` | yes | `entrypoint`, `propagation`, `control`, `sink`, or `evidence`. |
| `file` | yes | Path relative to the target root, forward slashes, exact letter case. One leading `./` is tolerated. No absolute paths, `..`, other `.` or empty segments, trailing slash, or segment ending in `.` or a space. |
| `line` | yes | 1-based line where the quote starts. |
| `end_line` | no | Last line the quote may extend to, at most 50 lines after `line` and not past the end of the file. Defaults to `line` plus the quote's line count minus one, so you only need it to allow slack. |
| `quote` | yes | Text copied verbatim from the file, at least 6 non-space characters. Indentation, runs of whitespace and line-ending style are ignored, but whitespace cannot be added or removed between tokens (`f(a,b)` does not match `f(a, b)`). See matching rules below. |
| `note` | no | What this location contributes. |

Role guidance: use `control` both for a control that exists on the path and for one that exists in the codebase but is *not applied* where it should be (for example an `isAdmin` middleware that the route never uses); say which in `note`. Code that is commented out is never a control: cite it as `evidence` with a note such as "fix exists but is commented out".

One root cause is one finding. If the same mistake reaches several sinks (three `eval` calls fed by the same handler), list each as a `sink` location in one finding. Use separate findings when the fixes would be separate.

## Quote matching rules

- **Single line:** the quote may be part of a line, but may not cut an identifier in half (Unicode letters and digits count). `exec(cmd)` does not match inside `safe_exec(cmd)`.
- **Several lines:** the lines must be contiguous. The first quote line may start mid-line and must run to the end of that file line, or stop just before a trailing `//`, `#`, `--` or `/*` comment (a marker inside a string literal does not count). Middle lines must match whole lines. The last quote line must start at the beginning of its file line and may stop early.
- A match proves the text exists at that place. It can still be inside a comment or a string literal; the verifier agent judges what the code does.

## How `verify` checks a location

1. The path must pass the rules above and resolve, after following symlinks, to a regular text file inside the target, under 5 MB.
2. `line` (and `end_line`, if given) must exist in the file.
3. The quote must sit within lines `line` to `end_line` (inclusive).
4. If not, the whole file is searched. One match nearby (at most 30 lines away, or several locations of a finding all shifted by the same amount) is `DRIFTED` and is fixable with `--fix`. One far-away match is `DRIFTED_FAR` and is not auto-fixed. Several matches are `AMBIGUOUS`, and none is `QUOTE_NOT_FOUND`.

A finding passes when all its locations pass. Failures in `rejected` findings are reported but never fail the run.

## Cloudflare `security-audit-skill` compatibility

`verify` also accepts that skill's `findings.json` (a top-level array with `trace` and `evidence` entries). Those entries have no quotes, so `verify` can only prove the file and line exist; each one is reported as `QUOTE_MISSING` (a warning, or an error with `--strict`). Paths that don't exist or point outside the target still fail.
