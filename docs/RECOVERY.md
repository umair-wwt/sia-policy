# Recovery coverage

Setup and Settings keep non-secret drafts only for the current home session. `/back` returns one screen;
`/cancel` returns home. Reopen either editor for the same configuration to resume pending edits. Closing the
process discards drafts. Saved configuration and credentials are separate.

This matrix describes the failure paths covered by the offline regression suite. It is not a guarantee against
every possible tenant response, operating-system failure, or abrupt process termination.

| Scenario | Expected recovery |
|---|---|
| Invalid Identity or other base URL | Explain the field error immediately; offer a safe syntax correction for explicit acceptance, or allow re-entry and Back. |
| Wrong earlier Setup answer | Back reaches the preceding screen; the review menu exposes every settings group. |
| Cancel, EOF, or Ctrl-C during Setup | Preserve the non-secret draft in the current home session; identify already-saved configuration separately during credential setup. |
| Leave and reopen Settings | Resume the same draft for the resolved config path; another project's draft is isolated. |
| Exit with pending drafts | Explicit home exit asks before discarding; drafts never survive process termination. |
| Invalid number, list, time zone, range, or template placeholder | Reject invalid input without advancing; run cross-field validation before saving. |
| Invalid TOML or unknown settings | Preserve the file, explain external repair, and provide a retry/reload route. |
| External config edit | Stop the save; merge unrelated changes and require a choice for overlapping fields before another review. |
| External config deletion or unresolved merge conflicts | Retain the full draft and unresolved choices for reviewed recovery. |
| Credential entry cancelled or password left empty | Store neither half of an incomplete pair; empty hidden input returns to the user field. |
| Mistyped credential storage option or `.env` save conflict | Retain the entry on that screen and offer an explicit retry/storage choice. |
| Malformed or nonregular credentials file | Explain the affected path; a home session can use explicitly chosen session credentials. |
| Guided workflow input error | Re-prompt the invalid answer, preserve earlier answers, and offer an editable command review before dispatch. |
| Quoted command arguments and paths | Parse native POSIX and Windows quoting; reject malformed command lines without exiting home. |
| Conflicting CSV mappings or generated account/target/policy names | Report input errors before tenant writes. |
| Malformed template policy | Validate copied structures and known field types before using it in a mutation payload. |
| Malformed authentication/API response | Report the endpoint/response failure rather than interpreting it as an empty inventory. |
| Pagination cycle, repeated page, or limit exceeded | Stop discovery as incomplete; do not make missing-object decisions from partial results. |
| Ambiguous Identity roles or groups, accounts, target sets, or policies | Require disambiguation; duplicate references to the same stable identity can be deduplicated. |
| Mutation timeout or server error | Preserve an uncertain outcome; require read-only reconciliation before repeating the write. |
| Policy listing omits principals | Read full details; report unverified if the full response still cannot establish the principals. |
| Accepted policy write or target-set update reads back different settings | Retry reads within the polling limit; retain the object reference and report unverified without a completed checkpoint if it does not match. |
| Version-2 checkpoint | Preserve the file and reconcile the row again under version-3 verification rules. |
| Interrupted run or checkpoint failure | Stop new write scheduling, retain in-flight results, block unattempted work, and keep partial object references. |
| Failed or interrupted report publication | Preserve tenant results and list completed output paths; local output failure does not undo tenant changes. |
| Closed console pipe after tenant work | Attempt durable reports before rendering the final summary. |
| Export collision or staging failure | Preserve existing generated outputs, reserve distinct names, and stage complete files before publication. |
| Permission, missing-file, disk-full, or dependency failure | Identify the supported cause and give the relevant recovery action. |
| Windows PowerShell cannot execute the installer | Try the next available PowerShell host, then the CMD/Python route automatically. |
| Missing Python, missing pip, or partial app installation | Discover or provision Python; repair pip or build a fresh environment, then validate startup before selecting it. |
| Failed environment upgrade | Preserve the previously selected environment and user files; a later launch or installer rerun can retry. |
| Changed source or broken runtime at launch | Perform one automatic repair, then recheck; no endless relaunch loop. |
| Windows `.env` protection fails before save | Retain credentials automatically in the terminal home session and explain that saving failed. |
| Windows `.env` replaced but final ACL check fails | Identify that the destination changed and its protection is unconfirmed; direct the user to Doctor. |

The principal regressions live in `tests/test_terminal.py`, `tests/test_settings.py`, `tests/test_config.py`,
`tests/test_inputs.py`, `tests/test_payloads.py`, `tests/test_client_response_safety.py`,
`tests/test_execution_recovery.py`, `tests/test_artifact_recovery.py`, and the CLI/diagnostic tests.

Run the offline suite from the checkout:

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -p no:cacheprovider
```

Interactive checks exercise URL correction, Back, Cancel, draft resume, save, workflow cancellation, and hidden
credential entry using temporary project files. Tenant API behavior and actual RDP/SSH connectivity still require
a separate authorized tenant check; offline tests do not establish those results. A forced kill or power loss
cannot preserve memory-only drafts or guarantee a final report.

Windows details and operating-system limits are in [WINDOWS.md](WINDOWS.md). Native launcher and DACL tests skip on
macOS/Linux. The Windows CI workflow provides separate native verification when it runs; local mocked tests and a
PowerShell syntax check do not establish that result.
