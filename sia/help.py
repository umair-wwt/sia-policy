"""Small, searchable operator guide available without files, credentials, or network."""
from __future__ import annotations

from .diagnostics import get_diagnostic_help, search_diagnostic_help

TOPICS = {
    "start": ("Getting started", "1. Start sia and choose /setup. The included config.toml has blank tenant fields and explained defaults.\n2. Add your service user and password through /credentials.\n3. Choose /doctor to check local files, then optionally test tenant access.\n4. Choose /plan to preview your server changes. Review the result before /apply.\n\nType / to see suggestions. Tab completes; arrow keys select; Enter runs. /menu shows the home menu and /exit closes it. Your existing CSV commands still work."),
    "settings": ("Settings and when they apply", "Open /settings to edit config.toml. Choose a displayed group or type a setting name such as timeout. Setup's review screen also reaches every group. Invalid fields are explained immediately; URL corrections require your acceptance.\n\nEdits stay pending until Save. Review the labeled changes; choose details for the full TOML diff. /back returns one screen; /cancel returns home. Setup and Settings share a non-secret draft for the same file during this home session. Exiting the process discards it; no draft is stored on disk. Credentials are separate.\n\nIf the file changed externally, Reload merges unrelated edits and asks you to resolve conflicting fields before saving. Repair malformed TOML or unknown keys in the file, then reload. Saving changes local settings only. Use Plan to preview their effect, then Apply with updates enabled to change managed objects. Template policies and CSV overrides can take precedence; the editor labels those settings."),
    "credentials": ("Credentials and their source", "Exported environment variables take precedence over session entries and .env. The Credentials menu shows set/missing and source, never passwords. Hidden prompts can keep credentials for this session or explicitly save them to .env. If an edited file value is shadowed, unset the exported variable before it can take effect. Keep password CSVs outside version control."),
    "plan": ("Plan and apply", "plan reads the tenant and previews changes; it may save local reports. --drift compares all supported policy settings and targets. apply asks you to type yes; --update also fixes differences on managed or explicitly adopted objects. The home screen enables full drift checking. Adoption is an explicit advanced run option. No command deletes tenant objects."),
    "status": ("Activate or suspend policies", "[defaults] policy_status controls new policies. Existing policy status is preserved during ordinary updates. To deliberately change selected policies, preview with sia plan --input input --update --set-policy-status Active, then use apply with the same flags. Suspended is also supported. Only managed or explicitly adopted policies can be updated. A created policy is not access-ready until its state is verified."),
    "inputs": ("Server lists", "servers.csv needs fqdn and either a group column or a configured group convention. domains.csv supplies shared domain accounts; strong_accounts.csv describes exceptions; groups.csv disambiguates directories. CSV problems include the path and row. For a single machine use --server FQDN --group NAME. Use --workgroup for a Windows target outside a domain. RDP is the default; SSH needs a username."),
    "tls": ("Certificates and corporate proxies", "A TLS error means a secure connection could not be verified. Check the tenant hostname, clock, certificate validity, and corporate proxy trust. Set [http] ca_bundle to your organization's trusted PEM file or CA directory; paths in TOML are relative to that file. HTTP TLS verification and target_set_cert_validation are separate settings. Do not disable verification to work around a production trust problem."),
    "resume": ("Interrupted or uncertain runs", "Interruptions and checkpoint failures stop new writes, retain results from requests already sent, and produce an incomplete result. Reports distinguish blocked work from uncertain writes; checkpoints contain only completed rows. Use the same input and checkpoint with apply --resume to skip rows previously completed under matching tenant/settings. Cached rows are labeled as not rechecked; run verify for current tenant state. Changed configuration, templates, or input mappings invalidate matching records. When a mutation outcome is uncertain, run plan --drift first to reconcile current state before another write."),
    "reports": ("Results and reports", "plan/apply write JSON and CSV to reports unless --no-report is set. --json prints one result document on stdout and keeps human messages on stderr, including on errors. Incomplete results include complete: false. Exit codes: 0 completed, 1 operation or verification needs attention, 2 input/configuration/command problem or cancellation, 130 interrupted. Automatically named exports preserve existing files. If publication fails partway through, the error lists completed paths. A report-saving error is separate from confirmed tenant changes; verify those changes before rerunning apply."),
    "connect": ("Connection troubleshooting", "connect-info exports gateway and connection details. --no-tenant works offline and leaves tenant status empty. A passing API check does not establish that a user can log in. Check group membership, policy status/access window, connector health, and connector-to-target WinRM or SSH reachability. Windows also needs the intended strong account and local-account remote administration prerequisites. Test one real session as a member of the allowed group."),
    "paths": ("Which files are in use?", "Defaults are config.toml, .env, input, and reports in the working directory. --config, --env, --input and --report-dir select other locations. CLI paths stay relative to the working directory; paths stored inside TOML are relative to that TOML file. Settings > Project files and settings --show display absolute paths. The terminal creates a bundled starter config.toml only when the selected file is missing; existing files are preserved. One project is active at a time."),
}


def _format_diagnostic(item: dict) -> str:
    lines = [f"{item['code']}: {item['summary']}", "", "What to do next:"]
    lines.extend(f"  - {action}" for action in item.get("actions", ()))
    return "\n".join(lines)


def help_text(query: str = "") -> str:
    query = query.strip()
    if not query:
        listing = "\n".join(f"  {name:<12} {title}" for name, (title, _) in TOPICS.items())
        return "SIA Help\n\nRun sia help TOPIC or sia help ERROR-CODE.\n\n" + listing + "\n\nUse sia <command> --help for exact flags."
    topic = TOPICS.get(query.lower())
    if topic:
        return f"{topic[0]}\n\n{topic[1]}"
    diagnostic = get_diagnostic_help(query.upper())
    if diagnostic:
        return _format_diagnostic(diagnostic)
    matches = [(key, title, body) for key, (title, body) in TOPICS.items()
               if query.lower() in f"{key} {title} {body}".lower()]
    found = search_diagnostic_help(query)
    text = "\n\n".join(f"{key}: {title}\n{body}" for key, title, body in matches)
    if found:
        rendered = "\n\n".join(_format_diagnostic(item) for item in found)
        text += ("\n\n" if text else "") + "Diagnostic matches:\n\n" + rendered
    return text.strip() or f"No help topic matches {query!r}. Run sia help to list topics."
