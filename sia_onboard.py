#!/usr/bin/env python3
"""Onboard Windows servers into CyberArk/Idira SIA: strong account -> target set -> per-server UAP access policies.

Commands:
  preflight               authenticate, detect the SIA API families, read tenant settings and counts (read-only)
  show-policy NAME        print an existing policy as JSON (use on a UI-created policy to confirm conventions)
  plan  --input DIR       dry run: what would be created / already exists / drifted
  apply --input DIR       create missing objects (idempotent); --update also fixes drift on managed/adopted objects
  verify --input DIR      PASS/FAIL per row: every object present and the policy Active (read-only)
  connect-info --input DIR  what end users need to connect: gateway, ZSP user name, optional .rdp files (read-only)
"""
from __future__ import annotations

import sys

if __name__ == "__main__":
    if sys.version_info < (3, 11):
        from sia.bootstrap import main as bootstrap_main
        sys.exit(bootstrap_main())
    try:
        import requests  # noqa: F401 - give direct-script users an actionable installation error
        import tomlkit  # noqa: F401
    except ImportError as exc:
        from sia.bootstrap import main as bootstrap_main
        sys.exit(bootstrap_main(dependency_error=exc))

import argparse
from contextlib import redirect_stdout
from contextvars import ContextVar
import json
import logging
import os
import tempfile
import traceback
from collections import Counter
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path

from sia.auth import AuthError, PlatformTokenProvider, make_identity_token_provider
from sia.checkpoint import DEFAULT_NAME as CHECKPOINT_NAME
from sia.checkpoint import Checkpoint
from sia.clients import IdentityClient, PerAccountTargetSetListingRequired, SIAClient, UAPClient
from sia.config import PRINCIPAL_RENAME_HINT, Config, ConfigError, load_config, load_password_file
from sia.diagnostics import Diagnostic, diagnose, render_diagnostic, sanitize
from sia.connect import build_rows, login_suffix, write_connection_outputs
from sia.http import HttpClient, RateLimiter, SIAApiError
from sia.inputs import LIST_SEPARATOR, InputError, Inputs, StrongAccountRow, inline_inputs, load_inputs
from sia.payloads import policy_name_for
from sia.pvwa import PVWAClient
from sia.reconcile import LOOKUP_MODES, MAX_WORKERS, STAGES, ReconcileError, Reconciler
from sia.redact import RedactingFilter, redact, register_secret
from sia.report import exit_code, print_summary, print_verify, result_dict, write_reports, write_verify_csv
from sia.resolve import PrincipalResolver, pick
from sia.runtime import Session, prompt_secret
from sia.trust import apply_trust_policy, describe_trust

EXIT_OK, EXIT_FAILURES, EXIT_USAGE = 0, 1, 2
PAM_REQUIRED_FIELDS = (("pvwa_base_url", "pvwaBaseUrl"), ("connector_pool_id", "connectorPoolId"),
                       ("service_user_secret_id", "serviceUserSecretId"))
MAX_PASSWORD_PROMPTS = 5
log = logging.getLogger("sia")
_active_checkpoint: Path | None = None
_secret_sink: ContextVar[dict[str, str] | None] = ContextVar("secret_sink", default=None)


def interactive() -> bool:
    return sys.stdin.isatty() and sys.stderr.isatty()


def remember_secret(name: str, value: str) -> None:
    register_secret(value)
    sink = _secret_sink.get()
    if sink is not None and value:
        sink[name] = value


def resolve_client_secret() -> str:
    secret = os.environ.get("SIA_CLIENT_SECRET", "")
    if not secret and interactive():
        secret = prompt_secret("SIA_CLIENT_SECRET (not echoed): ")
        remember_secret("SIA_CLIENT_SECRET", secret)
    if not secret:
        raise ConfigError("SIA_CLIENT_SECRET is not set (put it in .env, export it, or run interactively to be prompted)")
    register_secret(secret)
    return secret


class Context:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        client_id = os.environ.get("SIA_CLIENT_ID", "")
        if not client_id:
            raise ConfigError("SIA_CLIENT_ID is not set (put it in .env or export it)")
        self.client_id = client_id
        secret = resolve_client_secret()
        timeout = cfg.http.timeout_seconds
        # Before any session is built: truststore patches ssl.SSLContext process-wide.
        verify, self.trust_source = apply_trust_policy(cfg.http, log)
        self.verify = verify
        if verify is False:
            log.warning("TLS verification is OFF ([http] verify = false): traffic to the tenant is not authenticated")
        self.limiter = RateLimiter(cfg.http.max_requests_per_second) if cfg.http.max_requests_per_second > 0 else None
        self.token = PlatformTokenProvider(cfg.tenant.identity_url, client_id, secret, timeout=timeout, verify=verify)
        self.identity_token = make_identity_token_provider(
            cfg.auth.identity_auth, self.token, identity_url=cfg.tenant.identity_url, client_id=client_id,
            client_secret=secret, application=cfg.auth.oidc_application, timeout=timeout, verify=verify)
        self.http = HttpClient(self.token, timeout=timeout, max_retries=cfg.http.max_retries, limiter=self.limiter,
                               verify=verify)
        identity_http = self.http if self.identity_token is self.token else HttpClient(
            self.identity_token, timeout=timeout, max_retries=cfg.http.max_retries, limiter=self.limiter, verify=verify)
        self.sia = SIAClient(self.http, cfg.tenant.dpa_url, secrets_api=cfg.http.secrets_api, targetsets_api=cfg.http.targetsets_api)
        self.uap = UAPClient(self.http, cfg.tenant.uap_url, page_size=cfg.http.policy_page_size)
        self.identity = IdentityClient(identity_http, cfg.tenant.identity_url)
        self._pvwa: PVWAClient | None = None

    def pvwa_client(self) -> PVWAClient | None:
        """Logged-on PVWA client when [pvwa] is configured (credentials PVWA_USER / PVWA_PASSWORD), else None."""
        if not self.cfg.pvwa.enabled:
            return None
        if self._pvwa is None:
            user = os.environ.get("PVWA_USER", "")
            password = os.environ.get("PVWA_PASSWORD", "")
            if not password and interactive():
                password = prompt_secret(f"PVWA_PASSWORD for {user or 'PVWA user'} (not echoed): ")
                remember_secret("PVWA_PASSWORD", password)
            if not user or not password:
                raise ConfigError("[pvwa] is configured but PVWA_USER / PVWA_PASSWORD are not set (put them in .env)")
            client = PVWAClient(self.cfg.pvwa.base_url, auth_type=self.cfg.pvwa.auth_type,
                                timeout=self.cfg.http.timeout_seconds, verify=self.verify)
            client.logon(user, password)
            self._pvwa = client
        return self._pvwa


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ConfigError(f"Command not understood: {message}. Run 'sia help' or 'sia <command> --help'.")


def add_global_flags(parser: argparse.ArgumentParser, *, root: bool = False) -> None:
    def default(value):
        return value if root else argparse.SUPPRESS
    parser.add_argument("--config", default=default("config.toml"), help="configuration path (default: ./config.toml)")
    parser.add_argument("--env", default=default(".env"), help="credentials file (default: ./.env)")
    parser.add_argument("--report-dir", default=default("reports"), help="report directory (default: ./reports)")
    parser.add_argument("-v", "--verbose", action="store_true", default=default(False), help="sanitized technical details")
    parser.add_argument("--ca-bundle", metavar="FILE", default=default(None), help="trusted CA file/directory; overrides configuration")
    parser.add_argument("--system-trust", dest="system_trust", action="store_true", default=default(None),
                        help="verify TLS against the operating system trust store (default)")
    parser.add_argument("--no-system-trust", dest="system_trust", action="store_false", default=default(None),
                        help="verify TLS against certifi instead of the operating system trust store")
    parser.add_argument("--json", action="store_true", default=default(False), help="machine-readable result on stdout; messages on stderr")


def build_parser() -> argparse.ArgumentParser:
    parser = ArgumentParser(prog="sia", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_global_flags(parser, root=True)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("preflight", help="authenticate and read tenant state (read-only)")
    sp = sub.add_parser("show-policy", help="print an existing UAP policy as JSON")
    sp.add_argument("name")
    sp.add_argument("--from-list", action="store_true", help="print the (partial) object the list endpoint returns instead of the full policy")

    def add_input_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument("--input", default="input", help="directory with servers.csv[, domains.csv, strong_accounts.csv, groups.csv]")
        p.add_argument("--server", action="append", default=[], metavar="FQDN",
                       help="onboard this server instead of reading servers.csv (repeatable); the other CSVs are still read")
        p.add_argument("--principal", action="append", default=[], metavar="NAME",
                       help="--server only: Identity role (or group, see [defaults] principal_type) that may connect "
                            "(repeatable); omit to use principal_template")
        p.add_argument("--group", action="append", default=[], help=argparse.SUPPRESS)   # renamed; rejected with a hint
        p.add_argument("--strong-account", metavar="NAME", help="--server only: override the strong account")
        p.add_argument("--server-domain", metavar="DNS", help="--server only: AD domain, when it differs from the FQDN's")
        p.add_argument("--workgroup", action="store_true", help="--server only: the target is not domain-joined")
        p.add_argument("--protocol", choices=("rdp", "ssh"), help="--server only: rdp (default) or ssh")
        p.add_argument("--ssh-username", metavar="USER", help="--server only: certificate user name for --protocol ssh")
        p.add_argument("--offset", type=int, default=0, metavar="N", help="skip the first N servers of the input (waves)")
        p.add_argument("--limit", type=int, default=0, metavar="N", help="process at most N servers (0 = all)")
        p.add_argument("--lookup", choices=LOOKUP_MODES, default="auto",
                       help="how existing objects are read: search per server, one filtered list, or auto by size")
        p.add_argument("--workers", type=int, default=1, metavar="N",
                       help=f"parallel requests (1-{MAX_WORKERS}); the first object of each stage is always created alone first")

    for name, help_text in (("plan", "dry run"), ("apply", "create/update objects")):
        p = sub.add_parser(name, help=help_text)
        add_input_flags(p)
        p.add_argument("--only", choices=STAGES, default="all", help="restrict writes to one stage (lookups still run)")
        p.add_argument("--update", action="store_true",
                       help="also fix drift on objects this tool manages (owner tag/marker) or that you --adopt")
        p.add_argument("--drift", action="store_true",
                       help="compare targets of existing policies too (one extra read per policy; implied by --update)")
        p.add_argument("--adopt", action="append", default=[], metavar="FQDN|POLICY",
                       help="take ownership of an existing unmanaged policy/target set (repeatable)")
        p.add_argument("--adopt-all", action="store_true", help="take ownership of every matching unmanaged object")
        p.add_argument("--keep-going", action="store_true",
                       help="do not abort the run on the first 4xx from a create/update (default: fail fast)")
        p.add_argument("--passwords", metavar="FILE",
                       help="CSV (name,password) with strong-account passwords; overrides [auth] password_file")
        p.add_argument("--resume", action="store_true", help="skip rows the checkpoint file records as complete")
        p.add_argument("--checkpoint", metavar="FILE", help=f"checkpoint file (default: <input>/{CHECKPOINT_NAME})")
        p.add_argument("--progress-every", type=int, default=100, metavar="N", help="log progress every N objects (0 = off)")
        p.add_argument("--set-policy-status", choices=("Active", "Suspended"),
                       help="explicitly set the selected policies' status (requires --update)")
        p.add_argument("--no-report", action="store_true", help="do not write the JSON/CSV report files")
        if name == "apply":
            p.add_argument("--yes", "-y", action="store_true", help="do not ask for confirmation")
    vp = sub.add_parser("verify", help="check that every row's objects exist and its policy is Active (read-only)")
    add_input_flags(vp)
    vp.add_argument("--drift", action="store_true", help="also compare policy targets (one extra read per policy)")
    vp.add_argument("--out", metavar="FILE", help="write the PASS/FAIL table as CSV")
    cp = sub.add_parser("connect-info", help="export what end users need to connect (read-only, no secrets)")
    add_input_flags(cp)
    cp.add_argument("--out", metavar="FILE", help="CSV to write (default: <report-dir>/connect-info-<timestamp>.csv)")
    cp.add_argument("--rdp-dir", metavar="DIR", help="also write one .rdp file per Windows row into DIR")
    cp.add_argument("--login-user", default="<user>", metavar="USER", help="login name to put in the ZSP user name (default: a placeholder)")
    cp.add_argument("--network", metavar="NAME", help="connector network to add as '/n NAME' (overrides [connect] network)")
    cp.add_argument("--no-tenant", action="store_true", help="do not read the tenant; leave the status columns empty")
    sub.add_parser("setup", help="guided local configuration and optional credential saving")
    settings = sub.add_parser("settings", help="view or edit this project's real settings (offline)")
    settings.add_argument("--show", action="store_true", help="show values and their sources without prompting")
    doctor = sub.add_parser("doctor", help="check local setup; --online also checks tenant access")
    add_input_flags(doctor)
    doctor.add_argument("--online", action="store_true", help="authenticate and run read-only tenant checks")
    shell = sub.add_parser("shell", help="open the terminal home screen")
    shell.add_argument("--input", default="input", help="default input directory for this session")
    help_parser = sub.add_parser("help", help="plain-language help by topic or diagnostic code")
    help_parser.add_argument("topic", nargs="?", default="")
    for child in sub.choices.values():
        add_global_flags(child)
    return parser


def cmd_preflight(ctx: Context, checks: list[dict] | None = None, *, verbose: bool = False) -> int:
    checks = checks if checks is not None else []
    ok = True
    t = ctx.cfg.tenant
    print(f"Tenant:   {t.subdomain}  SIA={t.dpa_url}  UAP={t.uap_url}  Identity={t.identity_url}")
    print(f"TLS:      {describe_trust(ctx.cfg.http, getattr(ctx, 'trust_source', None))}")
    try:
        token = ctx.token()
        claims = ctx.token.claims
        print(f"Auth:     OK platform token ({len(token)} chars, subject={claims.get('unique_name') or claims.get('sub') or '?'})")
        checks.append({"name": "Auth", "status": "passed", "message": "Platform authentication succeeded"})
        claimed = claims.get("subdomain")
        if claimed and str(claimed).lower() != t.subdomain:
            print(f"          WARNING: token says subdomain={claimed!r} but config says {t.subdomain!r}")
            diagnostic = Diagnostic(code="SIA-TENANT-MISMATCH", message=f"Authenticated token belongs to tenant {claimed!r}, but configuration selects {t.subdomain!r}.",
                                    actions=("Correct the tenant configuration or credential source before applying changes.",),
                                    stage="Authentication", mutation_state="not_applicable")
            checks.append({"name": "Tenant identity", "status": "failed", "message": diagnostic.message, "diagnostic": diagnostic.to_dict()})
            render_diagnostic(diagnostic, sys.stdout, verbose=verbose)
            return EXIT_FAILURES
    except AuthError as exc:
        diagnostic = diagnose(exc, stage="Authentication")
        print("Auth:     FAILED")
        render_diagnostic(diagnostic, sys.stdout, verbose=verbose)
        checks.append({"name": "Auth", "status": "failed", "message": diagnostic.message, "diagnostic": diagnostic.to_dict()})
        return EXIT_FAILURES

    def settings() -> None:
        try:
            s = ctx.sia.get_settings()
        except SIAApiError as exc:
            if exc.status in (401, 403, 404, 405, 501):
                reason = "access was rejected; this endpoint may require a separate role" if exc.status in (401, 403) else "the optional endpoint is unavailable"
                message = f"Settings not verified (HTTP {exc.status}); {reason}."
                print(f"Settings: not verified (HTTP {exc.status}: {reason}; this check is optional)")
                checks.append({"name": "Settings", "status": "warning", "message": message})
                return
            raise
        pam = pick(s, "self_hosted_pam", "selfHostedPam", default=None)
        if not pam:
            print("Settings: OK  self_hosted_pam: not configured -- vault strong accounts need the PAM integration configured in SIA")
            checks.append({"name": "Settings", "status": "warning", "message": "PAM integration is not configured; check the required account integration before using Vault accounts."})
            return
        tenant_type = str(pick(pam, "tenant_type", "tenantType", default="") or "")
        missing = [snake for snake, camel in PAM_REQUIRED_FIELDS if not pick(pam, snake, camel)]
        state = "configured" if tenant_type.upper() == "SELF_HOSTED" and not missing else "incomplete"
        print(f"Settings: OK  self_hosted_pam={state} tenant_type={tenant_type or 'not set'} "
              f"pvwa={pick(pam, 'pvwa_base_url', 'pvwaBaseUrl', default='-')} connector_pool={pick(pam, 'connector_pool_id', 'connectorPoolId', default='-')}")
        if tenant_type.upper() != "SELF_HOSTED":
            print("          NOTE: expected tenant_type=SELF_HOSTED for a self-hosted Vault (PCLOUD = Privilege Cloud)")
        if missing:
            print(f"          NOTE: missing {', '.join(missing)}; complete the integration in SIA settings before relying on vault accounts")
        if state != "configured":
            checks.append({"name": "Settings", "status": "warning", "message": f"PAM integration is {state}; check the configured tenant integration."})

    def api_families() -> None:
        probe = getattr(ctx.sia, "probe", None)
        if probe is None:
            print("SIA API:  not probed")
            checks.append({"name": "SIA API", "status": "not checked", "message": "Client does not expose API-family probing"})
            return
        caps = probe()
        pins = f"[http] secrets_api = \"{ctx.cfg.http.secrets_api}\", targetsets_api = \"{ctx.cfg.http.targetsets_api}\""
        print(f"SIA API:  OK  {caps.describe()}  ({pins})")

    def secrets() -> None:
        items = ctx.sia.list_secrets()
        types = Counter(str(pick(i, "secret_type", "secretType", default="?")) for i in items)
        active = sum(1 for i in items if pick(i, "is_active", "isActive", default=True))
        print(f"Secrets:  OK  {len(items)} strong accounts ({dict(types)}, active={active})")
        for i in items[:20]:
            details = pick(i, "secret_details", "secretDetails", default={}) or {}
            print(f"          - {pick(i, 'secret_name', 'secretName', default='<unnamed>')}  [{pick(i, 'secret_type', 'secretType')}]  "
                  f"id={pick(i, 'secret_id', 'secretId')}  domain={details.get('account_domain', '-')}")
        if len(items) > 20:
            print(f"          ... {len(items) - 20} more")

    def target_sets() -> None:
        try:
            items = ctx.sia.list_target_sets()
        except PerAccountTargetSetListingRequired as exc:
            print(f"Targets:  OK  ({exc}; per-account listing will be used)")
            return
        types = Counter(str(pick(i, "type", default="?")) for i in items)
        print(f"Targets:  OK  {len(items)} target sets ({dict(types)})")

    def policies() -> None:
        items = ctx.uap.list_policies()
        statuses = Counter(str(((i.get("metadata") or {}).get("status") or {}).get("status", "?")) for i in items)
        owned = sum(1 for i in items if ctx.cfg.defaults.owner_tag in ((i.get("metadata") or {}).get("policyTags") or []))
        print(f"Policies: OK  {len(items)} VM access policies ({dict(statuses)}); {owned} tagged {ctx.cfg.defaults.owner_tag!r}")

    def directories() -> None:
        method = ctx.cfg.auth.identity_auth
        try:
            dirs = ctx.identity.list_directories()
        except SIAApiError as exc:
            if exc.status in (401, 403):
                other = "service_user_oidc" if method == "platform_token" else "platform_token"
                raise SIAApiError(exc.method, exc.url, exc.status,
                                  f"{exc.body} -- Identity rejected the {method} token; try [auth] identity_auth = \"{other}\"") from exc
            raise
        print(f"Identity: OK  {len(dirs)} directories (auth={method})")
        for d in dirs:
            print(f"          - {pick(d, 'Service')}  {pick(d, 'DisplayName', 'Name', default='')}  uuid={pick(d, 'directoryServiceUuid', 'DirectoryServiceUuid')}")

    def pvwa() -> None:
        if not ctx.cfg.pvwa.enabled:
            print("PVWA:     not configured ([pvwa] base_url empty; the vault stage is off)")
            checks.append({"name": "PVWA", "status": "not checked", "message": "Optional vault onboarding is disabled"})
            return
        client = ctx.pvwa_client()
        print(f"PVWA:     OK  logged on to {ctx.cfg.pvwa.base_url} (auth={ctx.cfg.pvwa.auth_type}, platform={ctx.cfg.pvwa.platform_id})")
        if client is not None:
            client.logoff()

    for label, fn in (("Settings:", settings), ("SIA API:", api_families), ("Secrets:", secrets), ("Targets:", target_sets),
                      ("Policies:", policies), ("Identity:", directories), ("PVWA:", pvwa)):
        previous_checks = len(checks)
        try:
            fn()
            if len(checks) == previous_checks:
                checks.append({"name": label.rstrip(":"), "status": "passed", "message": "Read-only API check succeeded"})
        except Exception as exc:
            ok = False
            diagnostic = diagnose(exc, stage=label.rstrip(":"))
            print(f"{label:<9} FAILED: {diagnostic.message}")
            render_diagnostic(diagnostic, sys.stdout, verbose=verbose)
            checks.append({"name": label.rstrip(":"), "status": "failed", "message": diagnostic.message, "diagnostic": diagnostic.to_dict()})
    print("\nPreflight", "OK" if ok else "finished with failures")
    return EXIT_OK if ok else EXIT_FAILURES


def cmd_show_policy(ctx: Context, name: str, from_list: bool = False) -> int:
    found = ctx.uap.find_policy_by_name(name)
    if not found:
        raise ReconcileError(f"policy {name!r} not found; check its exact name and the selected tenant")
    policy_id = pick(found.get("metadata") or {}, "policyId", "policy_id")
    policy = found if from_list or not policy_id else ctx.uap.get_policy(str(policy_id))
    print(json.dumps(sanitize(policy), indent=2, sort_keys=True))
    return EXIT_OK


def make_password_source(allow_prompt: bool, file_passwords: dict[str, str] | None = None, max_prompts: int = MAX_PASSWORD_PROMPTS):
    """Strong-account passwords, in order: environment variable, password file, then (interactive apply only) a
    no-echo prompt -- at most `max_prompts` prompts per run, after which the password file is the answer. Every
    value is registered with the redactor."""
    file_passwords = file_passwords or {}
    cache: dict[str, str] = {}
    prompted: list[str] = []

    def get_password(account: StrongAccountRow) -> str | None:
        env_name = account.password_env or ""
        value = os.environ.get(env_name, "") if env_name else ""
        if not value:
            value = file_passwords.get(account.name, "")
        if not value:
            value = cache.get(account.name, "")
        if not value and allow_prompt and interactive():
            if len(prompted) < max_prompts:
                prompted.append(account.name)
                value = prompt_secret(f"Password for strong account {account.name} (user {account.username}, not echoed): ")
                cache[account.name] = value
            elif len(prompted) == max_prompts:
                prompted.append("-")
                print(f"More than {max_prompts} passwords are missing; add them to the password file (--passwords) instead of typing them.",
                      file=sys.stderr)
        if value:
            register_secret(value)
        return value or None

    return get_password


SERVER_ONLY_FLAGS = (("principal", "--principal"), ("strong_account", "--strong-account"), ("server_domain", "--server-domain"),
                     ("workgroup", "--workgroup"), ("protocol", "--protocol"), ("ssh_username", "--ssh-username"))


def check_server_flags(args: argparse.Namespace) -> None:
    """These flags describe the row --server builds. Without --server they would silently do nothing."""
    if getattr(args, "group", None):
        raise ConfigError(f"--group was renamed to --principal ({PRINCIPAL_RENAME_HINT})")
    if args.server:
        return
    used = [flag for attr, flag in SERVER_ONLY_FLAGS if getattr(args, attr, None)]
    if used:
        raise ConfigError(f"{', '.join(used)} only apply together with --server; without it the servers and their "
                          "principals come from servers.csv")


def inline_rows(args: argparse.Namespace) -> list[dict[str, str]]:
    """--server FQDN [...] as servers.csv rows, so both paths run through the same validation."""
    shared = {
        "principal": LIST_SEPARATOR.join(args.principal),
        "strong_account": args.strong_account or "",
        "domain": args.server_domain or "",
        "protocol": args.protocol or "",
        "ssh_username": args.ssh_username or "",
        "domain_joined": "no" if args.workgroup else "",
    }
    return [{"fqdn": fqdn, **shared} for fqdn in args.server]


def load_wave(ctx: Context, args: argparse.Namespace) -> Inputs:
    if getattr(args, "_loaded_inputs", None) is not None:
        return args._loaded_inputs
    d = ctx.cfg.defaults
    check_server_flags(args)
    common = dict(strong_account_template=d.strong_account_spec or "", ssh_username_default=d.ssh_username,
                  policy_name_template=d.policy_name_template, principal_template=d.principal_template,
                  principal_type=d.principal_type, target_set_scope=d.target_set_scope)
    if args.server:
        inputs = inline_inputs(args.input, inline_rows(args), **common)
    else:
        inputs = load_inputs(args.input, **common)
    total = len(inputs.unique_fqdns)
    if args.offset or args.limit:
        if args.offset < 0 or args.limit < 0:
            raise ConfigError("--offset and --limit must be >= 0")
        inputs = inputs.window(args.offset, args.limit or None)
    log.info("Loaded %d rows for %d servers (%d ssh), %d strong accounts, %d directory pins%s", len(inputs.servers),
             len(inputs.unique_fqdns), sum(1 for s in inputs.servers if s.is_ssh), len(inputs.strong_accounts), len(inputs.groups),
             f" -- wave {args.offset}..{args.offset + len(inputs.unique_fqdns)} of {total} servers" if (args.offset or args.limit) else "")
    for warning in inputs.warnings:
        log.warning("%s", warning)
    if not 1 <= args.workers <= MAX_WORKERS:
        raise ConfigError(f"--workers must be between 1 and {MAX_WORKERS}")
    return inputs


def cmd_plan_apply(ctx: Context, args: argparse.Namespace, dry_run: bool) -> int:
    global _active_checkpoint
    d = ctx.cfg.defaults
    # With --json, stdout carries only the JSON document so a caller can parse it; everything human goes to stderr.
    human = sys.stderr if args.json else sys.stdout
    inputs = load_wave(ctx, args)
    file_passwords: dict[str, str] = {}
    password_file = args.passwords or ctx.cfg.auth.password_file
    if password_file:
        file_passwords = load_password_file(password_file)
        unknown = sorted(set(file_passwords) - set(inputs.strong_accounts))
        log.info("Loaded passwords for %d strong account(s) from %s", len(file_passwords), password_file)
        if unknown:
            log.warning("password file lists %d name(s) not in strong_accounts.csv: %s", len(unknown), ", ".join(unknown[:10]))
    checkpoint_path = Path(args.checkpoint) if args.checkpoint else Path(args.input) / CHECKPOINT_NAME
    checkpoint = Checkpoint(checkpoint_path)
    if not dry_run:
        writable, reason = checkpoint.check_writable()
        if not writable:
            raise ConfigError(f"Cannot write checkpoint {checkpoint_path}: {reason}. Choose --checkpoint with a writable path before applying.")
        if not args.no_report:
            directory = Path(args.report_dir)
            try:
                directory.mkdir(parents=True, exist_ok=True)
                with tempfile.TemporaryFile(dir=directory):
                    pass
            except OSError as exc:
                raise ConfigError(f"Cannot save reports in {directory}: {exc}. Choose --report-dir before applying, or explicitly use --no-report.") from exc
    if checkpoint_path.is_file():
        finished = checkpoint.done_count()
        if finished and not args.resume:
            log.info("checkpoint %s records %d finished row(s); pass --resume to skip them", checkpoint_path, finished)
    if not dry_run:
        _active_checkpoint = checkpoint_path
    resolver = PrincipalResolver(ctx.identity, inputs.pinned_directory, principal_type=ctx.cfg.defaults.principal_type)
    needs_vault = ctx.cfg.pvwa.enabled and args.only in ("all", "vault") and any(
        a.type == "vault" for a in inputs.referenced_strong_accounts)
    pvwa = ctx.pvwa_client() if needs_vault else None
    rec = Reconciler(sia=ctx.sia, uap=ctx.uap, resolver=resolver, inputs=inputs, defaults=d,
                     dry_run=dry_run, update=args.update, only=args.only, fail_fast=not args.keep_going,
                     adopt=args.adopt, adopt_all=args.adopt_all, workers=args.workers,
                     status_polls=ctx.cfg.http.status_polls, drift=True if args.drift else None,
                     lookup=args.lookup, lookup_search_max_rows=ctx.cfg.http.lookup_search_max_rows,
                     checkpoint=checkpoint, resume=args.resume, progress_every=args.progress_every,
                     pvwa=pvwa, pvwa_platform_id=ctx.cfg.pvwa.platform_id, pvwa_cpm_managed=ctx.cfg.pvwa.cpm_managed,
                     set_policy_status=args.set_policy_status, suspended_ok=d.policy_status == "Suspended",
                     reconciliation_context={"tenant": asdict(ctx.cfg.tenant), "pvwa": asdict(ctx.cfg.pvwa)},
                     get_password=make_password_source(allow_prompt=not dry_run, file_passwords=file_passwords))
    result = None
    run_stopped = False
    cleanup_interrupted = False
    cleanup_error: Exception | None = None
    previous_cancel = getattr(getattr(ctx, "http", None), "cancel_check", None)
    previous_pvwa_cancel = getattr(pvwa, "cancel_check", None)
    if getattr(ctx, "http", None) is not None:
        ctx.http.cancel_check = rec.check_cancelled
    if pvwa is not None:
        pvwa.cancel_check = rec.check_cancelled
    try:
        rec.snapshot()
        if not dry_run and not args.yes:
            preview = rec.reconcile(dry_run=True)
            print_summary(preview, human, verbose=args.verbose)
            if preview.failures:
                print("\nResolve the items above (or re-run with --yes to proceed with the rest).", file=human)
            try:
                # the prompt goes to `human` too: with --json, stdout must stay parseable
                print("\nType 'yes' to apply these changes: ", end="", file=human, flush=True)
                answer = input().strip().lower()
            except EOFError:
                answer = ""
                print("\nNo interactive terminal; use --yes to apply without confirmation.", file=human)
            if answer != "yes":
                print("Aborted; nothing changed.", file=human)
                if args.json:
                    print(json.dumps({"ok": False, "mode": "apply", "exit_code": EXIT_USAGE, "cancelled": True,
                                      "diagnostics": [Diagnostic(code="SIA-CANCELLED", message="Apply cancelled before tenant changes.",
                                                                 actions=("Review the plan and run apply when ready.",), mutation_state="not_applied").to_dict()]}))
                return EXIT_USAGE
        args._mutation_started = not dry_run
        try:
            result = rec.reconcile(dry_run=dry_run)
        except (Exception, KeyboardInterrupt) as exc:
            result = getattr(exc, "partial_result", None)
            if result is None:
                raise
            run_stopped = True
    finally:
        try:
            if pvwa is not None:
                try:
                    pvwa.logoff()
                except KeyboardInterrupt:
                    if result is None:
                        raise
                    cleanup_interrupted = True
                except Exception as exc:
                    if result is None:
                        raise
                    cleanup_error = exc
        finally:
            if getattr(ctx, "http", None) is not None:
                ctx.http.cancel_check = previous_cancel
            if pvwa is not None:
                pvwa.cancel_check = previous_pvwa_cancel

    # From this point onward tenant work has stopped and ``result`` is the
    # authoritative evidence. Persist it before writing the final console view:
    # stdout/stderr may be a closed pipe even though the report directory works.
    outcomes = ([outcome for server in result.servers
                 for outcome in (server.secret, server.target_set, server.policy)]
                + list(result.secrets.values()) + list(result.vault.values()))
    confirmed = (any(outcome.status in ("created", "updated") or
                     (outcome.diagnostic or {}).get("mutation_state") == "applied" for outcome in outcomes)
                 or any(diagnostic.get("mutation_state") == "applied" for diagnostic in result.diagnostics))
    mutation_state = ("not_applied" if dry_run else
                      "unknown" if any(outcome.status == "uncertain" for outcome in outcomes) else
                      "applied" if confirmed else
                      "unknown" if any(outcome.status == "unverified" for outcome in outcomes) else "not_applied")
    if cleanup_interrupted:
        result.incomplete = True
        result.interrupted = True
        result.diagnostics.append(Diagnostic(
            code="SIA-INTERRUPTED",
            message="PVWA session cleanup was interrupted after tenant results were collected.",
            actions=("The PVWA session expires automatically; review the saved results before continuing.",),
            stage="PVWA logoff",
            mutation_state=mutation_state,
        ).to_dict())
    elif cleanup_error is not None:
        result.incomplete = True
        result.diagnostics.append(diagnose(
            cleanup_error,
            stage="PVWA logoff",
            mutation_state=mutation_state,
        ).to_dict())

    artifact_diagnostics = []
    report_outputs: tuple[Path, Path] | None = None
    report_interrupted = False
    if not args.no_report:
        try:
            report_outputs = write_reports(result, args.report_dir)
        except (Exception, KeyboardInterrupt) as exc:
            report_interrupted = isinstance(exc, KeyboardInterrupt) or bool(getattr(exc, "interrupted", False))
            base = diagnose(exc, stage="Saving reports", mutation_state=mutation_state)
            diagnostic = (Diagnostic(
                code="SIA-INTERRUPTED",
                message="Report publication was interrupted; tenant results were retained below.",
                actions=("Keep any completed report paths listed in the diagnostic, then run plan --drift before another apply.",),
                stage="Saving reports",
                mutation_state=mutation_state,
                details=base.details,
            ) if report_interrupted else base)
            artifact_diagnostics.append(diagnostic.to_dict())
            if report_interrupted:
                result.incomplete = True
                result.interrupted = True

    output_interrupted = False
    output_failed = False
    try:
        if run_stopped:
            print("\nRun stopped. Results below include completed and in-flight operations; pending writes were cancelled.", file=human)
        print_summary(result, human, verbose=args.verbose)
        if report_outputs is not None:
            print(f"\nReport: {report_outputs[0]}\n        {report_outputs[1]}", file=human)
        for item in artifact_diagnostics:
            render_diagnostic(Diagnostic(**item), human, verbose=args.verbose)
        if artifact_diagnostics:
            completed = tuple(path for item in artifact_diagnostics for path in item.get("details", {}).get("completed_paths", ()))
            if completed:
                print("Completed report output(s): " + ", ".join(map(str, completed)), file=human)
            print("The operation results above still apply. A report-saving failure does not undo tenant changes.", file=human)
        if not dry_run and checkpoint_path.is_file():
            print(f"Checkpoint: {checkpoint_path} ({checkpoint.done_count()} row(s) complete; re-run with --resume to skip them)",
                  file=human)
    except KeyboardInterrupt:
        output_interrupted = True
        result.incomplete = True
        result.interrupted = True
        result.diagnostics.append(Diagnostic(
            code="SIA-INTERRUPTED",
            message="Console output was interrupted after tenant results were collected.",
            actions=("Use the report files saved before console rendering to review the result.",),
            stage="Displaying results",
            mutation_state=mutation_state,
            details={"reports": [str(path) for path in report_outputs or ()]},
        ).to_dict())
    except OSError as exc:
        output_failed = True
        result.incomplete = True
        diagnostic = diagnose(exc, stage="Displaying results", mutation_state=mutation_state)
        result.diagnostics.append(replace(
            diagnostic,
            details={**diagnostic.details, "reports": [str(path) for path in report_outputs or ()]},
        ).to_dict())

    run_data = result_dict(result)
    if args.json:
        data = run_data
        data.setdefault("diagnostics", []).extend(artifact_diagnostics)
        json.dump(sanitize(data), sys.stdout, indent=2)
        print()
    args._diagnostics = run_data.get("diagnostics", []) + ([] if args.json else artifact_diagnostics)
    return (130 if result.interrupted or report_interrupted or output_interrupted else
            EXIT_FAILURES if artifact_diagnostics or output_failed else exit_code(result))


def cmd_verify(ctx: Context, args: argparse.Namespace) -> int:
    inputs = load_wave(ctx, args)
    resolver = PrincipalResolver(ctx.identity, inputs.pinned_directory, principal_type=ctx.cfg.defaults.principal_type)
    rec = Reconciler(sia=ctx.sia, uap=ctx.uap, resolver=resolver, inputs=inputs, defaults=ctx.cfg.defaults, dry_run=True,
                     drift=bool(args.drift), lookup=args.lookup, lookup_search_max_rows=ctx.cfg.http.lookup_search_max_rows,
                     workers=args.workers, status_polls=1, progress_every=0,
                     get_password=make_password_source(allow_prompt=False))
    result = rec.run()
    args._result_data = result_dict(result)
    args._result_data["mode"] = "verify"
    problems = print_verify(result, verbose=args.verbose)
    for row in result.servers:
        missing = [name for name, outcome in (("strong account", row.secret), ("target set", row.target_set), ("policy", row.policy))
                   if outcome.status == "planned"]
        if missing:
            diagnostic = Diagnostic(code="SIA-MISSING", message=f"Missing {', '.join(missing)} for {row.fqdn}.",
                                    actions=("Run plan with the same configuration and input/server options to review what is missing.",
                                             "Apply the reviewed plan, then run verify again."), stage="Verification", object_name=row.fqdn,
                                    mutation_state="not_applicable")
            args._result_data.setdefault("diagnostics", []).append(diagnostic.to_dict())
            render_diagnostic(diagnostic, sys.stdout, verbose=args.verbose)
    args._result_data["ok"] = not problems
    args._result_data["exit_code"] = EXIT_FAILURES if problems else EXIT_OK
    if args.out:
        path = write_verify_csv(result, args.out)
        print(f"CSV: {path}")
    return EXIT_FAILURES if problems else EXIT_OK


def cmd_connect_info(ctx: Context, args: argparse.Namespace) -> int:
    inputs = load_wave(ctx, args)
    d = ctx.cfg.defaults
    policy_names = {(s.fqdn, s.line): policy_name_for(s, d) for s in inputs.servers}
    statuses = None
    if not args.no_tenant:
        resolver = PrincipalResolver(ctx.identity, inputs.pinned_directory, principal_type=ctx.cfg.defaults.principal_type)
        rec = Reconciler(sia=ctx.sia, uap=ctx.uap, resolver=resolver, inputs=inputs, defaults=d, dry_run=True, drift=False,
                         lookup=args.lookup, lookup_search_max_rows=ctx.cfg.http.lookup_search_max_rows, workers=args.workers,
                         progress_every=0, get_password=make_password_source(allow_prompt=False))
        statuses = rec.run().by_key()
    rdp_dir = Path(args.rdp_dir) if args.rdp_dir else None
    rows = build_rows(inputs, ctx.cfg, policy_names, statuses, user=args.login_user,
                      suffix=login_suffix(ctx.cfg, getattr(ctx, "client_id", os.environ.get("SIA_CLIENT_ID", ""))),
                      network=args.network, rdp_dir=rdp_dir)
    out = Path(args.out) if args.out else Path(args.report_dir) / f"connect-info-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.csv"
    out, written = write_connection_outputs(rows, out, generated=not bool(args.out), generated_rdp=True)
    windows = [r for r in rows if r.rdp_username]
    print(f"connect-info: {len(rows)} row(s) for {len(inputs.unique_fqdns)} server(s) -> {out}")
    if windows:
        print(f"  RDP gateway: {windows[0].gateway_host}   portal: {windows[0].portal_url}")
        print(f"  example user name: {windows[0].rdp_username}")
    if written:
        print(f"  {len(written)} .rdp file(s) written to {rdp_dir}")
    if statuses is not None:
        missing = sum(1 for r in rows if r.policy_status not in ("exists", "n/a") or r.target_set_status not in ("exists", "n/a"))
        if missing:
            print(f"  NOTE: {missing} row(s) are not fully onboarded yet (see the status columns); run plan/apply first")
    args._result_data = {"mode": "connect-info", "ok": True, "tenant_checked": statuses is not None,
                         "output": str(out), "rdp_files": [str(path) for path in written], "rows": [asdict(row) for row in rows]}
    return EXIT_OK


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    logging.getLogger().setLevel(logging.DEBUG if verbose else logging.INFO)
    for handler in logging.getLogger().handlers:
        if not any(isinstance(f, RedactingFilter) for f in handler.filters):
            handler.addFilter(RedactingFilter())
    logging.getLogger("urllib3").setLevel(logging.DEBUG if verbose else logging.WARNING)


class OfflineContext:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.client_id = os.environ.get("SIA_CLIENT_ID", "")


def read_config(args: argparse.Namespace) -> Config:
    ca_bundle = getattr(args, "ca_bundle", None)
    system_trust = getattr(args, "system_trust", None)
    if not ca_bundle and system_trust is None:
        return load_config(args.config)
    from sia.settings import open_settings
    document = open_settings(args.config)
    if ca_bundle:
        document.set("http", "ca_bundle", str(Path(ca_bundle).resolve()))
        document.set("http", "verify", True)
    if system_trust is not None:
        document.set("http", "system_trust", system_trust)
    return document.validate()


def emit_failure(exc: BaseException, args, session: Session, *, code: int | None = None) -> int:
    interrupted = isinstance(exc, KeyboardInterrupt) or bool(getattr(exc, "interrupted", False))
    if code is None:
        code = 130 if interrupted else EXIT_USAGE if isinstance(exc, (ConfigError, InputError, EOFError)) else EXIT_FAILURES
    recorded_state = getattr(exc, "mutation_state", None)
    has_evidence = recorded_state in ("not_applied", "applied", "unknown", "not_applicable") or isinstance(exc, SIAApiError)
    mutation_state = "unknown" if getattr(args, "_mutation_started", False) and not has_evidence else None
    if isinstance(exc, (EOFError, KeyboardInterrupt)):
        diagnostic = Diagnostic(code="SIA-INTERRUPTED" if code == 130 else "SIA-CANCELLED",
                                message="Operation interrupted." if code == 130 else "Input closed; the operation was cancelled.",
                                actions=("Run plan --drift to check current state before continuing." if mutation_state else "Run the command again when ready.",),
                                mutation_state=mutation_state or "not_applied")
    else:
        diagnostic = diagnose(exc, stage=getattr(args, "command", "Command") or "Command", mutation_state=mutation_state)
        if interrupted:
            diagnostic = replace(
                diagnostic, code="SIA-INTERRUPTED", message="Output publication was interrupted.",
                actions=("Review any completed output paths listed in the diagnostic before running again.",
                         *diagnostic.actions),
            )
    session.last_diagnostics = [diagnostic.to_dict()]
    render_diagnostic(diagnostic, sys.stderr, verbose=getattr(args, "verbose", False))
    if _active_checkpoint is not None and _active_checkpoint.is_file() and mutation_state:
        print(f"Checkpoint: {_active_checkpoint}. Run plan --drift before using apply --resume.", file=sys.stderr)
    if getattr(args, "json", False):
        print(json.dumps({"ok": False, "mode": getattr(args, "command", None), "exit_code": code,
                          "diagnostics": session.last_diagnostics}, indent=2))
    log.debug("diagnostic traceback:\n%s", redact("".join(traceback.format_exception(exc))))
    return code


def run_doctor(args, session: Session) -> int:
    from sia.doctor import local_checks, print_checks
    checks, cfg = local_checks(args, session, load_config=read_config,
                               load_inputs=lambda cfg, args: load_wave(OfflineContext(cfg), args))
    human = sys.stderr if args.json else sys.stdout
    print_checks(checks, out=human, verbose=args.verbose)
    if args.online and cfg is not None:
        online_checks: list[dict] = []
        try:
            with session.environment(args.env), redirect_stdout(human):
                cmd_preflight(Context(cfg), online_checks, verbose=args.verbose)
        except Exception as exc:
            diagnostic = diagnose(exc, stage="Tenant authentication")
            render_diagnostic(diagnostic, human, verbose=args.verbose)
            online_checks.append({"name": "Tenant authentication", "status": "failed", "message": diagnostic.message,
                                  "diagnostic": diagnostic.to_dict()})
        checks.extend(online_checks)
    else:
        check = {"name": "Tenant checks", "status": "not checked", "message": "Fix configuration first." if args.online else "Use doctor --online or preflight to check tenant access."}
        checks.append(check)
        print(f"[NOT CHECKED] {check['name']}: {check['message']}", file=human)
    code = EXIT_FAILURES if any(check["status"] == "failed" for check in checks) else EXIT_OK
    session.last_diagnostics = [check["diagnostic"] for check in checks if check.get("diagnostic")]
    print("\nDoctor: " + ("some checks need attention" if code else "checks completed; review warnings and items not checked"), file=human)
    if args.json:
        print(json.dumps(sanitize({"ok": code == 0, "mode": "doctor", "exit_code": code, "checks": checks}), indent=2))
    return code


def execute(args: argparse.Namespace, session: Session) -> int:
    """One command boundary used by both the shell and the original CLI."""
    global _active_checkpoint
    _active_checkpoint = None
    session.last_diagnostics = []
    token = _secret_sink.set(session.secrets)
    configure_logging(args.verbose)
    try:
        if args.command == "help":
            from sia.help import help_text
            content = help_text(args.topic)
            print(json.dumps({"topic": args.topic, "help": content}) if args.json else content)
            return EXIT_OK
        if args.command in ("settings", "setup", "shell"):
            from sia import terminal
            if args.command == "settings" and args.show:
                return terminal.settings(args, session)
            if not (sys.stdin.isatty() and sys.stdout.isatty()) or args.json:
                raise ConfigError("This screen needs an interactive terminal. Use 'sia settings --show', 'sia doctor --json', or an explicit command in scripts.")
            try:
                if args.command == "setup":
                    return terminal.setup(args, session)
                if args.command == "settings":
                    return terminal.settings(args, session)
                shared = ["--config", args.config, "--env", args.env, "--report-dir", args.report_dir]
                if args.ca_bundle:
                    shared += ["--ca-bundle", args.ca_bundle]
                if args.system_trust is not None:
                    shared.append("--system-trust" if args.system_trust else "--no-system-trust")
                if args.verbose:
                    shared.append("--verbose")
                def run(argv: list[str]) -> int:
                    try:
                        child = build_parser().parse_args([*shared, *argv])
                    except ConfigError as exc:
                        return emit_failure(exc, args, session)
                    except SystemExit as exc:
                        # argparse uses SystemExit after --help. Finish this child
                        # command without terminating the surrounding home session.
                        return int(exc.code or 0)
                    return execute(child, session)
                return terminal.home(args, session, run)
            except terminal.Cancelled:
                print("Cancelled; pending settings were not saved.")
                return EXIT_USAGE
        if args.command == "doctor":
            return run_doctor(args, session)
        cfg = read_config(args)
        if args.command in ("plan", "apply", "verify", "connect-info"):
            # Every CSV is validated before authentication or tenant reads.
            args._loaded_inputs = load_wave(OfflineContext(cfg), args)
        if getattr(args, "set_policy_status", None) and (not args.update or args.only not in ("all", "policies")):
            raise ConfigError("--set-policy-status requires --update and --only all or policies. Preview the selected status change with plan first.")
        with session.environment(args.env):
            ctx = OfflineContext(cfg) if args.command == "connect-info" and args.no_tenant else Context(cfg)
            if args.command == "preflight":
                checks: list[dict] = []
                with redirect_stdout(sys.stderr if args.json else sys.stdout):
                    code = cmd_preflight(ctx, checks, verbose=args.verbose)
                session.last_diagnostics = [c["diagnostic"] for c in checks if c.get("diagnostic")]
                if args.json:
                    print(json.dumps(sanitize({"ok": code == 0, "mode": "preflight", "exit_code": code, "checks": checks}), indent=2))
                return code
            if args.command == "show-policy":
                return cmd_show_policy(ctx, args.name, args.from_list)
            if args.command == "verify":
                with redirect_stdout(sys.stderr if args.json else sys.stdout):
                    code = cmd_verify(ctx, args)
                session.last_diagnostics = args._result_data.get("diagnostics", [])
                if args.json:
                    print(json.dumps(sanitize(args._result_data), indent=2))
                return code
            if args.command == "connect-info":
                with redirect_stdout(sys.stderr if args.json else sys.stdout):
                    code = cmd_connect_info(ctx, args)
                if args.json:
                    print(json.dumps(sanitize(args._result_data), indent=2))
                return code
            code = cmd_plan_apply(ctx, args, dry_run=(args.command == "plan"))
            session.last_diagnostics = getattr(args, "_diagnostics", [])
            return code
    except (Exception, KeyboardInterrupt) as exc:
        return emit_failure(exc, args, session)
    finally:
        _secret_sink.reset(token)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    session = Session()
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except ConfigError as exc:
        args = argparse.Namespace(command=None, json="--json" in argv, verbose="-v" in argv or "--verbose" in argv)
        return emit_failure(exc, args, session, code=EXIT_USAGE)
    except SystemExit as exc:
        return int(exc.code or 0)
    if args.command is None:
        if not (sys.stdin.isatty() and sys.stdout.isatty()) or args.json:
            if args.json:
                return emit_failure(ConfigError("Choose a command, for example: sia doctor --json."), args, session, code=EXIT_USAGE)
            parser.print_help()
            return EXIT_USAGE
        args.command = "shell"
        args.input = "input"
    return execute(args, session)


if __name__ == "__main__":
    sys.exit(main())
