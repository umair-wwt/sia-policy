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

import argparse
import getpass
import json
import logging
import os
import sys
import traceback
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from sia.auth import AuthError, PlatformTokenProvider, make_identity_token_provider
from sia.checkpoint import DEFAULT_NAME as CHECKPOINT_NAME
from sia.checkpoint import Checkpoint
from sia.clients import IdentityClient, SIAClient, UAPClient
from sia.config import Config, ConfigError, load_config, load_dotenv, load_password_file, validate
from sia.connect import build_rows, login_suffix, write_connect_csv, write_rdp_files
from sia.http import HttpClient, RateLimiter, SIAApiError
from sia.inputs import LIST_SEPARATOR, InputError, Inputs, StrongAccountRow, inline_inputs, load_inputs
from sia.payloads import policy_name_for
from sia.pvwa import PVWAClient
from sia.reconcile import LOOKUP_MODES, MAX_WORKERS, STAGES, ReconcileError, Reconciler
from sia.redact import RedactingFilter, redact, register_secret
from sia.report import exit_code, print_summary, print_verify, result_dict, write_reports, write_verify_csv
from sia.resolve import PrincipalResolver, pick

EXIT_OK, EXIT_FAILURES, EXIT_USAGE = 0, 1, 2
PAM_REQUIRED_FIELDS = (("pvwa_base_url", "pvwaBaseUrl"), ("connector_pool_id", "connectorPoolId"),
                       ("service_user_secret_id", "serviceUserSecretId"))
MAX_PASSWORD_PROMPTS = 5
log = logging.getLogger("sia")
_active_checkpoint: Path | None = None


def interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def resolve_client_secret() -> str:
    secret = os.environ.get("SIA_CLIENT_SECRET", "")
    if not secret and interactive():
        secret = getpass.getpass("SIA_CLIENT_SECRET (not echoed): ")
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
        verify = cfg.http.tls_verify
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
        self.uap = UAPClient(self.http, cfg.tenant.uap_url)
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
                password = getpass.getpass(f"PVWA_PASSWORD for {user or 'PVWA user'} (not echoed): ")
            if not user or not password:
                raise ConfigError("[pvwa] is configured but PVWA_USER / PVWA_PASSWORD are not set (put them in .env)")
            client = PVWAClient(self.cfg.pvwa.base_url, auth_type=self.cfg.pvwa.auth_type,
                                timeout=self.cfg.http.timeout_seconds, verify=self.cfg.http.tls_verify)
            client.logon(user, password)
            self._pvwa = client
        return self._pvwa


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sia_onboard.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default="config.toml", help="path to config.toml (default: ./config.toml)")
    parser.add_argument("--env", default=".env", help="path to .env with SIA_CLIENT_ID/SIA_CLIENT_SECRET (default: ./.env)")
    parser.add_argument("--report-dir", default="reports", help="where plan/apply reports are written (default: ./reports)")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging (HTTP method/URL/status; never secrets)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("preflight", help="authenticate and read tenant state (read-only)")
    sp = sub.add_parser("show-policy", help="print an existing UAP policy as JSON")
    sp.add_argument("name")
    sp.add_argument("--from-list", action="store_true", help="print the (partial) object the list endpoint returns instead of the full policy")

    parser.add_argument("--ca-bundle", metavar="FILE", help="PEM file (or directory) of trusted CAs; overrides [http] ca_bundle")

    def add_input_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument("--input", default="input", help="directory with servers.csv[, domains.csv, strong_accounts.csv, groups.csv]")
        p.add_argument("--server", action="append", default=[], metavar="FQDN",
                       help="onboard this server instead of reading servers.csv (repeatable); the other CSVs are still read")
        p.add_argument("--group", action="append", default=[], metavar="NAME",
                       help="--server only: Identity group that may connect (repeatable); omit to use group_template")
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
        p.add_argument("--json", action="store_true",
                       help="print the run as JSON on stdout (the table goes to stderr); for scripted callers")
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
    return parser


def cmd_preflight(ctx: Context) -> int:
    ok = True
    t = ctx.cfg.tenant
    print(f"Tenant:   {t.subdomain}  SIA={t.dpa_url}  UAP={t.uap_url}  Identity={t.identity_url}")
    tls = ctx.cfg.http.tls_verify
    if tls is True:
        trust = "certifi (default trust store)"
    elif tls is False:
        trust = "VERIFICATION OFF -- traffic to the tenant is not authenticated"
    else:
        trust = f"CA bundle {tls}"
    print(f"TLS:      {trust}")
    try:
        token = ctx.token()
        claims = ctx.token.claims
        print(f"Auth:     OK platform token ({len(token)} chars, subject={claims.get('unique_name') or claims.get('sub') or '?'})")
        claimed = claims.get("subdomain")
        if claimed and str(claimed).lower() != t.subdomain:
            print(f"          WARNING: token says subdomain={claimed!r} but config says {t.subdomain!r}")
    except AuthError as exc:
        print(f"Auth:     FAILED: {exc}")
        return EXIT_FAILURES

    def settings() -> None:
        try:
            s = ctx.sia.get_settings()
        except SIAApiError as exc:
            if exc.status in (401, 403):
                print(f"Settings: not verified (HTTP {exc.status}: the service user lacks the Settings API role; this check is optional)")
                return
            raise
        pam = pick(s, "self_hosted_pam", "selfHostedPam", default=None)
        if not pam:
            print("Settings: OK  self_hosted_pam: not configured -- vault strong accounts need the PAM integration configured in SIA")
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

    def api_families() -> None:
        probe = getattr(ctx.sia, "probe", None)
        if probe is None:
            print("SIA API:  not probed")
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
        except ValueError as exc:
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
            return
        client = ctx.pvwa_client()
        print(f"PVWA:     OK  logged on to {ctx.cfg.pvwa.base_url} (auth={ctx.cfg.pvwa.auth_type}, platform={ctx.cfg.pvwa.platform_id})")
        if client is not None:
            client.logoff()

    for label, fn in (("Settings:", settings), ("SIA API:", api_families), ("Secrets:", secrets), ("Targets:", target_sets),
                      ("Policies:", policies), ("Identity:", directories), ("PVWA:", pvwa)):
        try:
            fn()
        except (SIAApiError, AuthError, ConfigError) as exc:
            ok = False
            print(f"{label:<9} FAILED: {exc}")
    print("\nPreflight", "OK" if ok else "finished with failures")
    return EXIT_OK if ok else EXIT_FAILURES


def cmd_show_policy(ctx: Context, name: str, from_list: bool = False) -> int:
    found = ctx.uap.find_policy_by_name(name)
    if not found:
        print(f"policy {name!r} not found", file=sys.stderr)
        return EXIT_FAILURES
    policy_id = pick(found.get("metadata") or {}, "policyId", "policy_id")
    policy = found if from_list or not policy_id else ctx.uap.get_policy(str(policy_id))
    print(json.dumps(policy, indent=2, sort_keys=True))
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
                value = getpass.getpass(f"Password for strong account {account.name} (user {account.username}, not echoed): ")
                cache[account.name] = value
            elif len(prompted) == max_prompts:
                prompted.append("-")
                print(f"More than {max_prompts} passwords are missing; add them to the password file (--passwords) instead of typing them.",
                      file=sys.stderr)
        if value:
            register_secret(value)
        return value or None

    return get_password


SERVER_ONLY_FLAGS = (("group", "--group"), ("strong_account", "--strong-account"), ("server_domain", "--server-domain"),
                     ("workgroup", "--workgroup"), ("protocol", "--protocol"), ("ssh_username", "--ssh-username"))


def check_server_flags(args: argparse.Namespace) -> None:
    """These flags describe the row --server builds. Without --server they would silently do nothing."""
    if args.server:
        return
    used = [flag for attr, flag in SERVER_ONLY_FLAGS if getattr(args, attr, None)]
    if used:
        raise ConfigError(f"{', '.join(used)} only apply together with --server; without it the servers and their "
                          "groups come from servers.csv")


def inline_rows(args: argparse.Namespace) -> list[dict[str, str]]:
    """--server FQDN [...] as servers.csv rows, so both paths run through the same validation."""
    shared = {
        "group": LIST_SEPARATOR.join(args.group),
        "strong_account": args.strong_account or "",
        "domain": args.server_domain or "",
        "protocol": args.protocol or "",
        "ssh_username": args.ssh_username or "",
        "domain_joined": "no" if args.workgroup else "",
    }
    return [{"fqdn": fqdn, **shared} for fqdn in args.server]


def load_wave(ctx: Context, args: argparse.Namespace) -> Inputs:
    d = ctx.cfg.defaults
    check_server_flags(args)
    common = dict(strong_account_template=d.strong_account_spec or "", ssh_username_default=d.ssh_username,
                  policy_name_template=d.policy_name_template, group_template=d.group_template,
                  target_set_scope=d.target_set_scope)
    if args.server:
        inputs = inline_inputs(args.input, inline_rows(args), **common)
    else:
        inputs = load_inputs(args.input, **common)
    total = len(inputs.unique_fqdns)
    if args.offset or args.limit:
        if args.offset < 0 or args.limit < 0:
            raise ConfigError("--offset and --limit must be >= 0")
        inputs = inputs.window(args.offset, args.limit or None)
    log.info("Loaded %d rows for %d servers (%d ssh), %d strong accounts, %d pinned groups%s", len(inputs.servers),
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
    if checkpoint_path.is_file():
        finished = checkpoint.done_count()
        if finished and not args.resume:
            log.info("checkpoint %s records %d finished row(s); pass --resume to skip them", checkpoint_path, finished)
    if not dry_run:
        _active_checkpoint = checkpoint_path
    resolver = PrincipalResolver(ctx.identity, inputs.pinned_directory)
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
                     get_password=make_password_source(allow_prompt=not dry_run, file_passwords=file_passwords))
    try:
        rec.snapshot()
        if not dry_run and not args.yes:
            preview = rec.reconcile(dry_run=True)
            print_summary(preview, human)
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
                return EXIT_USAGE
        result = rec.reconcile(dry_run=dry_run)
    finally:
        if pvwa is not None:
            pvwa.logoff()
    print_summary(result, human)
    if not args.no_report:
        json_path, csv_path = write_reports(result, args.report_dir)
        print(f"\nReport: {json_path}\n        {csv_path}", file=human)
    if not dry_run and checkpoint_path.is_file():
        print(f"Checkpoint: {checkpoint_path} ({checkpoint.done_count()} row(s) complete; re-run with --resume to skip them)",
              file=human)
    if args.json:
        json.dump(result_dict(result), sys.stdout, indent=2)
        print()
    return exit_code(result)


def cmd_verify(ctx: Context, args: argparse.Namespace) -> int:
    inputs = load_wave(ctx, args)
    resolver = PrincipalResolver(ctx.identity, inputs.pinned_directory)
    rec = Reconciler(sia=ctx.sia, uap=ctx.uap, resolver=resolver, inputs=inputs, defaults=ctx.cfg.defaults, dry_run=True,
                     drift=bool(args.drift), lookup=args.lookup, lookup_search_max_rows=ctx.cfg.http.lookup_search_max_rows,
                     workers=args.workers, status_polls=1, progress_every=0,
                     get_password=make_password_source(allow_prompt=False))
    result = rec.run()
    problems = print_verify(result)
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
        resolver = PrincipalResolver(ctx.identity, inputs.pinned_directory)
        rec = Reconciler(sia=ctx.sia, uap=ctx.uap, resolver=resolver, inputs=inputs, defaults=d, dry_run=True, drift=False,
                         lookup=args.lookup, lookup_search_max_rows=ctx.cfg.http.lookup_search_max_rows, workers=args.workers,
                         progress_every=0, get_password=make_password_source(allow_prompt=False))
        statuses = rec.run().by_key()
    rdp_dir = Path(args.rdp_dir) if args.rdp_dir else None
    rows = build_rows(inputs, ctx.cfg, policy_names, statuses, user=args.login_user,
                      suffix=login_suffix(ctx.cfg, getattr(ctx, "client_id", os.environ.get("SIA_CLIENT_ID", ""))),
                      network=args.network, rdp_dir=rdp_dir)
    out = Path(args.out) if args.out else Path(args.report_dir) / f"connect-info-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.csv"
    write_connect_csv(rows, out)
    written = write_rdp_files(rows) if rdp_dir else []
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
    return EXIT_OK


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    for handler in logging.getLogger().handlers:
        handler.addFilter(RedactingFilter())
    if not verbose:
        logging.getLogger("urllib3").setLevel(logging.WARNING)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose)
    try:
        load_dotenv(args.env)
        cfg = load_config(args.config)
        if args.ca_bundle:
            cfg = replace(cfg, http=replace(cfg.http, ca_bundle=args.ca_bundle, verify=True))
            validate(cfg)
        ctx = Context(cfg)
        if args.command == "preflight":
            return cmd_preflight(ctx)
        if args.command == "show-policy":
            return cmd_show_policy(ctx, args.name, args.from_list)
        if args.command == "verify":
            return cmd_verify(ctx, args)
        if args.command == "connect-info":
            return cmd_connect_info(ctx, args)
        return cmd_plan_apply(ctx, args, dry_run=(args.command == "plan"))
    except (ConfigError, InputError) as exc:
        print(f"error: {redact(str(exc))}", file=sys.stderr)
        return EXIT_USAGE
    except (AuthError, ReconcileError) as exc:
        print(f"error: {redact(str(exc))}", file=sys.stderr)
        return EXIT_FAILURES
    except SIAApiError as exc:
        print(f"API error: {exc}", file=sys.stderr)
        return EXIT_FAILURES
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        if _active_checkpoint is not None and _active_checkpoint.is_file():
            print(f"rows finished so far are recorded in {_active_checkpoint}; re-run apply with --resume", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - last resort: never leak a raw traceback (or a secret) to the terminal
        log.debug("unexpected error:\n%s", redact(traceback.format_exc()))
        print(f"unexpected error: {exc.__class__.__name__}: {redact(str(exc))} (run with -v for details)", file=sys.stderr)
        return EXIT_FAILURES


if __name__ == "__main__":
    sys.exit(main())
