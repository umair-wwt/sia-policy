# sia-policy-automation

Configure and onboard Windows/RDP and Linux/SSH access into CyberArk / Idira **Secure Infrastructure Access
(SIA)** from a guided terminal or CSV files.

For every server it creates the three things SIA needs for zero-standing-privilege RDP: the server's **strong
account** (its local administrator, referenced from your Vault), a **target set**, and an **access policy** named
after the server. It can process small lists or controlled waves from larger inventories, can be run again without
changing objects that already match, and can reconcile safely after an interruption.

```text
sia                          # terminal home: setup, settings, help and workflows
sia setup                    # guided local configuration
sia doctor                   # offline checks; add --online for read-only tenant checks
sia plan  --input input      # what would change? (changes nothing)
sia apply --input input      # do it after showing the plan and asking for confirmation
sia verify --input input     # is every server ready? PASS / FAIL
```

SIA creates your local `config.toml` from the [bundled starter](sia/config.toml): fill in your tenant details
through Setup or edit it directly. The local file is excluded from Git and contains no credentials.
[config.example.toml](config.example.toml) is the longer advanced reference.

Run `sia` for the terminal home. It shows the next setup step and explains each command. Type `/` to see
suggestions, use **Tab** to complete, **↑/↓** to select, and **Enter** to run. `/settings` groups related settings
and lets you search by name, such as `timeout`. File prompts complete paths too. `/menu` shows the menu again;
`/exit` closes SIA. The existing `python sia_onboard.py ...` form remains supported for scripts.

## How it works

```mermaid
flowchart TB
    G["Identity role<br/>SIA-Web-Admins<br/><i>already in place</i>"]
    subgraph tool["Created by the tool, per server"]
        direction TB
        P["1. Access policy<br/>web01.corp.example.com<br/>who may connect, RDP with a temporary local user, when"]
        T["2. Target set<br/>web01.corp.example.com"]
        A["3. Strong account<br/>reference to the server's local admin in the Vault"]
    end
    V["Vault account<br/>web01-Administrator in safe SIA-LocalAdmins<br/><i>already in place</i>"]
    S["Windows server<br/>web01.corp.example.com<br/><i>already in place</i>"]
    G -- "may connect through" --> P
    P -. "same name" .-> T
    T -- "uses" --> A
    A -- "password from" --> V
    A -- "creates the temporary user on" --> S
```

For each Windows server in your list the tool:

1. makes sure SIA has a **strong account** for it — either the shared account for the server's AD domain
   (listed once per domain in `domains.csv`), or a reference to the server's own local admin account in the
   Vault, found by a naming convention you set once (safe `SIA-LocalAdmins`, account `<hostname>-Administrator`);
2. creates a **target set** pointing at that account: one per server, or one per AD domain when the account is
   shared;
3. creates the **access policy**: which Identity role (or group) may connect, by RDP with a temporary local user, for how long.

Linux servers get only a policy (SIA uses an SSH certificate there). A second role on the same server is just a
second row with a `policy_suffix`.

**When a user connects**, they open **Access › Infrastructure** in the portal, search the server, and click
**Connect › RDP**. SIA finds the policy, uses the strong account to create a temporary local user on the server,
opens the session, and deletes that user when the session ends (after 2 hours, or 10 idle minutes, by default).
Nobody types a password. `connect-info` exports the same connection for RDP clients (gateway
`<subdomain>.rdp.cyberark.cloud`, user name `secureaccess /i alice@acme.cyberark.cloud /s acme /a web01.corp.example.com`).
Details: [How a user connects](docs/OPERATIONS.md#2-how-a-user-connects).

## Install

### Windows: open one file

1. Get the tool: **Code → Download ZIP** on GitHub, or `git clone https://github.com/umair-wwt/sia-policy.git`.
   **Extract the ZIP completely** into a writable folder, such as Documents.
2. Double-click **`install.cmd`**. Or, from PowerShell in that folder, run:

   ```powershell
   .\install.cmd
   ```

   Setup runs the PowerShell installer first and automatically tries another available route if that host cannot
   run it. It finds Python 3.11 or newer, installs Python for your user if needed, installs the app's dependencies,
   checks the result, and opens SIA. No environment activation, administrator terminal, or permanent execution-policy
   change is needed. Internet access is needed on a fresh computer unless IT has supplied Python and offline packages.

   **Next time, double-click `Start-SIA.cmd`.** It checks the app and automatically attempts repair if the runtime is
   missing, damaged, or out of date with the source. Keep these launchers with the extracted project. For scripted
   commands, use `.\Start-SIA.cmd doctor`. Commands beginning with
   `sia` elsewhere in this README can use `.\Start-SIA.cmd` instead; no PATH setup is required.

   See the [Windows guide](docs/WINDOWS.md) for automatic fallbacks, offline packages, updates, and managed computers.

### macOS / Linux

With Python 3.11 or newer installed, open a terminal in the extracted project:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/sia
```

Use `.venv/bin/sia` again in a new terminal, or activate `.venv` to use the shorter `sia` command.

### First setup

1. In SIA, choose `/setup`. The bundled starter starts with blank tenant fields, so it cannot
   accidentally connect to an example tenant. Setup explains the defaults, lets you customize them, and shows a
   short summary before saving. When launched from a folder without this file, SIA creates a bundled starter;
   it never overwrites an existing configuration. The starter leaves `strong_account_template` blank, so every
   row of `servers.csv` has to name its strong account until you switch on the naming convention shown here.
   You can also edit the generated local file directly:

   ```toml
   [tenant]
   subdomain    = "acme"                                # from https://acme.cyberark.cloud
   identity_url = "https://abc1234.id.cyberark.cloud"   # Identity Administration › Settings › Customization › Tenant URLs

   [defaults]
   time_zone = "America/New_York"
   days_of_week = [0, 1, 2, 3, 4, 5, 6]                 # when users may connect (0 = Sunday)
   from_hour = ""                                       # "" = all day
   to_hour = ""
   target_set_cert_validation = false                   # true once servers have valid WinRM certificates
   strong_account_template = "ADM-{hostname}"           # name of each server's strong account in SIA; blank = every row must name one
   strong_account_type = "vault"                        # vault = a reference to the server's local admin in your Vault
   strong_account_safe_template = "SIA-LocalAdmins"     # where the servers' local admin accounts live in the Vault
   strong_account_account_name_template = "{hostname}-Administrator"   # their account name in the Vault
   strong_account_username_template = "Administrator"   # their Windows user name
   ```

2. Configure the service user (an Identity user flagged **Is OAuth confidential client**, member of the **Secure
   Infrastructure Access administrator** role, `DpaAdmin` — the SIA administrator role, not one of the Identity
   roles a policy grants access to). From the terminal home, credentials can stay in memory for that
   home session or be explicitly saved to `.env`. Standalone setup offers explicit `.env` saving. You may instead
   copy `.env.example` to `.env`:

   ```dotenv
   SIA_CLIENT_ID=svc_sia_automation@acme.cyberark.cloud
   SIA_CLIENT_SECRET=its-password
   ```

   Paste the secret unquoted and it is stored exactly as typed, backslashes included — a
   password like `p@ss\word` needs no escaping. Quote it only when it starts or ends with a
   space or contains ` #`; quotes delimit rather than escape, so a backslash is never doubled
   and only a doubled quote is special (`"it""s"` is `it"s`). Save `.env` as UTF-8 —
   PowerShell's `>`, `Out-File` and `Set-Content` write UTF-16 unless given
   `-Encoding utf8`. Entering the credential under Settings > Credentials avoids all of this.

   Exported environment variables take precedence over session and `.env` values. `sia settings --show` reports
   whether each credential is set and which source wins, without printing its value. Windows saves automatically
   protect `.env` with a private file ACL. If that protection cannot be established before saving, the terminal home
   keeps the entered credentials in memory for the session and explains the fallback. Do not share `.env`.
3. Check local files first, then the tenant:

   ```text
   sia doctor
   sia doctor --online
   sia preflight
   ```

   Offline `doctor` needs no credentials. Online checks and `preflight` report each endpoint separately; an optional
   settings endpoint may be `not verified` while required checks pass. If a check fails, see
   [Troubleshooting](docs/OPERATIONS.md#8-troubleshooting).

**Before the first server**, three things must be true on your side: a local administrator account for every
server exists in the Vault under the naming convention above (the tool can onboard missing ones through PVWA, see
the operations guide), the SIA connectors reach the servers over WinRM (TCP 5985/5986), and local accounts have
`LocalAccountTokenFilterPolicy = 1` (a GPO setting).

## Your list: `input/servers.csv`

One row per policy. Usually that is one row per server; a second role gets a second row.

```csv
fqdn,strong_account,principal,policy_name,policy_suffix,assign_groups,domain,description,protocol,ssh_username,domain_joined
web01.corp.example.com,,SIA-Web-Admins,,,,,,,,
web01.corp.example.com,,SIA-Platform-Ops,,-ops,Remote Desktop Users,,,,,
web02.corp.example.com,,SIA-Web-Admins,,,,,,,,
app-lnx01.corp.example.com,,SIA-Linux-Admins,,,,,,ssh,ec2-user,
```

| Column | Fill in |
|---|---|
| `fqdn` | The server name exactly as users will connect to it. **The only required column.** |
| `principal` | The Identity role that may connect (several: `SIA-Web-Admins;SIA-Platform-Ops`); with `principal_type = "group"` in `config.toml` it names an Identity group instead. Leave empty to derive it from the server name — see below. Not needed with `--accounts`. |
| `policy_suffix` | Only for a second policy on the same server, e.g. `-ops`. |
| `assign_groups` | Local groups the temporary user joins; empty = `Administrators`. |
| `protocol`, `ssh_username` | `ssh` and the certificate user name for Linux servers; empty = Windows/RDP. |
| `strong_account` | Leave empty. Only for the few servers that need a specific account declared in `strong_accounts.csv`. |
| `domain_joined` | `no` for a workgroup server, so it gets its own local account instead of its domain's. |
| `policy_name`, `domain`, `description` | Optional overrides; the example file shows them. |

Column names must match exactly; every problem is reported with its line number and nothing is touched until
the files are clean.

## Deriving the principal and the strong account

Filling in a principal and a strong account per server does not scale past a few hundred rows. Two conventions
remove both columns.

**The principal comes from the server name.** Set it once in `config.toml`:

```toml
[defaults]
principal_template = "SIA-{hostname_upper}-RDP"     # server ABC123 -> role SIA-ABC123-RDP
```

Templates may use `{hostname}`, `{fqdn}`, `{domain}` and the `{hostname_upper}` / `{hostname_lower}` /
`{domain_upper}` variants. A `principal` typed into a row always wins.

**The strong account comes from the server's AD domain.** List your domains once in `input/domains.csv`:

```csv
domain,strong_account,target_set,target_set_type,principal_template,description
corp.example.com,SA-CORP-SIA,,Domain,,
dmz.example.com,SA-DMZ-SIA,,Domain,SIA-{hostname_upper}-DMZ,
```

| Column | Fill in |
|---|---|
| `domain` | The AD domain, exactly as it appears at the end of the servers' FQDNs. |
| `strong_account` | The domain account already onboarded into SIA. The tool only looks it up — it never creates it. |
| `target_set` | The target set holding that account; empty = the domain name. |
| `target_set_type` | `Domain` (every machine in the domain, the default) or `Suffix` (every machine under a DNS suffix). `Target` scopes a set to one machine, so it is only valid together with an explicit `target_set`. |
| `principal_template` | Overrides `[defaults] principal_template` for this domain only. |

Then `servers.csv` is just a list of names, and `strong_accounts.csv` is only needed for the exceptions:

```csv
fqdn
web01.corp.example.com
web02.corp.example.com
```

**How a server picks its strong account**, in order: the `strong_account` cell → its domain's row in
`domains.csv` (domain-joined servers only) → `[defaults] strong_account_template`, the per-host local
administrator. So a workgroup server (`domain_joined = no`) always falls through to its own local account,
and both kinds can sit in the same file.

**One target set per domain instead of one per server.** A domain account works on every machine in its
domain, so it does not need a target set per server. Set `target_set_scope = "auto"` in `config.toml` and
each domain gets a single `Domain` target set — 24 objects instead of 24,000. Workgroup servers keep their
own `Target` set. The default, `server`, keeps one target set per server for everyone.

`groups.csv` (`name,directory`) is only read for group principals (`principal_type = "group"`), when a group name
exists in two directories. Roles are unique in the tenant and need no pin.

### Migrating from group principals

Policies created by earlier releases name an Identity **group**. After upgrading, `sia plan --input input` lists
every managed policy as `drift: principals differ (… (GROUP) -> … (ROLE))`; `sia apply --input input --update`
replaces the group with the role of the same name (create the roles first, or set `principal_template`
accordingly). To keep the old behaviour, set `principal_type = "group"` in `config.toml`. Old column and key
names are rejected with a message that names the replacement: `group` → `principal`, `group_template` →
`principal_template`, `--group` → `--principal`. `groups.csv` is only read for group principals, and the
`connect-info` CSV column `groups` is now `principals`. Checkpoint rows written before the upgrade are reconciled
again.

## Settings and paths

`sia settings` opens the editor; `sia settings --show` prints every setting, its saved value, its effective value
and whether it came from the config file, a tool default or a command-line override. Related settings appear in
small groups; search reaches every supported TOML field. Comments and unrelated TOML content are preserved, changes
are validated before an atomic save, and an external edit made while the screen is open stops the save.
Reload merges unrelated external changes into your pending edits; when the same field changed in both places,
choose which value to keep and review again before saving.

Setup validates each entry immediately. If a URL contains a path, trailing slash, or missing HTTPS scheme, it
offers a corrected base URL for you to accept. `/back` returns one screen; `/cancel` returns home. Unsaved,
non-secret Setup and Settings drafts stay available for that home session, shared by both editors for the same
config file. They are not written to disk and disappear when the process exits. Every settings group is available
from Setup's review screen, so a validation error always has a repair or reload route. Credentials are saved
separately and are never included in configuration drafts.

Values supplied by `template_policy` take precedence for the approved access-window, session, connection-profile,
time-zone and tag fields. CSV cells still take precedence where the input format documents an override, such as
`group`, `assign_groups` and `ssh_username`. The settings screen explains when each field applies.

Relative `password_file` and `ca_bundle` paths written in TOML resolve beside that TOML file. Relative paths passed
on the command line, including `--config`, `--env`, `--input` and `--report-dir`, resolve from the directory where
you run the command. This TOML behavior is different from older releases; check a moved config with
`sia settings --show` or `sia doctor`.

## Run it

**`plan`** shows one line per row and changes nothing:

```text
Servers:
  Server                      Strong account  Policy                      Secret   Target set  Policy
  web01.corp.example.com      ADM-web01       web01.corp.example.com      planned  planned     planned
  web01.corp.example.com      ADM-web01       web01.corp.example.com-ops  planned  planned     planned
  web02.corp.example.com      ADM-web02       web02.corp.example.com      planned  planned     planned
  app-lnx01.corp.example.com  -               app-lnx01.corp.example.com  n/a      n/a         planned

Summary: n/a=1, planned=8
```

**`apply`** shows the plan again, asks you to type `yes`, then creates the objects in order (strong accounts,
target sets, policies) and prints the same table with `created`. Run it again and everything says `exists`.
Anything that differs from your list is shown as `drift`, never changed silently. Add `--drift` to fetch complete
policies and compare every managed field the tool writes: descriptions, tags, time frame, time zone, principals
(directory metadata for group principals only), entitlement, delegation, conditions, targets, and RDP/SSH behavior
including local groups and reconnect. A field only the tenant carries (one the tool never writes) is a note, not
drift, and `--update` preserves it. Target-set type, account, description, certificate validation and provisioning format are also compared.
`--update` implies this full comparison.

`policy_status` in TOML is used only when a policy is created. To activate or suspend existing managed policies,
make the intent explicit and review it before applying:

```text
sia plan  --input input --update --set-policy-status Suspended
sia apply --input input --update --set-policy-status Suspended
```

The status action requires `--update`; normal updates preserve an existing `Active` or `Suspended` status.
When correcting fields on a policy in a platform-managed state such as `Error` or `Validating`, the update requests
the configured `policy_status`; the plan shows this status change.

**`verify`** prints `PASS`, `MISSING` or `FAIL` per row and is what you hand to whoever signs the change off.
**`connect-info --rdp-dir out`** writes a CSV with the connection settings per server and one `.rdp` file each.

Start with one server, test the login as a member of the role, then load the real list.
[What the results mean](docs/OPERATIONS.md#1-what-the-results-mean) explains every status.

## Big lists

- Work in waves: `--offset 0 --limit 5000`, then `--offset 5000 --limit 5000`, and `verify` after each.
- Add `--workers 8` and set `max_requests_per_second = 10` in `config.toml`.
- Interrupted? Run the same `apply` again with `--resume`. Only complete, verified rows from a matching version-3
  checkpoint are skipped; changed tenant/config/template/input fingerprints, a different `--update`/`--drift`
  choice, and malformed or older records are reconciled again. Version-2 records are preserved and rechecked
  because their completion checks did not confirm the saved fields after policy and target-set updates.

More in [Large rollouts](docs/OPERATIONS.md#6-large-rollouts).

## One server at a time (from a build job)

`--server` replaces `servers.csv` for a single run, so a newly built server can be onboarded from the same
job that builds it. `domains.csv`, `strong_accounts.csv` and `groups.csv` are still read, so the principal and
strong account resolve exactly as they would in a bulk run:

```bash
python sia_onboard.py apply --server web09.corp.example.com --yes --json --no-report
```

`--json` puts a valid result on stdout for both success and failure (the table and prompts go to stderr) and the
exit code is `0` success, `1` something needs attention, `2` bad input or configuration. Add `--principal NAME` to name the role (or group) explicitly,
`--workgroup` for a server that is not domain-joined.

## Standalone servers: onboard the strong accounts first

A workgroup (standalone) server has no domain account to borrow: its strong account is its own local administrator,
which already exists on the server. Those accounts can be onboarded into SIA on their own, before anyone decides
which role gets a policy, from a list of server names marked as workgroup servers:

```csv
fqdn,domain_joined
dmz-app01.example.com,no
dmz-app02.example.com,no
```

Set `domain_joined = no` for every standalone server, including an accounts-only run; use `--workgroup` with
`--server`. Without it, a matching DNS suffix in `domains.csv` can select the domain account instead of the
server's local account. The account name, the Windows user name and the `local` domain come from the naming
convention in `config.toml`; `credentials` stores
the user name and password in the SIA service (the *Stored in SIA* option of the portal), which is what a server
outside any Vault needs:

```toml
[defaults]
strong_account_template = "ADM-{hostname}"
strong_account_type = "credentials"
strong_account_username_template = "Administrator"
strong_account_domain = "local"
```

Passwords come from the password file (`name,password`, kept outside the repository), where the name may be the
account name **or the server FQDN**, so the list and the password file can be exported from the same inventory:

```csv
name,password
dmz-app01.example.com,current-password-1
dmz-app02.example.com,current-password-2
```

For local `credentials` or `vault` accounts declared in `strong_accounts.csv`, a missing `address` is inferred
when the complete input maps the account to one distinct server. Repeated policy rows for that server count
once, and wave selection does not change the inference. An explicit address takes precedence. For an account
shared by several servers, key its password by account name or set an explicit address. In the password file,
an account-name entry takes precedence over an address entry; both are matched case-insensitively.

Then:

```text
sia plan   --input input --accounts
sia apply  --input input --accounts --passwords /secure/passwords.csv
sia verify --input input --accounts
sia apply  --accounts --server dmz-app09.example.com --workgroup --yes --json --no-report   # from a build job
```

`--accounts` creates strong accounts only: no target set, no policy, no checkpoint, and no principal is needed
(`--update`, `--drift`, `--adopt`, `--set-policy-status`, `--resume` and `--principal` are rejected; `--only vault`
or `--only secrets` still limit the account stages). The table, the reports (`plan-accounts-*.json/.csv`) and the
`verify` verdicts are per account. Run it again and every account says `exists`; the later `sia apply` for the
same servers finds the account, reports it as `exists`, and creates only the target set and the policy.
With `[pvwa]` configured, `verify --accounts` checks each selected Vault account as well as its SIA reference;
a missing or unreadable Vault account cannot pass verification.

Before the run, on each server: the account is in the local *Administrators* group,
`LocalAccountTokenFilterPolicy = 1` is set (there is no GPO to push it on a workgroup machine), and the SIA
connector reaches the server over WinRM. A `credentials` account is stored in SIA and not rotated; see
[Standalone (workgroup) servers](docs/OPERATIONS.md#4-strong-accounts-in-detail) for the details and for vaulting
the accounts later.

## Behind a TLS-inspecting proxy

Export the proxy's root CA and point the tool at it, rather than turning verification off:

```bash
python sia_onboard.py --ca-bundle /path/to/corp-root-ca.pem preflight
```

Or set `ca_bundle` under `[http]` in `config.toml` to make it permanent. `preflight` prints which bundle is
in use.

## Safety

`plan` writes nothing. `apply` asks before changing anything, never deletes, only touches objects it created
(or that you `--adopt`), stops at the first rejected create instead of failing for every server, and never prints
a password. A timeout or malformed response after a write is `uncertain` or `unverified`, never success; it is not
stored as a completed checkpoint row. Reconcile with a new read-only plan before deciding whether another write is
needed.

## More

- [docs/WINDOWS.md](docs/WINDOWS.md) — Windows installation, automatic repair, offline packages, and troubleshooting.
- [docs/OPERATIONS.md](docs/OPERATIONS.md) — results, how users connect, first time on a tenant, strong accounts
  in detail, day-to-day changes, large rollouts, troubleshooting, FAQ, glossary, open items.
- [docs/DEVELOPER.md](docs/DEVELOPER.md) — architecture, API calls, tests.
- [docs/sia-onboarding-flow.html](docs/sia-onboarding-flow.html) — a one-page visual explainer.
