# sia-policy-automation

Onboard Windows servers into CyberArk / Idira **Secure Infrastructure Access (SIA)** from a spreadsheet.

For every server it creates the three things SIA needs for zero-standing-privilege RDP: the server's **strong
account** (its local administrator, referenced from your Vault), a **target set**, and an **access policy** named
after the server. It works for 5 servers or 70,000, can be run again at any time without changing anything that is
already right, and picks up where it stopped if interrupted.

```text
python sia_onboard.py preflight                    # can I reach the tenant?
python sia_onboard.py plan  --input input          # what would change? (changes nothing)
python sia_onboard.py apply --input input          # do it
python sia_onboard.py verify --input input         # is every server ready? PASS / FAIL
python sia_onboard.py connect-info --input input   # what users type into their RDP client
```

## How it works

```mermaid
flowchart TB
    G["Identity group<br/>SIA-Web-Admins<br/><i>already in place</i>"]
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

1. makes sure SIA has a **strong account** for it: a reference to the server's own local admin account in the
   Vault, found by a naming convention you set once (safe `SIA-LocalAdmins`, account `<hostname>-Administrator`);
2. creates a **target set** named after the server, pointing at that account;
3. creates the **access policy**: which Identity group may connect, by RDP with a temporary local user, for how long.

Linux servers get only a policy (SIA uses an SSH certificate there). A second group on the same server is just a
second row with a `policy_suffix`.

**When a user connects**, they open **Access › Infrastructure** in the portal, search the server, and click
**Connect › RDP**. SIA finds the policy, uses the strong account to create a temporary local user on the server,
opens the session, and deletes that user when the session ends (after 2 hours, or 10 idle minutes, by default).
Nobody types a password. `connect-info` exports the same connection for RDP clients (gateway
`<subdomain>.rdp.cyberark.cloud`, user name `secureaccess /i alice@acme.cyberark.cloud /s acme /a web01.corp.example.com`).
Details: [How a user connects](docs/OPERATIONS.md#2-how-a-user-connects).

## Install

You need Python 3.11 or newer (<https://www.python.org/downloads/>; on Windows tick *Add python.exe to PATH*).

1. Get the tool: **Code → Download ZIP** on GitHub, or `git clone https://github.com/uakbr/sia-policy-automation.git`.
2. Open a terminal in the folder and install the one dependency:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1          # Windows PowerShell (macOS/Linux: source .venv/bin/activate)
   pip install -r requirements.txt
   ```

   Run the *Activate* line again whenever you open a new terminal.
3. Copy `config.example.toml` to `config.toml` and set these lines (the file explains the rest):

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
   strong_account_safe_template = "SIA-LocalAdmins"     # where the servers' local admin accounts live in the Vault
   strong_account_account_name_template = "{hostname}-Administrator"   # their account name in the Vault
   strong_account_username_template = "Administrator"   # their Windows user name
   ```

4. Copy `.env.example` to `.env` and put in the service user (an Identity user flagged **Is OAuth confidential
   client**, member of the **Secure Infrastructure Access administrator** role):

   ```dotenv
   SIA_CLIENT_ID=svc_sia_automation@acme.cyberark.cloud
   SIA_CLIENT_SECRET=its-password
   ```

   Leave the secret out to be prompted instead. Never share `config.toml` or `.env`.
5. Check the connection:

   ```text
   python sia_onboard.py preflight
   ```

   Every line should say `OK`. If not, see [Troubleshooting](docs/OPERATIONS.md#8-troubleshooting).

**Before the first server**, three things must be true on your side: a local administrator account for every
server exists in the Vault under the naming convention above (the tool can onboard missing ones through PVWA, see
the operations guide), the SIA connectors reach the servers over WinRM (TCP 5985/5986), and local accounts have
`LocalAccountTokenFilterPolicy = 1` (a GPO setting).

## Your list: `input/servers.csv`

One row per policy. Usually that is one row per server; a second group gets a second row.

```csv
fqdn,strong_account,group,policy_name,policy_suffix,assign_groups,domain,description,protocol,ssh_username,domain_joined
web01.corp.example.com,,SIA-Web-Admins,,,,,,,,
web01.corp.example.com,,SIA-Platform-Ops,,-ops,Remote Desktop Users,,,,,
web02.corp.example.com,,SIA-Web-Admins,,,,,,,,
app-lnx01.corp.example.com,,SIA-Linux-Admins,,,,,,ssh,ec2-user,
```

| Column | Fill in |
|---|---|
| `fqdn` | The server name exactly as users will connect to it. |
| `group` | The Identity group that may connect (several: `SIA-Web-Admins;SIA-Platform-Ops`). |
| `policy_suffix` | Only for a second policy on the same server, e.g. `-ops`. |
| `assign_groups` | Local groups the temporary user joins; empty = `Administrators`. |
| `protocol`, `ssh_username` | `ssh` and the certificate user name for Linux servers; empty = Windows/RDP. |
| `strong_account` | Leave empty. Only for the few servers that use a shared domain account declared in `strong_accounts.csv`. |
| `policy_name`, `domain`, `description`, `domain_joined` | Optional overrides; the example file shows them. |

The example folder also has `strong_accounts.csv` (shared or special accounts) and `groups.csv` (only needed
when a group name exists in two directories). Column names must match exactly; every problem is reported with
its line number and nothing is touched until the files are clean.

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
Anything that differs from your list is shown as `drift`, never changed silently.

**`verify`** prints `PASS`, `MISSING` or `FAIL` per row and is what you hand to whoever signs the change off.
**`connect-info --rdp-dir out`** writes a CSV with the connection settings per server and one `.rdp` file each.

Start with one server, test the login as a member of the group, then load the real list.
[What the results mean](docs/OPERATIONS.md#1-what-the-results-mean) explains every status.

## Big lists

- Work in waves: `--offset 0 --limit 5000`, then `--offset 5000 --limit 5000`, and `verify` after each.
- Add `--workers 8` and set `max_requests_per_second = 10` in `config.toml`.
- Interrupted? Run the same `apply` again with `--resume`; finished rows are skipped.

More in [Large rollouts](docs/OPERATIONS.md#6-large-rollouts).

## Safety

`plan` writes nothing. `apply` asks before changing anything, never deletes, only touches objects it created
(or that you `--adopt`), stops at the first rejected create instead of failing for every server, and never prints
a password.

## More

- [docs/OPERATIONS.md](docs/OPERATIONS.md) — results, how users connect, first time on a tenant, strong accounts
  in detail, day-to-day changes, large rollouts, troubleshooting, FAQ, glossary, open items.
- [docs/DEVELOPER.md](docs/DEVELOPER.md) — architecture, API calls, tests.
- [docs/sia-onboarding-flow.html](docs/sia-onboarding-flow.html) — a one-page visual explainer.
