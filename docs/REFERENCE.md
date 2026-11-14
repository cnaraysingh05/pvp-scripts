# Technical reference

This document describes script interfaces and compatibility. It is not a host-by-host operator walkthrough.

## Inventory and comparison

`blue/linux/collect.py --output DIRECTORY` runs `recon.py`, `review.py`, `persistence.py` and `service_inventory.py`. Run with sufficient host privileges for complete collection. A unique mode-0700 run directory contains mode-0600 JSON. Individual reports can also be printed by running their modules directly; redirect sensitive output only into a private directory. `collection.json` records top-level failures; section failures remain inside reports.

`blue/windows/Collect.ps1` requires elevation, creates an ACL-restricted `%ProgramData%\PvPReports-*` directory, and includes AD review on domain controllers. Other inventory scripts can run independently. Reports may contain sensitive account names, task arguments, paths and exclusions; they are not suitable for a public issue or commit.

`tools/baseline_diff.py BEFORE AFTER` ignores generated UTC timestamps and array ordering. It preserves collection errors, ownership, permission and file-hash changes. Exit 0: no changes; exit 1: changes; exit 2: invalid input. Compare the same report type from the same host. This is not a malware classifier.

## Credentials

Linux: `python3 blue/linux/credentials.py USER` previews the selected local `/etc/passwd` identity. `--apply --ack-service-impact` invokes native `passwd` interactively. Passwords never enter Python arguments or reports. Review dependent jobs/services and scored-user status first.

Windows local: `Credentials.ps1 -User USER` previews; `-Apply -AckServiceImpact` requests a secure password and resets exactly one local account. It refuses DCs. Domain: `AD-Credentials.ps1 -Identity USER [-Server DC]` previews; application requires `-Apply -DependenciesReviewed -ScoringStatus coordinated|not-scored` and exact-name confirmation. Accounts with SPNs, built-in Administrator and krbtgt are excluded from that domain utility. SPN absence does not prove there are no dependencies.

A coordinated scoring status is a declaration, not automated proof of PCR submission. Complete the scorer change and test new authentication. Existing sessions, keys, tickets and application credentials are not all invalidated by a password reset.

`tools/password_gen.py` generates local password candidates. `--save PATH` creates a new owner-only file (mode 0600) and refuses to overwrite an earlier list. It does not set passwords on any host.

`tools/credential_ledger.py` keeps the host/user/password/PCR state locally in mode-0700 `private/credentials/` SQLite. `add` prompts for the new password; `pcr-submitted`, `pcr-pending` and `verified` record scorer state; `pending` lists accounts still missing a PCR; `export --host IP` reveals one host's stored passwords only after an interactive host-name confirmation. It never contacts the scoring engine or changes an account.

## Firewall

Linux interface: `firewall.py plan|apply|rollback`. Plan/apply require `--config PATH`; apply also requires root and `--console-confirmed`. The runtime input table is `pvp_scripts`; state is `/var/lib/pvp-scripts`. Backups precede atomic nftables changes. Rollback deletes only the managed table. Existing connections and ICMP are retained. This backend requires a systemd Linux host with nft and no active UFW/firewalld.

Windows interface: `Firewall.ps1 -Config PATH` previews; `-Apply -ConsoleConfirmed` applies; `-Rollback` restores saved profile defaults and removes this transaction's rules. State is `%ProgramData%\PvPScripts`. Existing firewall rules remain. Exported `.wfw` files are retained, but rollback intentionally does not overwrite all policy. `Firewall-Audit.ps1` joins effective inbound rules with address, port, program and service filters.

On a host using firewalld/UFW, use its native configuration workflow and preserve that manager's configuration. This release inventories those managers but does not implement their policy mutations. Do not stop an existing manager just to make this backend run. Container-published services require inspection of forwarding/NAT policy. Runtime-only Linux rules must be rechecked after reboot or firewall reload. No automatic rollback timer is installed; working console access and a recovery owner are required for application.

Firewall templates contain known service ports and unknown client addresses as `XX`. Verify actual listeners and authorized clients; remove unused example management ports. There is no scorer-only restriction assumption. Do not apply the SMB member-server template to a DC. Full AD dependency rules and dynamic RPC policy require environment-specific review.

## Configuration snapshots

Linux: `config_backup.py save --path /etc/ssh [--path /etc/nginx ...]` captures regular configuration files under supported `/etc` roots into a root-owned mode-0700 `/var/lib/pvp-scripts/backups` snapshot. Excludes symlinks, `flag.txt`, database files and logs; files are capped at 10 MiB. Read `manifest.json` for skipped files. Existing snapshots are not overwritten.

`config_backup.py restore --snapshot ABSOLUTE_SNAPSHOT --file /etc/ssh/sshd_config` previews one existing file. `--apply` requires exact-path confirmation, snapshots the current file, and atomically replaces that selected file. Recorded ownership/mode/xattrs are restored before replacement. Permission/xattr failures abort replacement. Verify syntax and service behavior before reload. This does not validate application syntax itself or restore deleted files, directory ACLs or a complete machine. Live databases need their native backup procedures.

Windows: `Backup-Config.ps1 -Path FILE1,FILE2` captures explicit `.config/.conf/.ini/.json/.xml` files up to 10 MiB and records SHA-256 and SDDL in a private `%ProgramData%\PvPBackup-*` directory. Recovery is manual per file: preserve the current version, compare the saved hash, replace only the selected configuration and restore required ACLs. This does not back up Active Directory system state, registry policy, live databases or a whole server.

## Functional checks

`checks/check_services.py --scope PATH --config PATH [--only NAME]` validates and previews. Add `--run` to contact only own confirmed targets. Exit codes: 0 all selected checks pass; 1 a check fails; 2 configuration/runtime setup error. `--timeout` bounds native commands and socket operations; HTTP socket timeouts are per operation, not a hard whole-response deadline.

| Type | Verification | Authentication / limitation |
| --- | --- | --- |
| `tcp` | Connection established | Reachability only |
| `http` | Exact status and expected substring within 1 MiB | No redirects, cookies or login flow; optional Host header; HTTPS uses system CA/IP certificate validation |
| `dns` | Expected A record through selected DNS server, UDP or TCP | Select a stable query/expected address confirmed for the environment; does not prove Pi-hole UI login |
| `ssh` | Authenticated execution of `printf PVP_SSH_OK` | Key authentication, prevalidated known_hosts, strict host-key checks; does not verify password-based scorer login |
| `ldap` | Authenticated base query with expected distinguished-name content | Hidden password prompt; StartTLS/LDAPS required; trusted server certificate with matching IP identity required |
| `smb` | Authenticated share listing with expected substring | Hidden password prompt; does not prove read/write permissions for every file |
| `mysql` | Authenticated `SELECT 1` | Hidden password prompt; select the actual database/port |
| `postgres` | Authenticated `SELECT 1` | Hidden password prompt; select the actual database/port |

Linux/macOS authenticated clients use private temporary credential files removed on normal exit. An abrupt process termination may leave a file in the private temporary directory; inspect and remove it after interruption. Passwords are not command-line arguments or output. Client certificate/TLS setup remains environment-specific; no certificate-validation bypass is provided. Database TLS behavior follows the client configuration. Do not select a database engine before identifying it.

For Windows-integrated directory authentication, `checks/Check-Services.ps1 -Kind LDAP -Server 172.16.XX.50 -Scope PATH -BaseDN 'DC=misty,DC=view' [-Run]` performs a Negotiate bind with signing/sealing and a base query. This is an alternative to simple-bind TLS checks, not proof the scorer uses the same authentication mode. `-Kind SMB -Server 172.16.XX.51 -Scope PATH -Share NAME -ExpectedEntry NAME [-Run]` uses a temporary PSDrive and verifies an exact entry. Existing SMB sessions using other credentials may cause Windows credential conflicts; do not indiscriminately disconnect other operators' sessions. SMB calls may wait on Windows network timeouts.

## Offensive reconnaissance

All `red/` wrappers share `red/scope_gate.py` and `red/runner.py`. They preview a command by default; `--run` requires `--grace-ended --provided-kali` and verifies `/etc/os-release` reports `ID=kali`. Each run gets a unique mode-0700 evidence directory, per-command timeouts, and redaction of supplied passwords in printed and recorded commands.

Scope validation is centralized in `pvp_core.competition_host`: targets must be literal IPv4 addresses inside `172.16.0.0/12` ending `.50` through `.54`. Addresses ending `.1` (pod router) and `.2` (Kali) are rejected with a specific message even if someone lists them in scope. Overlap between own and opponent lists and unconfirmed scope are rejected. Targets are never inferred from a team number.

`red/recon.py --scope PATH --target IP --profile inventory|web|windows|ssh|database` previews a single-target Nmap command. Ports and script names are fixed per profile. Requests have a rate cap and host/script/process timeouts; output goes to a unique private directory under `reports/recon/` unless overridden. Nmap raw/XML output and step records preserve errors and timestamps. Discovery does not prove exploitability. This does not scan UDP or every TCP port.

`red/ffuf_scan.py`, `red/nuclei_scan.py`, `red/smb_enum.py`, `red/netexec_scan.py`, `red/kerbrute_scan.py`, `red/linpeas_deploy.py` and `red/sharphound_deploy.py` follow the same gate. Credential-taking wrappers offer a hidden prompt and redact the value; `--password` remains available but places the secret in shell history. Password spraying prints a lockout warning and stays single-password by design. `linpeas_deploy.py` and `sharphound_deploy.py` run cleanup even when an earlier step fails. `sharphound_deploy.py` performs collection only; it does not obtain credentials or exploit the DC.

`tools/preflight_check.py --scope PATH` applies the same host rule to a scope file, reports out-of-grid or conflicting addresses as warnings, and exits non-zero on any error.

## Flag ledger

`tools/flag_ledger.py add --scope PATH --host IP --path FLAG_PATH` reads a flag through a hidden prompt and records it in private local SQLite. The stored value is exactly what was submitted: a bare SHA-256 value or a raw flag string of 1..512 printable ASCII characters without whitespace. A SHA-256 digest of that value is also stored as a separate column for cross-checking. `accepted` and `rejected` update the selected value's state after manual FlagKeeper feedback; `list` shows only a value prefix and digest prefix. Exact duplicates are rejected. No network submission occurs and no hash is invented. Default storage: ignored `private/flags`, mode 0700.
