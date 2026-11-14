# pvp-scripts

Competition tooling for defending Linux and Windows services, inspecting configuration changes, and conducting scoped reconnaissance during SWIFT Purple vs Purple.

The toolkit combines the defensive foundation of [hpko-toolkit](https://github.com/cnaraysingh05/hpko-toolkit) with AD/SMB inspection, functional service checks, configuration snapshots, baseline comparison, and a small offensive discovery workflow. Commands that change credentials or firewall policy require explicit application; reconnaissance and service checks default to preview.

## Environment

| Host | Platform | Scored service |
| --- | --- | --- |
| `thehouse` | Windows Server 2022 | LDAP / Active Directory |
| `sunflower` | Windows Server 2019 | SMB |
| `cherrybomb` | Ubuntu 25.04 | Pi-hole and HTTP |
| `chomper` | CentOS 10 | Database engine to be confirmed |
| `peashooter` | Debian 12 | SSH |

Configuration templates retain `XX` for unknown values. They are deliberately non-executable until completed. The briefing lists conflicting Ubuntu addresses and an inconsistent team-number example; actual addressing and opponent ranges must be confirmed. No subnet-wide targeting is inferred from a team number.

## Components

| Directory | Capabilities |
| --- | --- |
| `blue/linux/` | Inventory, configuration/persistence review, local password rotation, nftables input policy with rollback, configuration snapshots and selected-file restoration |
| `blue/windows/` | Inventory, AD and SMB review, effective firewall-rule inspection, local/domain password rotation, firewall rollback, selected-file backups |
| `checks/` | HTTP content, DNS A records, SSH key authentication, LDAP bind/query, SMB listing and database `SELECT 1` checks; native Windows LDAP/SMB checks |
| `red/` | Explicit-target Nmap service discovery and focused protocol enumeration |
| `tools/` | JSON baseline comparison and private flag-submission ledger |
| `config/` | Scope, accounts and per-service templates |
| `tests/` | Portable unit tests, isolated fixtures and PowerShell parser/preview checks |
| `docs/` | Technical reference, compatibility boundaries, validation status and briefing constraints |

## Requirements

- Python 3.10+; Python utilities have no third-party package dependencies.
- Managed Linux hosts: systemd; `nft` for the optional nftables backend. Read-only collectors report missing utilities explicitly.
- Managed Windows hosts: 64-bit Windows PowerShell 5.1. AD commands require the ActiveDirectory module and appropriate directory permissions.
- Reconnaissance: Nmap on the provided Kali machine.
- Native checks on Linux/macOS: `dig`, OpenSSH, `ldapsearch`, `smbclient`, `mysql` or `psql`, depending on the selected check. Install only the clients needed, on the checking machine.

## Configuration and command interface

Create completed configuration copies under ignored `config/local/`. Keep the distributed templates unchanged. Populate both target lists, set `confirmed` to `true` only after scope verification, and leave the opponent list empty when configuring defense only. An offensive target must match an exact entry in `opponent_targets`; a service check must match `own_targets`.

Representative interfaces (run from the repository root):

```bash
python3 blue/linux/collect.py --output /var/lib/pvp-scripts/reports
python3 blue/linux/firewall.py plan --config config/local/linux-web.json
python3 checks/check_services.py --config config/local/checks.json --scope config/local/scope.json --only http
python3 red/recon.py --scope config/local/scope.json --target 172.16.XX.50 --profile windows
python3 tools/baseline_diff.py reports/before.json reports/after.json
python3 -m unittest discover -s tests -v
```

The `XX` reconnaissance example will reject the unresolved address. Preview is the default for the network utilities; `--run` is required to contact hosts. Offensive execution additionally requires `--grace-ended --provided-kali` and Kali Linux. These flags record operator acknowledgment; they cannot independently verify the organizer's clock or the identity of the provided VM.

```powershell
.\blue\windows\Collect.ps1
.\blue\windows\AD-Review.ps1
.\blue\windows\SMB-Review.ps1
.\blue\windows\Firewall-Audit.ps1
.\tests\Test-Windows.ps1
```

See [REFERENCE.md](docs/REFERENCE.md) for arguments, authentication behavior and output semantics. Host operation requires the corresponding permissions. Collection scripts write reports but do not alter security settings.

## Operational model

- Preserve baseline evidence and relevant configurations before changes.
- Change one explicitly selected account or policy at a time, then verify a fresh connection and the actual application transaction.
- Coordinate scored-account password changes with the scoring engine's password change request process. The toolkit does not submit PCRs.
- Keep reports, passwords, captured flags and completed environment configurations out of version control. Ignored directories are a convenience, not a secret scanner.
- Review collection errors. A missing tool, inaccessible section or successful TCP connection is not a clean security verdict.
- Flags are read and submitted according to competition rules; no utility alters target flags or their locations. The local ledger does not contact FlagKeeper.

## Compatibility and validation

The nftables module is a runtime, host-INPUT guard. It refuses active UFW/firewalld, does not control all container-forwarded traffic, and does not persist through reboot. Use the detected firewall manager's native workflow where appropriate. Windows firewall application retains existing rules; effective access must be reviewed separately. The firewall namespaces are specific to this repository and do not adopt hpko-toolkit rollback state.

There is intentionally no generic DC firewall template: LDAP availability depends on more than a single port, and the required AD traffic must be established before restricting access. Account lists are review references, not deletion instructions.

Offensive functionality covers discovery, focused enumeration and local evidence/flag tracking. Exploit execution and flag submission remain operator actions. No automatic exploitation, bulk account deletion, mass password reset, broad update, forced reboot or service-restart loop is included.

Portable unit tests are included and were run on macOS. Live Linux firewall integration, Windows execution and competition service checks still require platform validation. See [VALIDATION.md](docs/VALIDATION.md) for the precise results and remaining checks.

## Competition constraints

The 2026 briefing specifies a 30-minute defense-only grace period, attacks from the provided Kali, hosts `.50` through `.54` within the confirmed opponent scope, untouched routers/Kali infrastructure, and no flag modification. Resets cost 200 points and require Green Team coordination. Service/flag weights, scoring details and several addresses remain unresolved in the briefing. [BRIEFING.md](docs/BRIEFING.md) records these constraints without inventing missing values.

## License and provenance

MIT. The original copyright notice is preserved in [LICENSE](LICENSE). Defensive modules are adapted from hpko-toolkit; [PROVENANCE.md](docs/PROVENANCE.md) records their source blobs and changes. The FAU CPTC repository informed the organization and review, but its source files and binaries are not redistributed in this package.
