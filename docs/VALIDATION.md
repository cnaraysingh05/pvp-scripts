# Validation status

## Executed locally

Environment: macOS, Python 3. No elevated host changes and no competition network traffic.

| Check | Result |
| --- | --- |
| Python compilation | Passed |
| Portable unit suite | 58 passed |
| Firewall/credential transaction behavior | Mocked subprocess tests; no kernel/account changes |
| Scope and grace gates | Tested: placeholders, out-of-subnet and infrastructure hosts, overlap, unconfirmed scope, unlisted targets and missing acknowledgments rejected |
| Functional check interpretation | Mocked tests for HTTP body/status, DNS exact answers, native failures and missing tools |
| Secret handling | Tested SMB password absence from argv, credential-file mode, generated-password file mode 0600 and no-overwrite behavior |
| Flag ledger | Tested raw/SHA-256 flag values and digest stability |
| Baseline comparison | Tested ordering/timestamp handling and collection-error visibility |
| Configuration-file filtering | Tested symlink, flag and traversal rejection |

## Not validated here

- PowerShell is not installed on the build host. No Windows script has been parsed or executed here. `tests/Test-Windows.ps1` supplies parser and firewall-preview checks, not live integration coverage.
- Live nftables apply/rollback, kernel interaction, manager coexistence, container filtering and reboot behavior.
- Windows firewall apply/rollback, ACL behavior, AD cmdlets, credential resets and native LDAP/SMB checks.
- Live SSH, DNS, HTTP, LDAP, SMB or database checks against competition targets.
- Live configuration snapshot/restore with Linux ACL/SELinux attributes, or Windows backup recovery.

## Platform acceptance criteria

Before applying mutations on competition hosts, validate on representative disposable practice machines: baseline service succeeds; preview makes no security changes; apply preserves a fresh management connection and the functional service; invalid inputs fail before mutation; rollback restores expected connectivity; interruption leaves recoverable state. Verify actual scored-account/PCR behavior with the organizer's platform. Practice-machine snapshots are distinct from competition snapshots, which require Green Team coordination.

For Windows run `powershell.exe -NoProfile -File tests\Test-Windows.ps1` in a practice environment, then exercise AD, SMB, firewall and recovery against that environment. Syntax success does not establish operational safety or compatibility.

This toolkit is source-reviewed and locally unit-tested, not certified for the competition environment.
