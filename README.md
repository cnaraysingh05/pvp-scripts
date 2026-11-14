# PvP Scripts

A cross-platform cybersecurity toolkit developed for **SWIFT's 2026 Purple vs Purple (Plants vs. Zombies)** competition at Cal Poly Pomona.

The repository provides defensive administration, system auditing, service validation, scoped offensive reconnaissance, and post-access enumeration utilities for Windows and Linux environments.

The toolkit emphasizes repeatable workflows, explicit scope validation, configuration preservation, and minimizing disruption to critical services.

## Competition Environment

Purple vs Purple is a team-based cybersecurity competition in which participants defend their assigned infrastructure while attempting to compromise authorized opposing systems and capture flags.

Teams earn points through scored-service availability and successful flag submissions. The competition includes an initial 30-minute defense-only period before authorized offensive operations begin.

### Target Infrastructure

| Hostname | Operating System | Critical Scored Services |
|---|---|---|
| `thehouse` | Windows Server 2022 | LDAP / Active Directory |
| `sunflower` | Windows Server 2019 | SMB |
| `cherrybomb` | Ubuntu 25.04 | Pi-hole, HTTP |
| `chomper` | CentOS 10 | Database |
| `peashooter` | Debian 12 | SSH |

Competition hosts use assigned team-specific addresses. Unconfirmed addressing and configuration values remain placeholders until verified.

The briefing contains an inconsistency in Cherrybomb's network address. Actual host addresses and offensive scope must be confirmed before execution.

## Repository Structure

```text
pvp-scripts/
├── blue/
│   ├── linux/
│   └── windows/
├── checks/
├── config/
│   └── firewall/
├── docs/
├── red/
├── scripts/
├── tests/
│   └── fixtures/
├── tools/
├── pvp_core.py
└── README.md
```

### Defensive Tooling — `blue/`

Utilities for inspecting, securing, and maintaining assigned infrastructure.

**Linux**

- System and service inventory
- User and credential administration
- Configuration and persistence inspection
- Firewall policy planning and controlled application
- Configuration backups and selected-file restoration
- Security review and evidence collection

**Windows**

- System and account inventory
- Active Directory user and privilege review
- SMB configuration inspection
- Windows Defender Firewall auditing
- Firewall configuration with rollback support
- Local and domain credential administration
- Configuration backups and persistence review

Security-changing operations are separated from read-only inspection. Firewall changes support previews and rollback procedures, but must be validated on the actual target platform before use.

Account reviews do not automatically establish that an account is unauthorized. Administrative actions require comparison against the competition's approved account lists and operational requirements.

### Offensive Tooling — `red/`

Python wrappers for authorized reconnaissance, enumeration, and post-access assessment.

| Script | Purpose |
|---|---|
| `recon.py` | Scoped Nmap service discovery |
| `smb_enum.py` | SMB enumeration |
| `netexec_scan.py` | SMB, LDAP, and WinRM enumeration and credential validation |
| `kerbrute_scan.py` | Kerberos username enumeration and optional password spraying |
| `ffuf_scan.py` | Web content discovery |
| `nuclei_scan.py` | Template-based vulnerability and misconfiguration checks |
| `linpeas_deploy.py` | Linux post-access enumeration over SSH |
| `sharphound_deploy.py` | Active Directory data collection using SharpHound |
| `scope_gate.py` | Target validation and execution restrictions |
| `runner.py` | Command execution, timeouts, and evidence management |

Offensive scripts use explicit target allowlists and default to command previews where supported.

Network execution requires confirmation that the competition's grace period has ended and that the operator is using the provided Kali environment.

These acknowledgments do not independently verify organizer authorization or the official competition clock.

Post-access utilities require an existing authorized foothold or valid credentials. They do not independently establish initial access or privilege escalation.

Some wrappers require separately installed open-source tools and have not been integration-tested against the competition environment.

### Service Validation — `checks/`

Functional availability checks for critical infrastructure.

Supported checks include:

- HTTP status and response-content validation
- DNS resolution and expected-answer verification
- SSH authentication
- LDAP binding and queries
- SMB share access
- Database connectivity and basic query execution

Windows-native LDAP and SMB checks are also included.

Checks are designed to validate more than TCP port availability. Their results depend on correctly configured credentials, expected responses, network connectivity, and external utilities.

The competition's actual scoring-engine behavior remains authoritative.

### Flag Utilities — `scripts/`

Read-only flag discovery utilities:

- `flag_finder.sh` — Linux filesystem inspection
- `Find-Flags.ps1` — Windows filesystem inspection

These scripts inspect documented and additional candidate flag locations without intentionally modifying flag files.

The competition documents the following standard locations:

```text
Linux:
/root/flag.txt
/user/flag.txt

Windows:
C:\Windows\flag.txt
```

Additional flags may exist outside these locations.

The scripts display candidate values and SHA-256 file digests for manual review. A calculated file digest is not necessarily equivalent to the flag value expected by the scoring bot.

Flag submission is performed manually through the competition's FlagKeeper system.

### Supporting Utilities — `tools/`

| Utility | Function |
|---|---|
| `preflight_check.py` | Validate competition scope configuration |
| `baseline_diff.py` | Compare collected system baselines |
| `credential_ledger.py` | Track credential changes and scoring-engine password-change requests |
| `flag_ledger.py` | Record discovered flags and submission status locally |
| `password_gen.py` | Generate passwords locally |

Completed credentials, captured flags, and environment-specific configuration files should remain outside version control.

## Requirements

### Core

- Python 3.10 or newer
- Git
- Appropriate local system permissions

The core Python utilities use the standard library.

### Linux

- A systemd-based distribution
- Required administrative permissions
- `nftables` for the optional Linux firewall backend
- Additional service-specific utilities as needed

### Windows

- Windows PowerShell 5.1
- Administrative permissions for privileged operations
- ActiveDirectory PowerShell module for applicable AD operations

### Offensive Dependencies

Depending on the selected script:

- Nmap
- NetExec
- Kerbrute
- ffuf
- Nuclei
- linPEAS
- SharpHound
- OpenSSH

Dependencies must be installed separately. Availability of a wrapper does not guarantee that its external executable is installed or compatible.

## Configuration

Example configurations are provided under `config/`.

These include:

- Competition scope and target allowlists
- Approved account references
- Service health-check definitions
- Linux and Windows firewall rules
- Database-specific configuration examples

Create local configuration copies under `config/local/` and populate them using verified competition information.

Unresolved addresses, usernames, passwords, service expectations, and other environment-specific fields are intentionally left unspecified.

The scope configuration distinguishes assigned infrastructure from authorized opposing targets.

Offensive commands must target explicitly listed, confirmed addresses.

## Usage

Run commands from the repository root.

### Run Portable Tests

```bash
python3 -m unittest discover -s tests -v
```

### Validate Scope Configuration

```bash
python3 tools/preflight_check.py \
  --scope config/local/scope.json
```

### Collect Linux System Information

```bash
python3 blue/linux/collect.py \
  --output reports/linux
```

### Preview Linux Firewall Configuration

```bash
python3 blue/linux/firewall.py plan \
  --config config/local/linux-web.json
```

### Check Scored Services

```bash
python3 checks/check_services.py \
  --config config/local/checks.json \
  --scope config/local/scope.json
```

### Preview Scoped Reconnaissance

```bash
python3 red/recon.py \
  --scope config/local/scope.json \
  --target 172.16.XX.50 \
  --profile windows
```

The unresolved `XX` address is illustrative only and will be rejected until replaced with an explicitly authorized target.

Preview mode does not initiate the scan.

### Windows System Review

Run from an appropriate Windows PowerShell session:

```powershell
.\blue\windows\Collect.ps1
.\blue\windows\AD-Review.ps1
.\blue\windows\SMB-Review.ps1
.\blue\windows\Firewall-Audit.ps1
```

Consult `docs/REFERENCE.md` for additional arguments, authentication requirements, and operational details.

## Validation Status

The repository includes automated tests and supporting fixtures for configuration validation, scope enforcement, command behavior, and selected security workflows.

The documented local validation includes:

- Python compilation
- 58 passing portable unit tests
- Mocked firewall and credential operations
- Scope and execution-gate validation
- Service-check result interpretation
- Secret-handling checks
- Flag-ledger and baseline-comparison tests

These are the previously documented results, not a guarantee that the current revision has passed a fresh test run.

**The toolkit has not been fully validated on the live competition infrastructure.**

Outstanding validation includes:

- Windows PowerShell execution and compatibility
- Active Directory and SMB operations
- Live firewall application and rollback
- Linux firewall and kernel interactions
- Real service-health checks
- Credential and scoring-engine integration
- Deployment and cleanup of post-access tools

Automated tests and command previews do not replace integration testing against representative systems.

## Operational Considerations

The toolkit is designed to support controlled security operations rather than indiscriminate system modification.

Recommended practices include:

- Collecting a system baseline before making changes
- Verifying scored services before and after modifications
- Maintaining access to a recovery console
- Confirming account authorization before removal or privilege changes
- Coordinating scored-account password changes with the scoring engine
- Reviewing firewall dependencies before enforcing restrictions
- Preserving evidence and documenting operational changes
- Verifying that scripts and external tools behave as expected before deployment

The Linux firewall module uses a runtime nftables policy and does not provide universal persistent firewall management.

Windows firewall changes preserve existing rules, which may continue to affect effective access.

No generic firewall configuration should be assumed safe for an Active Directory domain controller without identifying its actual dependencies.

## Competition Rules and Scope

Operations must comply with the official SWIFT Purple vs Purple briefing.

Important restrictions include:

- No access to opposing environments during the initial 30-minute grace period
- Offensive operations must remain within explicitly authorized targets
- Opposing routers and Kali machines are out of scope
- Offensive activity must use the competition-provided Kali machine
- No intentional sabotage of competition infrastructure
- No unauthorized snapshots or machine reversions
- No modification or relocation of competition flags
- Use of open-source tools as required by competition rules

Competition machine resets require Green Team coordination and carry a 200-point penalty.

Scored-service credentials must be updated through the appropriate password-change request process when required.

Official competition rules and organizer instructions take precedence over repository documentation.

## Documentation

Additional technical and operational documentation is available in `docs/`.

- `BRIEFING.md` — Competition-specific constraints and environment details
- `REFERENCE.md` — Script interfaces and technical reference
- `VALIDATION.md` — Testing results and known validation gaps
- `PROVENANCE.md` — Source history and adapted components

## License

MIT License. See [LICENSE](LICENSE).

The repository includes defensive components adapted from earlier security tooling, with additional competition-specific functionality and source attribution documented in `docs/PROVENANCE.md`.
