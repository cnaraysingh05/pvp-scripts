# Source provenance

Defensive source: https://github.com/cnaraysingh05/hpko-toolkit (MIT, copyright Christopher Naraysingh). Files were retrieved from the default branch; the Git blob IDs below identify the exact source content.

| Destination | Upstream blob SHA |
| --- | --- |
| `LICENSE` | `e5f0e0e51af3ca658a5b1b0c4b667c9bbf47f092` |
| `blue/linux/common.py` | `5f71aec086e587158b3c663f4da871478e0cd303` |
| `blue/linux/credentials.py` | `fc22fe4137ad2562eaed5754ecf926ae6d470f4f` |
| `blue/linux/firewall.py` | `a07da33847768c4c14d34534ff97c53bbcc4faa0` |
| `blue/linux/persistence.py` | `c3343f2a1a885829bc14932e356b9ee188e4d332` |
| `blue/linux/recon.py` | `950939d4362d16eae168c295b94baed3d6dfac2e` |
| `blue/linux/review.py` | `171e48427dcaecaa12fead0687fcaf7b774ae8ab` |
| `blue/windows/Common.ps1` | `678c7b0b22479d9fb0b4e22119721f12d8f35916` |
| `blue/windows/Credentials.ps1` | `b45cbf9abe65262f667b15178d95557ea1699da4` |
| `blue/windows/Firewall.ps1` | `aa550e2e94e4e0c03ab647fd39113e62ab396c34` |
| `blue/windows/Persistence.ps1` | `cbdc8352f392c157dff6e1eba26a6f00c9f19902` |
| `blue/windows/Recon.ps1` | `ef077170793a2fe87dbba6b856f40f83da49beb9` |
| `blue/windows/Review.ps1` | `c38bc78163ecabcca688188c97b52dd4457b9c60` |

Adaptations: directory layout, repository-specific firewall namespaces/state paths and technical references. Original copyright and license terms remain in LICENSE. Existing firewall behavior is retained; the new audit scripts do not silently replace its policy semantics.

`tests/test_linux.py` and `tests/Test-Windows.ps1` are adapted from the same upstream repository with updated paths and isolated fixture locations.

New components in this repository include scoped reconnaissance, external service checks, AD/SMB/firewall inspection, configuration backup, collection wrappers, baseline comparison, flag ledger, scope/config templates and additional validation.

The FAU CPTC repository (https://github.com/nationalcptc-teamtools/Florida-Atlantic-University) was reviewed as a reference. No code or binary from it is copied into this distribution. Nmap, OpenSSH, OpenLDAP clients, Samba clients and database clients are external dependencies, not vendored content.
