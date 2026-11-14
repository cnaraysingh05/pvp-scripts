# SWIFT Purple vs Purple — 2026 constraints

Source: supplied 15-page briefing, dated November 14, 2026. Organizer updates override this record.

| Topic | Briefing requirement |
| --- | --- |
| Opening | 30-minute defense-only grace period; no accessing, viewing or enumerating other environments |
| Offensive origin | Provided Kali machine |
| Allowed hosts | Confirmed opponent `172.16.XX.50` through `.54`; opponent team range remains unspecified |
| Out of scope | Routers, other teams' Kali, and anything not explicitly authorized; own router cannot be changed defensively |
| Scoring | Functional service checks and captured flags; own flag losses reduce score; exact weights unspecified |
| Resets | -200 points; request through Green Team; no snapshots/reverts without their knowledge |
| Flags | Do not change contents or locations; known paths `/root/flag.txt`, `/user/flag.txt`, `C:\Windows\flag.txt`; other flags and containers may exist |
| Submissions | `/submit_flag` in team Discord; use found SHA-256-formatted value |
| Credentials | Update scored-user passwords through scoring-engine password change requests as well as on the host |
| Tools | Scripts allowed; open-source tools required |
| Access | SDC access setup required before competition; Kamino credentials arrive in team Discord |

## Items requiring organizer confirmation

- Ubuntu's host page lists `172.25.XX.52`, conflicting with general `172.16.XX.50–54` scope. All templates are placeholders pending confirmation, not an authorization decision.
- Team-number explanation conflicts with its example. Do not derive another team's range from the example.
- Opponent range, scoring URL, point weights, scored identities, check frequency and exact application transactions are not supplied.
- Database engine, share name, DNS checks, HTTP content and application deployment/container details are not supplied.
- Domain table includes Administrator; the DC host page excludes it and names only crazydave as administrator. Do not automatically delete or demote built-in/service identities.
- Allowed source restrictions for scored services and treatment of flag file permissions are not specified. Do not infer permission to make flags inaccessible by changing them.
- Packet does not specify flag rotation/expiration. Do not assume fixed flags or periodic resets.

The account template is a human-access review aid. Linux system accounts and AD service/computer identities are not automatically unauthorized because they are absent from those lists. Sensitive-data cleanup must never remove competition flags.
