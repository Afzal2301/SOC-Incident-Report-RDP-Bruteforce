# RDP Brute-Force Compromise — Incident Response Report

**Incident ID:** INC-2026-001 · **Severity:** Critical · **Date:** 10 July 2026

> This is a self-directed home-lab exercise built on a virtualized SOC environment (VirtualBox, Wazuh, Sysmon) — no real client or production data is involved. The TLP:AMBER label inside the report reflects realistic SOC documentation practice, not an actual confidentiality restriction.

## Summary

Detected and investigated a brute-force RDP compromise against a Windows 10 endpoint. Correlated failed authentication attempts with a subsequent successful logon (MITRE ATT&CK T1110.001), traced the attacker through session establishment, unauthorized account creation, discovery activity, and an attempted anti-forensic log clear — then closed out with containment, eradication, and a documented Sysmon visibility gap fix.

**[Full report (PDF)](report/INC-2026-001_Incident_Report.pdf)**

## Environment

| Host | Role |
|---|---|
| Windows 10 (WINDOWS-VICTIM) | Target endpoint — Wazuh agent, Sysmon |
| Ubuntu (UBUNTU-SIEM) | Wazuh manager / indexer |
| Kali Linux | Attack source — THC-Hydra, FreeRDP |

## Attack chain (MITRE ATT&CK)

| Phase | Technique | Detection |
|---|---|---|
| Initial Access | T1110.001 — Brute Force | Wazuh Rule 100010 / 100011 |
| Execution | T1078 — Valid Accounts | Wazuh Rule 92653 (Logon Type 10) |
| Persistence | T1136.001 — Local Account | Windows Event 4720 / Rule 60109 |
| Discovery | T1087 — Account Discovery | Wazuh Rule 92031 |
| Defense Evasion | T1070.001 — Clear Logs | Windows Event 1102 / Rule 63103 |
| Impact | T1005 — Local Data | Monitoring gap — see report §9 |

## What this demonstrates

- Writing custom Wazuh correlation rules (brute-force chaining, discovery aggregation, false-positive suppression)
- Mapping raw log/alert data to MITRE ATT&CK
- End-to-end IR documentation following the SANS PICERL model (Identification → Containment → Eradication → Recovery → Lessons Learned)
- Root-causing a detection gap (Sysmon config exclusion) rather than just noting it existed
- Evidence handling — timeline reconstruction, IOC table, detection rule appendix

## Repo contents

```
report/              Full incident report (PDF)
screenshots/          Individual Wazuh evidence screenshots
detection-rules/      Custom local_rules.xml (Wazuh)
```

## Tools used

Wazuh SIEM · Sysmon · Windows Event Log · THC-Hydra · FreeRDP · VirtualBox

---
**Author:** Afzal M · [LinkedIn](https://linkedin.com/in/afzal) · [GitHub](https://github.com/Afzal2301)
