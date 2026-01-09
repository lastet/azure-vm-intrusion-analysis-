# azure-vm-intrusion-analysis-# Azure VM Intrusion Monitoring & Log Analysis

## Overview
This project documents the analysis of real-world authentication attacks against a public-facing Azure Windows virtual machine.  
The environment was intentionally exposed to the internet to observe attacker behavior and analyze security events using Microsoft Sentinel and KQL.

Within hours of deployment, the VM began receiving high-volume automated authentication attempts originating from multiple regions.

---

## Environment
- Azure Virtual Machine (Windows)
- Microsoft Sentinel
- Log Analytics Workspace
- Windows Security Event Logs
- Custom GeoIP watchlist

---

## Data Sources
- Windows SecurityEvent logs
- Event IDs analyzed include:
  - **4625** — Failed logon attempts
  - **4624** — Successful logons
  - Supporting system and authentication events for validation

---

## Key Findings
- The VM was rapidly discovered and targeted after becoming publicly accessible
- Sustained **credential spraying** activity observed:
  - Single source IPs targeting hundreds of distinct account names
  - Consistent attack rates per minute indicating automation
- Attackers focused on common usernames such as:
  - administrator, admin, user, test, scanner, service-style accounts
- Geographic enrichment revealed concentrated attack sources by region
- No evidence of successful compromise beyond expected system activity
- No indicators of post-authentication exploitation or lateral movement detected

---

## Analysis Techniques
- Time-series aggregation of authentication failures
- Correlation of **Account + IP Address + Time**
- Detection of credential spraying via distinct account counts per IP
- GeoIP enrichment using a custom watchlist
- Validation of successful logons and system activity to rule out compromise

---

## Repository Structure

.
├── README.md
├── screenshots/
│ ├── 01-geo-map.png
│ ├── 02-credential-spraying.png
│ ├── 03-account-targeting.png
│ └── raw/
│ └── exploratory-analysis/
├── kql/
│ ├── failed-logons.kql
│ ├── credential-spraying.kql
│ ├── account-correlation.kql
│ └── post-auth-validation.kql
└── notes/
└── investigation-notes.md




---

## Outcome
This lab demonstrates how quickly exposed infrastructure is targeted and how log analysis can be used to distinguish automated attack behavior from legitimate activity.

The virtual machine was decommissioned after analysis.

---

## Skills Demonstrated
- Security log analysis
- Microsoft Sentinel & KQL
- Threat behavior identification
- Credential attack detection
- Analytical documentation
