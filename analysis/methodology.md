# Methodology – Azure VM Intrusion Analysis

This document outlines the methodology used to observe, collect, and analyze real-world authentication attack activity against a publicly exposed Azure Windows virtual machine.

The goal of this project was not to simulate attacks, but to capture and analyze naturally occurring opportunistic intrusion attempts commonly seen on internet-facing infrastructure.

---

## 1. Environment Preparation

A Windows-based Azure Virtual Machine was deployed and intentionally exposed to the public internet to observe unsolicited authentication attempts.

Key configuration steps:
- Public IP address assigned to the VM
- Remote authentication services exposed
- Windows Security Event logging enabled
- Logs forwarded to Azure Log Analytics
- Microsoft Sentinel configured for centralized log analysis

No defensive hardening or rate limiting was applied during the observation window to avoid altering attacker behavior.

---

## 2. Data Collection

All analysis was performed using Windows Security Event logs collected in Azure Log Analytics.

Primary data source:
- **SecurityEvent** table

Relevant event types:
- **4625** – Failed logon attempts
- **4624** – Successful logons (used for validation and contrast)

Logs were collected continuously from the moment the VM became publicly accessible.

---

## 3. Geographic Enrichment

To add geographic context to authentication attempts, a custom GeoIP watchlist was uploaded into Microsoft Sentinel.

Method:
- Source IP addresses were enriched using `ipv4_lookup`
- Country, city, latitude, and longitude fields were appended to authentication events

This enabled region-based analysis and visualization of attack concentration by geographic origin.

---

## 4. Analytical Approach

Rather than relying on single indicators, analysis focused on **behavioral patterns over time**, using aggregation and correlation.

The following analytical perspectives were applied:

### 4.1 Account-Centric Analysis
- Identified accounts targeted repeatedly
- Measured number of attempts per account
- Counted distinct source IPs targeting the same account
- Highlighted common administrative and service account names

Purpose:
To detect account spraying and role-based targeting behavior.

---

### 4.2 IP-Centric Analysis
- Aggregated authentication attempts by source IP
- Measured number of unique accounts targeted per IP
- Identified burst patterns using time binning

Purpose:
To distinguish brute-force, password spraying, and automated attack tooling.

---

### 4.3 Time-Series Analysis
- Authentication events grouped into 1-minute intervals
- Attempt volume analyzed per IP over time
- Sustained vs burst activity compared

Purpose:
To identify automation, rate consistency, and scripted behavior.

---

### 4.4 Geographic Outcome Analysis
- Successful vs failed logons compared by country
- Retry rates calculated per region

Purpose:
To separate legitimate access from automated attack traffic and reduce false assumptions.

---

## 5. Interpretation Strategy

Results were interpreted conservatively using well-established SOC heuristics:

- High-volume + consistent timing → automation
- Many accounts + single IP → credential spraying
- Many IPs + single account → account spraying
- Dictionary-style usernames → enumeration
- Zero successful logins → opportunistic scanning

No conclusions were drawn from statistically insignificant data (e.g., single isolated events).

---

## 6. Limitations

- Observation window was limited to a short time period
- Single-host environment (no internal network for lateral movement)
- No endpoint telemetry beyond Windows Security Events

As a result, conclusions are limited to **pre-authentication attack behavior**.

---

## 7. Ethical Considerations

- No attacker interaction or countermeasures were performed
- No payloads or exploitation attempts were initiated
- All observed activity was unsolicited and passive

The project strictly focused on defensive observation and analysis.

---

## 8. Outcome

This methodology enabled clear identification of:
- Automated brute-force activity
- Credential and account spraying patterns
- Geographic concentration of attack sources
- Absence of post-authentication compromise

The approach mirrors real-world SOC triage workflows used to assess internet-exposed assets.
