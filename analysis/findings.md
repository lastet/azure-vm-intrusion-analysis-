# Findings – Azure VM Intrusion Analysis

## Executive Summary

A publicly exposed Azure Windows VM was monitored to observe real-world authentication attack behavior.
Within hours of deployment, the system began receiving high-volume automated authentication attempts originating from multiple regions.

The observed activity is consistent with opportunistic internet-wide scanning and automated credential-based attacks.
No evidence of successful compromise, lateral movement, or post-authentication exploitation was identified during the observation window.

---

## 1. Rapid Discovery of Public-Facing Infrastructure

Shortly after the VM became accessible from the internet, it was targeted by automated authentication attempts.
This behavior demonstrates how quickly exposed infrastructure is discovered by automated scanners and botnets.

**Implication:**  
Public-facing systems are continuously probed regardless of size, purpose, or perceived value.

---

## 2. Credential and Password Spraying Activity

Multiple indicators of credential spraying were observed:

- Single IP addresses targeting hundreds of distinct usernames
- Consistent request rates per minute
- Repeated attempts using common and role-based account names

In several one-minute windows:
- ~300 unique accounts were targeted
- ~380 authentication attempts occurred
- Request rates averaged 6–7 attempts per second

This pattern clearly differentiates credential spraying from traditional brute-force attacks.

**Assessment:**  
The activity is fully automated and cannot be attributed to human-driven behavior.

---

## 3. Username Enumeration Attempts

A significant number of failed authentication attempts targeted:
- Common usernames (e.g., `administrator`, `admin`, `user`, `test`)
- Service-style or role-based account names
- Random or dictionary-generated usernames with single attempts

Single-attempt failures across many unique account names indicate username enumeration rather than password guessing.

**Assessment:**  
Attackers attempted to identify valid account names prior to focused attacks.

---

## 4. Administrator and Privileged Account Targeting

Administrative and privileged account names were disproportionately targeted.
Repeated failed authentication attempts were observed against usernames containing `"admin"` and similar role indicators.

**Assessment:**  
This aligns with standard attacker prioritization of high-value accounts using automated tooling.

---

## 5. Burst and Sustained Attack Patterns

Two distinct attack styles were identified:

### Burst Attacks
- High-volume attempts concentrated in short time windows
- Synchronized activity across multiple IP addresses
- Stable per-minute request rates

### Slow Brute Force Attempts
- Lower-frequency, sustained attempts over longer periods
- Indicative of controlled, scripted behavior designed to avoid detection

**Assessment:**  
The presence of both noisy and low-noise techniques suggests multiple automated attack strategies operating concurrently.

---

## 6. Geographic Distribution of Attack Sources

Authentication events enriched with GeoIP data revealed:

- Poland and Argentina accounted for the highest volume of failed attempts
- 100% failure rates from these regions (RetryRate = 1.0)
- Single isolated events from Taiwan and Japan (statistical noise)
- One successful login from the United States with no associated failures

**Assessment:**  
The geographic distribution is consistent with globally distributed automated attack infrastructure.
The lone successful login aligns with expected legitimate administrative access.

---

## 7. Absence of Post-Compromise Activity

No indicators of successful compromise were identified:

- No successful brute-force authentication beyond expected administrative access
- No evidence of lateral movement
- No suspicious process creation or post-authentication behavior observed

**Assessment:**  
Despite sustained attack activity, the environment remained uncompromised during the monitoring period.

---

## Final Assessment

The observed authentication activity represents automated, opportunistic attacks commonly directed at publicly exposed infrastructure.
The attacks relied on credential spraying, username enumeration, and dictionary-based techniques rather than targeted intrusion.

While attack volume was high, defensive controls and authentication mechanisms effectively prevented compromise.

This analysis demonstrates the importance of:
- Strong authentication policies
- Monitoring failed authentication patterns
- Limiting public exposure where possible
- Early detection of automated attack behavior
