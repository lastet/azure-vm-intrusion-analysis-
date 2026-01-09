# KQL Queries – Azure VM Intrusion Analysis

This document contains the KQL queries used to analyze real-world authentication attacks
against a publicly exposed Azure Windows virtual machine using Microsoft Sentinel.

The analysis focuses on identifying brute-force activity, credential spraying,
and attacker behavior patterns based on Windows authentication events.

---

## Geo-Enriched Failed Login Events

Enriches failed authentication events with GeoIP data to visualize attack sources.

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
SecurityEvent
| where EventID == 4625
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| project TimeGenerated, Account, Computer, AttackerIP = IpAddress,
          cityname, countryname, latitude, longitude



Account Spraying Detection
Multiple IPs targeting a single account
Identifies accounts that are repeatedly targeted from multiple source IP addresses.




SecurityEvent
| where EventID == 4625
| summarize
    Attempts = count(),
    SourceIPs = dcount(IpAddress)
  by Account
| where Attempts > 50
| order by SourceIPs desc

Username Enumeration Detection
Detects potential username discovery attempts based on single failed login attempts
against many unique account names.

SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by Account
| where Attempts == 1
| order by Account asc


Interpretation:
Typically random or dictionary-based usernames, indicating enumeration rather than brute force.



Administrator-Focused Attacks
Identifies failed authentication attempts against privileged or role-based accounts.



SecurityEvent
| where EventID == 4625
| where Account has "admin"
| summarize count() by Account
| order by count_ desc


Finding:
Repeated targeting of administrative account names is consistent with automated attack tooling.


Burst Attack Detection
High-volume attempts in short time windows

SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by IpAddress, bin(TimeGenerated, 1m)
| where Attempts > 20
| order by Attempts desc



Observed pattern:
Stable per-minute request rates
Synchronization across multiple IPs
Gradual decline in activity over time
Likely causes include rate-limiting, dictionary exhaustion, or loss of attacker interest.






Slow Brute Force Detection
Low-noise, sustained attacks


SecurityEvent
| where EventID == 4625
| summarize
    Attempts = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
  by IpAddress
| extend DurationMinutes = datetime_diff("minute", LastAttempt, FirstAttempt)
| where Attempts >= 5 and DurationMinutes >= 10
| order by DurationMinutes desc


SOC Assessment:
Indicates controlled, scripted attacks rather than noisy scanning behavior.


Password Spraying Detection
Single IP targeting many accounts
SecurityEvent
| where EventID == 4625
| summarize
    Attempts = count(),
    TargetedAccounts = dcount(Account)
  by IpAddress
| where TargetedAccounts >= 5
| order by TargetedAccounts desc


Classification:
Textbook password spraying behavior.


Credential Spraying Over Time
High-volume account targeting within short intervals


SecurityEvent
| where EventID == 4625
| summarize
    TargetedAccounts = dcount(Account),
    Attempts = count()
  by IpAddress, bin(TimeGenerated, 1m)
| where TargetedAccounts >= 5
| order by TargetedAccounts desc


Example Interpretation:

Single IP targeting ~300 unique accounts
~380 authentication attempts per minute
~6–7 requests per second
This activity cannot be human-driven and clearly indicates automation.


Account-Centric View
Single account targeted by multiple IPs over time

SecurityEvent
| where EventID == 4625
| summarize
    Attempts = count(),
    SourceIPs = dcount(IpAddress),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by Account
| where Attempts >= 20
| order by SourceIPs desc

Finding:
Coordinated attacks against common service and administrative accounts from multiple sources.


Geo-Based Authentication Outcome Analysis
Aggregates successful and failed logins by country and calculates retry rates.

let GeoIPDB_FULL = _GetWatchlist("geoip");
SecurityEvent
| where EventID in (4624, 4625)
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| summarize
    Success = countif(EventID == 4624),
    Failure = countif(EventID == 4625),
    Total = count()
  by countryname
| extend RetryRate = round(todouble(Failure) / todouble(Total), 3)
| order by RetryRate desc, Total desc
| project countryname, Success, Failure, Total, RetryRate


Key Observations:


Poland: 45,044 failures, 0 successes (RetryRate = 1.0)
Argentina: 22,582 failures, 0 successes (RetryRate = 1.0)
These patterns indicate fully automated authentication attacks with no successful access.
Taiwan / Japan: Single isolated events (noise, not signal)
United States: One successful login with no failures, consistent with legitimate access


Final Assessment

Despite high-volume brute-force and credential spraying activity, no indicators of
successful compromise, lateral movement, or post-exploitation behavior were observed.
The observed authentication activity is consistent with automated, opportunistic
scanning commonly targeting publicly exposed infrastructure.


