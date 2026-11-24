# SentinelHub - MITRE ATT&CK Coverage

## Detection Coverage

| Detection | Technique |
|---|---|
| Brute Force | T1110 |
| Web Scanning | T1595 |
| Valid Account Indicators | T1078 |
| Potential Kerberoasting | T1558.003 |
| Potential AS-REP Roasting | T1558.004 |
| Remote Desktop Protocol | T1021.001 |
| SMB Administrative Shares | T1021.002 |
| Remote Services | T1021 |
| Service Execution | T1569.002 |
| Account Manipulation | T1098 |
| Administrative Group Changes | T1098.007 |
| Scheduled Tasks | T1053.005 |
| Windows Services | T1543.003 |
| Create Account | T1136 |
| Registry Run Keys | T1547.001 |
| Clear Windows Event Logs | T1070.001 |
| Network Protocol Indicators | T1071 |
| DNS Indicators | T1071.004 |

## Event Sources

- Linux authentication logs
- Nginx and Apache access logs
- Windows Security JSON/JSONL logs
- Sysmon JSON/JSONL logs
- Synthetic security telemetry

## Validation

Detection rules are validated using synthetic events
and automated pytest tests.

## Limitations

- Detection rules identify indicators, not confirmed attacks.
- Native EVTX ingestion is not implemented.
- Real Active Directory validation is pending.
- Correlation operates within individual detection batches.
- Thresholds require environment-specific tuning.
- Authentication and production deployment hardening
  remain future work.
