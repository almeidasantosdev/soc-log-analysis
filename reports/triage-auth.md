# Auth log triage report

Failure threshold for attack/incident classes: **5**

| Source IP | Failures | Successes | Class | Suggested N1 action |
|-----------|----------|-----------|-------|---------------------|
| `203.0.113.10` | 12 | 1 | `incident_candidate` | Escalate to N2 — success after failures (credential compromise suspected) |
| `198.51.100.44` | 8 | 0 | `attack_attempt` | Ticket + consider block; monitor for success; follow brute-force playbook |
| `10.0.0.12` | 1 | 1 | `noise_or_fp_candidate` | Likely FP/noise — document; tune if recurring |
| `10.0.0.20` | 0 | 3 | `success_only` | Normal logins in window — no brute pattern |

## Samples

### `203.0.113.10`
```
Mar 23 08:01:01 lab-web-01 sshd[1101]: Failed password for root from 203.0.113.10 port 52201 ssh2
Mar 23 08:01:04 lab-web-01 sshd[1102]: Failed password for root from 203.0.113.10 port 52202 ssh2
Mar 23 08:01:07 lab-web-01 sshd[1103]: Failed password for root from 203.0.113.10 port 52203 ssh2
```

### `198.51.100.44`
```
Mar 23 08:05:01 lab-web-01 sshd[1201]: Failed password for root from 198.51.100.44 port 40001 ssh2
Mar 23 08:05:03 lab-web-01 sshd[1202]: Failed password for root from 198.51.100.44 port 40002 ssh2
Mar 23 08:05:05 lab-web-01 sshd[1203]: Failed password for root from 198.51.100.44 port 40003 ssh2
```

### `10.0.0.12`
```
Mar 23 08:10:01 lab-web-01 sshd[1301]: Failed password for alice from 10.0.0.12 port 51001 ssh2
Mar 23 08:10:05 lab-web-01 sshd[1302]: Accepted publickey for alice from 10.0.0.12 port 51002 ssh2
```

### `10.0.0.20`
```
Mar 23 08:12:00 lab-web-01 sshd[1401]: Accepted publickey for deploy from 10.0.0.20 port 22022 ssh2
Mar 23 08:12:30 lab-web-01 sshd[1402]: Accepted publickey for deploy from 10.0.0.20 port 22023 ssh2
Mar 23 08:13:00 lab-web-01 sshd[1403]: Accepted publickey for deploy from 10.0.0.20 port 22024 ssh2
```

## Classification legend

- `incident_candidate` — treat as incident; escalate
- `attack_attempt` — active brute force without confirmed access
- `noise_or_fp_candidate` — below threshold or benign pattern
- `success_only` — successes without failures in this file
