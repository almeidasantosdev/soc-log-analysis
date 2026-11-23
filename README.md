# SOC Log Analysis — Parsers & FP vs Incident Reports

Python and Bash utilities for **SOC N1** practice:

- Parse Linux `auth.log` style lines  
- Simple correlation (failures → success from same IP)  
- Generate a **false positive vs incident** triage report  

Designed to work with sample logs in this repo and with events from [soc-homelab](https://github.com/almeidasantosdev/soc-homelab).

---

## Quick start

```bash
# Python 3.10+ recommended (stdlib only — no pip required)
python scripts/parse_auth_log.py samples/auth.log --summary

# Correlation + triage report (Markdown)
python scripts/parse_auth_log.py samples/auth.log --report reports/triage-auth.md

# Bash helper (requires grep/awk; Git Bash / WSL / Linux)
bash scripts/correlate_auth.sh samples/auth.log
```

---

## What the report answers

For each source IP the tools classify:

| Class | Meaning |
|-------|---------|
| `noise_or_fp_candidate` | Failures only, below aggressive thresholds, or known patterns |
| `attack_attempt` | Brute force failures without success |
| `incident_candidate` | Success after failures → escalate per N1 playbook |
| `success_only` | Successful logins without prior failures in window |

This mirrors the alert map in [soc-detections](https://github.com/almeidasantosdev/soc-detections) and playbooks in [soc-n1-playbooks](https://github.com/almeidasantosdev/soc-n1-playbooks).

---

## Layout

```
soc-log-analysis/
├── README.md
├── scripts/
│   ├── parse_auth_log.py
│   ├── correlate_auth.sh
│   └── send_sample_alert.sh
├── samples/
│   ├── auth.log
│   └── firewall_denies.log
└── reports/
    └── .gitkeep
```

---

## Example output

```text
Source IP          Failures  Success  Class
203.0.113.10             12        1  incident_candidate
198.51.100.44             8        0  attack_attempt
10.0.0.12                 0        3  success_only
```

---

## Disclaimer

Synthetic logs only. Educational Blue Team tooling — not a production SIEM replacement.
