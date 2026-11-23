#!/usr/bin/env python3
"""Parse Linux-style auth logs and emit triage summaries for SOC N1 practice."""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import DefaultDict, Dict, List, Optional

FAIL_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)
INVALID_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+)"
)
SUCCESS_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)"
)


@dataclass
class IpStats:
    failures: int = 0
    successes: int = 0
    users_failed: DefaultDict[str, int] = field(default_factory=lambda: defaultdict(int))
    users_success: DefaultDict[str, int] = field(default_factory=lambda: defaultdict(int))
    samples: List[str] = field(default_factory=list)

    def classify(self, fail_threshold: int = 5) -> str:
        if self.failures >= fail_threshold and self.successes > 0:
            return "incident_candidate"
        if self.failures >= fail_threshold and self.successes == 0:
            return "attack_attempt"
        if self.failures > 0 and self.successes == 0:
            return "noise_or_fp_candidate"
        if self.successes > 0 and self.failures == 0:
            return "success_only"
        if self.failures > 0 and self.successes > 0:
            return "noise_or_fp_candidate"  # low failure count then success (typo login)
        return "unknown"


def parse_line(line: str) -> Optional[Dict[str, str]]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    for regex, kind in (
        (FAIL_RE, "failure"),
        (INVALID_RE, "failure"),
        (SUCCESS_RE, "success"),
    ):
        match = regex.search(line)
        if match:
            data = match.groupdict()
            data["kind"] = kind
            data["raw"] = line
            return data
    return None


def analyze(path: Path) -> Dict[str, IpStats]:
    stats: Dict[str, IpStats] = defaultdict(IpStats)
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        event = parse_line(line)
        if not event:
            continue
        ip = event["ip"]
        bucket = stats[ip]
        if len(bucket.samples) < 3:
            bucket.samples.append(event["raw"])
        user = event.get("user", "?")
        if event["kind"] == "failure":
            bucket.failures += 1
            bucket.users_failed[user] += 1
        else:
            bucket.successes += 1
            bucket.users_success[user] += 1
    return dict(stats)


def print_summary(stats: Dict[str, IpStats], fail_threshold: int) -> None:
    print(f"{'Source IP':<18} {'Failures':>8} {'Success':>8}  Class")
    print("-" * 60)
    rows = sorted(
        stats.items(),
        key=lambda item: (item[1].classify(fail_threshold) != "incident_candidate", -item[1].failures),
    )
    for ip, bucket in rows:
        print(
            f"{ip:<18} {bucket.failures:>8} {bucket.successes:>8}  "
            f"{bucket.classify(fail_threshold)}"
        )


def write_report(stats: Dict[str, IpStats], out: Path, fail_threshold: int) -> None:
    lines = [
        "# Auth log triage report",
        "",
        f"Failure threshold for attack/incident classes: **{fail_threshold}**",
        "",
        "| Source IP | Failures | Successes | Class | Suggested N1 action |",
        "|-----------|----------|-----------|-------|---------------------|",
    ]
    action = {
        "incident_candidate": "Escalate to N2 — success after failures (credential compromise suspected)",
        "attack_attempt": "Ticket + consider block; monitor for success; follow brute-force playbook",
        "noise_or_fp_candidate": "Likely FP/noise — document; tune if recurring",
        "success_only": "Normal logins in window — no brute pattern",
        "unknown": "Manual review",
    }
    for ip, bucket in sorted(stats.items(), key=lambda x: -x[1].failures):
        cls = bucket.classify(fail_threshold)
        lines.append(
            f"| `{ip}` | {bucket.failures} | {bucket.successes} | `{cls}` | {action.get(cls, '')} |"
        )

    lines.extend(["", "## Samples", ""])
    for ip, bucket in stats.items():
        if not bucket.samples:
            continue
        lines.append(f"### `{ip}`")
        lines.append("```")
        lines.extend(bucket.samples)
        lines.append("```")
        lines.append("")

    lines.extend(
        [
            "## Classification legend",
            "",
            "- `incident_candidate` — treat as incident; escalate",
            "- `attack_attempt` — active brute force without confirmed access",
            "- `noise_or_fp_candidate` — below threshold or benign pattern",
            "- `success_only` — successes without failures in this file",
            "",
        ]
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote report: {out}")


def main() -> None:
    parser = argparse.ArgumentParser(description="SOC N1 auth.log parser")
    parser.add_argument("logfile", type=Path, help="Path to auth.log sample")
    parser.add_argument("--summary", action="store_true", help="Print table to stdout")
    parser.add_argument("--report", type=Path, help="Write Markdown triage report")
    parser.add_argument("--fail-threshold", type=int, default=5)
    args = parser.parse_args()

    if not args.logfile.exists():
        raise SystemExit(f"File not found: {args.logfile}")

    stats = analyze(args.logfile)
    if args.summary or not args.report:
        print_summary(stats, args.fail_threshold)
    if args.report:
        write_report(stats, args.report, args.fail_threshold)


if __name__ == "__main__":
    main()
