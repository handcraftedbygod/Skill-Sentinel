"""Merge static heuristics + sandbox findings into a Markdown/JSON report with
a risk score — framed as "what a skill actually did" vs. "what it claims to do"."""

from __future__ import annotations

import base64
import json
import posixpath
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.findings import Finding, Severity
from sentinel.sandbox import (
    SandboxRunResult,
    strace_connect_events,
    strace_notable_openat_events,
)
from sentinel.skillmd import SkillMetadata

# Explicit, auditable weights — used to compute a single numeric score on top
# of the per-finding severities, so two reports are comparable at a glance.
SEVERITY_WEIGHT = {
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 7,
    Severity.CRITICAL: 15,
}

SECRET_LOOKING_RE_PARTS = ("key", "token", "secret", "password", "credential", "api_key")

# Below this many notable opens under the same directory, list each individually
# (still useful detail). At or above it, collapse into one finding — otherwise a
# single bulk operation (e.g. a self-installer copying its own N bundled files to
# ~/.claude/skills/<name>/) emits one HIGH finding per file. Found on a real skill
# during the launch scan: 3388 near-identical findings inflated the score to
# 23719 — nonsensically above any genuine hidden_executable/exfil finding — while
# also making the report unreadable.
DIRECTORY_GROUP_THRESHOLD = 3

OPENAT_PATH_RE = re.compile(r'^AT_FDCWD,\s*"([^"]*)"')


def _openat_path(raw_args: str) -> str:
    match = OPENAT_PATH_RE.match(raw_args)
    return match.group(1) if match else raw_args


def _body_looks_like_secret(body_base64: str) -> bool:
    try:
        decoded = base64.b64decode(body_base64).decode("utf-8", errors="ignore").lower()
    except Exception:
        return False
    return any(part in decoded for part in SECRET_LOOKING_RE_PARTS)


def sandbox_result_findings(result: SandboxRunResult) -> list[Finding]:
    """Turn one sandboxed run's raw observations into report-ready Findings."""
    findings: list[Finding] = []
    source = f"invocation: {result.invocation}"

    if result.timed_out:
        findings.append(
            Finding(
                category="sandbox_timeout",
                severity=Severity.MEDIUM,
                summary=f"`{result.invocation}` did not finish within the sandbox timeout",
                source=source,
            )
        )
    elif not result.strace_events:
        # Zero events at all (not even the traced process's own execve) almost
        # always means the trace never actually captured anything — a broken
        # mount, a container that failed to start, etc. — not a skill that
        # legitimately did nothing. Surfacing this distinctly matters: without
        # it, a broken sandbox and a genuinely clean run render identically.
        findings.append(
            Finding(
                category="sandbox_no_trace_data",
                severity=Severity.HIGH,
                summary=f"`{result.invocation}` produced no trace data at all — the sandbox "
                "likely failed to run rather than the skill being clean; treat this result as "
                "inconclusive, not as a clean bill of health",
                source=source,
            )
        )

    for flow in result.http_flows:
        if flow.kind != "http_request":
            continue
        looks_secret = _body_looks_like_secret(flow.body_base64)
        findings.append(
            Finding(
                category="network_request",
                severity=Severity.CRITICAL if looks_secret else Severity.HIGH,
                summary=f"{flow.method} https://{flow.host}{flow.path}"
                + (" (request body looks like it may contain a secret)" if looks_secret else ""),
                detail=f"headers={flow.headers}",
                source=source,
                extra={"host": flow.host, "path": flow.path, "body_base64": flow.body_base64},
            )
        )

    for flow in result.http_flows:
        if flow.kind == "tls_handshake_failed":
            findings.append(
                Finding(
                    category="tls_handshake_failed",
                    severity=Severity.MEDIUM,
                    summary=f"TLS handshake failed for SNI={flow.sni} (possible certificate pinning)",
                    source=source,
                )
            )

    by_directory: dict[str, list] = {}
    for event in strace_notable_openat_events(result.strace_events):
        directory = posixpath.dirname(_openat_path(event.raw_args))
        by_directory.setdefault(directory, []).append(event)

    for directory, group in by_directory.items():
        if len(group) < DIRECTORY_GROUP_THRESHOLD:
            for event in group:
                findings.append(
                    Finding(
                        category="out_of_scope_file_access",
                        severity=Severity.HIGH,
                        summary=f"Opened a file outside the skill's own directory: {event.raw_args}",
                        source=source,
                    )
                )
        else:
            sample = ", ".join(_openat_path(e.raw_args) for e in group[:3])
            findings.append(
                Finding(
                    category="out_of_scope_file_access",
                    severity=Severity.HIGH,
                    summary=f"Opened {len(group)} files outside the skill's own directory, all "
                    f"under `{directory}/` (e.g. {sample}, ...)",
                    source=source,
                )
            )

    observed_hosts = {f.host for f in result.http_flows if f.host}
    raw_connects = strace_connect_events(result.strace_events)
    if raw_connects and not observed_hosts:
        # A connect() attempt strace saw but mitmproxy never turned into a
        # flow — e.g. a hardcoded-IP attempt that skipped DNS and never
        # completed a handshake mitmproxy could decrypt.
        findings.append(
            Finding(
                category="network_connection",
                severity=Severity.MEDIUM,
                summary=f"{len(raw_connects)} outbound network connection attempt(s) observed "
                "with no decrypted request captured",
                source=source,
            )
        )

    return findings


@dataclass
class Report:
    skill_path: str
    skill_name: str | None
    skill_description: str | None
    findings: list[Finding]
    risk_score: int
    risk_level: Severity
    invocations: list[str]
    generated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "skill_path": self.skill_path,
            "skill_name": self.skill_name,
            "skill_description": self.skill_description,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "invocations": self.invocations,
            "generated_at": self.generated_at,
            "findings": [f.to_dict() for f in self.findings],
        }


def compute_risk(findings: list[Finding]) -> tuple[int, Severity]:
    if not findings:
        return 0, Severity.LOW
    score = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    level = max((f.severity for f in findings), key=lambda s: s.rank)
    return score, level


def build_report(
    skill_dir: Path,
    metadata: SkillMetadata,
    heuristic_findings: list[Finding],
    sandbox_results: list[SandboxRunResult] | None,
    invocations: list[str],
) -> Report:
    all_findings = list(heuristic_findings)
    for result in sandbox_results or []:
        all_findings.extend(sandbox_result_findings(result))

    score, level = compute_risk(all_findings)

    return Report(
        skill_path=str(skill_dir),
        skill_name=metadata.name,
        skill_description=metadata.description,
        findings=all_findings,
        risk_score=score,
        risk_level=level,
        invocations=invocations,
    )


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2)


def render_markdown(report: Report) -> str:
    lines: list[str] = []
    lines.append(f"# Skill Sentinel report: {report.skill_name or report.skill_path}")
    lines.append("")
    if report.skill_description:
        lines.append(f"> {report.skill_description}")
        lines.append("")
    lines.append(f"**Risk score:** {report.risk_score} ({report.risk_level.value.upper()})")
    lines.append("")
    lines.append(f"**Invocations attempted:** {', '.join(f'`{i}`' for i in report.invocations) or '(none)'}")
    lines.append("")

    network_findings = [f for f in report.findings if f.category in ("network_request", "network_connection")]
    lines.append("## Network activity")
    if network_findings:
        for f in network_findings:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.summary}")
    else:
        lines.append("- No network activity observed.")
    lines.append("")

    subprocess_findings = [
        f for f in report.findings if f.category in ("sandbox_timeout", "sandbox_no_trace_data")
    ]
    lines.append("## Subprocess / execution")
    if subprocess_findings:
        for f in subprocess_findings:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.summary}")
    else:
        lines.append("- Nothing unusual observed.")
    lines.append("")

    file_findings = [f for f in report.findings if f.category == "out_of_scope_file_access"]
    lines.append("## Out-of-scope file access")
    if file_findings:
        for f in file_findings:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.summary}")
    else:
        lines.append("- No file access outside the skill's own directory observed.")
    lines.append("")

    static_findings = [
        f
        for f in report.findings
        if f.category in ("base64_blob", "eval_exec_decode", "hidden_executable")
    ]
    lines.append("## Static red flags")
    if static_findings:
        for f in static_findings:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.summary} ({f.source})")
    else:
        lines.append("- None found.")
    lines.append("")

    other_findings = [
        f
        for f in report.findings
        if f
        not in network_findings + subprocess_findings + file_findings + static_findings
    ]
    if other_findings:
        lines.append("## Other findings")
        for f in other_findings:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.summary}")
        lines.append("")

    return "\n".join(lines)
