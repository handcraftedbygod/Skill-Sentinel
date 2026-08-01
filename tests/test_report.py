"""Regression coverage for sentinel.report's scoring/grouping behavior."""

from sentinel.findings import Finding, Severity
from sentinel.report import Report, render_html, render_html_multi, sandbox_result_findings
from sentinel.sandbox import HttpFlow, SandboxRunResult, StraceEvent


def _openat_event(path: str) -> StraceEvent:
    return StraceEvent(
        pid="1",
        timestamp="00:00:00.000000",
        syscall="openat",
        raw_args=f'AT_FDCWD, "{path}", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666',
        result="3",
    )


def test_many_opens_under_one_directory_collapse_to_one_finding():
    # Regression test: a self-installer copying its own N bundled files to
    # ~/.claude/skills/<name>/ emitted one HIGH finding per file — found
    # inflating a real skill's score to 23719 (3388 near-identical findings)
    # during the launch scan, dwarfing genuinely severe findings like a single
    # hidden_executable (score 15).
    events = [
        _openat_event(f"/root/.claude/skills/my-skill/scripts/file{i}.py") for i in range(10)
    ]
    result = SandboxRunResult(
        invocation="python3 install.py",
        exit_code=0,
        timed_out=False,
        strace_events=events,
        dns_queries=[],
        http_flows=[],
    )

    findings = sandbox_result_findings(result)
    file_findings = [f for f in findings if f.category == "out_of_scope_file_access"]
    assert len(file_findings) == 1
    assert "10 files" in file_findings[0].summary


def test_repeated_identical_network_requests_collapse_to_one_finding():
    # Regression test: pip retrying the same blocked URL after the sandbox's
    # network sinkhole emitted one HIGH network_request finding per retry — found
    # contributing 42 of 77 points on a real skill (alanl1234/
    # xiaohongshu-matrices-cli) during the launch scan for a single install
    # attempt, not 6 distinct destinations.
    flows = [
        HttpFlow(kind="http_request", host="pypi.org", port=443, method="GET", path="/simple/foo/")
        for _ in range(6)
    ]
    result = SandboxRunResult(
        invocation="sh scripts/install.sh",
        exit_code=0,
        timed_out=False,
        strace_events=[],
        dns_queries=[],
        http_flows=flows,
    )

    findings = sandbox_result_findings(result)
    net_findings = [f for f in findings if f.category == "network_request"]
    assert len(net_findings) == 1
    assert "6x" in net_findings[0].summary


def test_a_couple_of_scattered_opens_stay_individual():
    events = [_openat_event("/root/.ssh/id_rsa"), _openat_event("/root/.aws/credentials")]
    result = SandboxRunResult(
        invocation="python3 main.py",
        exit_code=0,
        timed_out=False,
        strace_events=events,
        dns_queries=[],
        http_flows=[],
    )

    findings = sandbox_result_findings(result)
    file_findings = [f for f in findings if f.category == "out_of_scope_file_access"]
    assert len(file_findings) == 2


def _clean_report(name: str = "clean-skill") -> Report:
    return Report(
        skill_path=f"/tmp/{name}",
        skill_name=name,
        skill_description="A totally normal skill.",
        findings=[],
        risk_score=0,
        risk_level=Severity.LOW,
        invocations=["python3 main.py"],
    )


def test_render_html_is_well_formed_and_shows_clean_state():
    output = render_html(_clean_report())
    assert output.startswith("<!doctype html>")
    assert output.rstrip().endswith("</html>")
    assert "clean-skill" in output
    assert "LOW" in output
    assert "None found" in output  # static red flags empty state
    assert "Not run" in output  # semantic review not run, default False


def test_render_html_escapes_adversarial_finding_content():
    # Regression guard: everything embedded here (skill names, finding
    # summaries/details/sources) ultimately comes from a scanned skill's own,
    # potentially adversarial, content. A malicious skill naming itself
    # "<script>alert(1)</script>" must not become live markup in the very
    # report meant to warn about it.
    report = Report(
        skill_path="/tmp/evil",
        skill_name="<script>alert(1)</script>",
        skill_description=None,
        findings=[
            Finding(
                category="out_of_scope_file_access",
                severity=Severity.HIGH,
                summary='<img src=x onerror=alert(1)>',
                detail="<b>bold detail</b>",
                source="<i>source</i>",
            )
        ],
        risk_score=7,
        risk_level=Severity.HIGH,
        invocations=[],
    )
    output = render_html(report)
    assert "<script>alert(1)</script>" not in output
    assert "<img src=x onerror=alert(1)>" not in output
    assert "&lt;script&gt;" in output
    assert "&lt;img src=x onerror=alert(1)&gt;" in output


def test_render_html_multi_collapses_to_single_report():
    assert render_html_multi([_clean_report()]) == render_html(_clean_report())


def test_render_html_multi_shows_summary_table_and_per_skill_sections():
    reports = [_clean_report("skill-a"), _clean_report("skill-b")]
    output = render_html_multi(reports)
    assert "2 skills" in output
    assert '<table class="summary">' in output
    assert output.count("<details>") == 2
    assert "skill-a" in output
    assert "skill-b" in output
