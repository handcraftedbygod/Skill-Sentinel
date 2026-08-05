"""Unit tests for sentinel.console: wordmark/welcome rendering, and the
markup=False guard against skill-content that looks like Rich markup."""

import io

from rich.console import Console

from sentinel.console import (
    maybe_print_wordmark,
    print_summary_table,
    print_report,
    print_welcome,
)
from sentinel.findings import Confidence, Finding, Severity
from sentinel.report import Report


def _console(*, no_color=False):
    buf = io.StringIO()
    console = Console(
        file=buf,
        force_terminal=True,
        width=200,
        no_color=no_color,
        color_system=None if no_color else "auto",
        markup=False,
        highlight=False,
    )
    return console, buf


def _report(summary: str, skill_name: str = "test-skill") -> Report:
    finding = Finding(
        category="network_request",
        severity=Severity.HIGH,
        summary=summary,
        confidence=Confidence.HIGH,
        mitre_technique="T1071",
    )
    return Report(
        skill_path="/tmp/skill",
        skill_name=skill_name,
        skill_description="A test skill.",
        findings=[finding],
        risk_score=10,
        risk_level=Severity.HIGH,
        invocations=["python run.py"],
    )


def test_wordmark_color_has_ansi_when_forced_terminal():
    console, buf = _console()
    maybe_print_wordmark(console)
    out = buf.getvalue()
    assert "\x1b[" in out
    assert "SkillTrace" in out


def test_wordmark_no_color_flag_suppresses_ansi():
    console, buf = _console(no_color=True)
    maybe_print_wordmark(console)
    out = buf.getvalue()
    assert "\x1b[" not in out
    assert "SkillTrace" in out


def test_welcome_lists_quickstart_commands():
    console, buf = _console(no_color=True)
    print_welcome(console)
    out = buf.getvalue()
    assert "Get started" in out
    assert "skilltrace scan ./my-skill" in out


def test_report_table_does_not_interpret_bracket_markup_in_skill_content():
    console, buf = _console()
    report = _report("[bold red]injected[/bold red] via skill content")
    print_report(console, report)
    out = buf.getvalue()
    assert "[bold red]injected[/bold red] via skill content" in out


def test_summary_table_lists_all_skills():
    console, buf = _console(no_color=True)
    reports = [_report("finding one", "skill-one"), _report("finding two", "skill-two")]
    print_summary_table(console, reports)
    out = buf.getvalue()
    assert "skill-one" in out
    assert "skill-two" in out
