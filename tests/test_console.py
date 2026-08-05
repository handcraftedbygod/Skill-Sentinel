"""Unit tests for sentinel.console: wordmark/welcome rendering, and the
markup=False guard against skill-content that looks like Rich markup."""

import io

from rich.console import Console

from sentinel.console import (
    CollectionProgress,
    maybe_print_banner,
    print_summary_table,
    print_report,
    print_welcome,
    busy_status,
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


def test_banner_color_has_ansi_when_forced_terminal():
    console, buf = _console()
    maybe_print_banner(console)
    out = buf.getvalue()
    assert "\x1b[" in out
    assert "Static heuristics" in out


def test_banner_no_color_flag_suppresses_ansi():
    console, buf = _console(no_color=True)
    maybe_print_banner(console)
    out = buf.getvalue()
    assert "\x1b[" not in out
    assert "Static heuristics" in out


def test_banner_hidden_when_not_a_terminal():
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, markup=False, highlight=False)
    maybe_print_banner(console)
    assert buf.getvalue() == ""


class _ExplodingFile:
    """Simulates Rich's legacy-Windows-console writer, which can raise
    UnicodeEncodeError regardless of content — the banner must degrade to a
    plain print(), never crash the CLI over purely decorative output."""

    def write(self, text):
        raise UnicodeEncodeError("cp1252", text, 0, 1, "simulated legacy console")

    def flush(self):
        pass

    def isatty(self):
        return True


def test_banner_falls_back_when_console_write_raises_unicode_error(capsys):
    console = Console(file=_ExplodingFile(), force_terminal=True, markup=False, highlight=False)
    maybe_print_banner(console)
    assert "SKILLTRACE" in capsys.readouterr().out


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


def test_collection_progress_transitions_queued_scanning_skipped_done():
    console, buf = _console(no_color=True)
    with CollectionProgress(console, ["skill-a", "skill-b", "skill-c"]) as progress:
        progress.start(0, "skill-a")
        progress.skip(1)
        progress.start(2, "skill-c")
        progress.finish(2, Severity.CRITICAL, 30)
    out = buf.getvalue()
    assert "skill-a" in out
    assert "Skipped" in out
    assert "Done" in out
    assert "CRITICAL (30)" in out


def test_busy_status_quiet_suppresses_output(capsys):
    console, buf = _console()
    ran = False
    with busy_status(console, "Running in sandbox...", quiet=True):
        ran = True
    assert ran
    assert buf.getvalue() == ""
    assert capsys.readouterr().out == ""


def test_busy_status_non_tty_prints_plain_line():
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, markup=False, highlight=False)
    ran = False
    with busy_status(console, "Running in sandbox...", quiet=False):
        ran = True
    assert ran
    assert "Running in sandbox..." in buf.getvalue()


def test_busy_status_terminal_uses_spinner_without_crashing():
    console, buf = _console()
    ran = False
    with busy_status(console, "Running in sandbox...", quiet=False):
        ran = True
    assert ran
