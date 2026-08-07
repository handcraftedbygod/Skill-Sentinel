"""Unit tests for sentinel.console: wordmark/welcome rendering, and the
markup=False guard against skill-content that looks like Rich markup."""

import io

from rich.console import Console

from sentinel.console import (
    CollectionProgress,
    busy_status,
    file_scan_progress,
    maybe_print_banner,
    print_report,
    print_summary_table,
    print_welcome,
)
from sentinel.findings import Confidence, Finding, Severity
from sentinel.report import Report, risk_guidance


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


def test_summary_table_shows_overall_risk_score_and_guidance():
    low_report = _report("minor thing", "quiet-skill")
    low_report.risk_score = 1
    low_report.risk_level = Severity.LOW
    critical_report = _report("bad thing", "dangerous-skill")
    critical_report.risk_score = 30
    critical_report.risk_level = Severity.CRITICAL

    console, buf = _console(no_color=True)
    print_summary_table(console, [low_report, critical_report])
    out = buf.getvalue()
    assert "Overall risk score: 30 (CRITICAL, driven by dangerous-skill)" in out
    assert risk_guidance(critical_report) in out


def test_collection_progress_transitions_and_shows_file_progress():
    console, buf = _console(no_color=True)
    with CollectionProgress(console, ["skill-a", "skill-b", "skill-c"], [4, 3, 2]) as progress:
        progress.start(0, "skill-a")
        progress.advance_file(0, 0)
        progress.advance_file(0, 1)
        progress.skip(1)
        progress.start(2, "skill-c")
        progress.finish(2, Severity.CRITICAL, 30, 5)
    out = buf.getvalue()
    assert "skill-a" in out
    assert "Skipped" in out
    assert "Done" in out
    assert "CRITICAL (30)" in out
    assert "2/4" in out  # skill-a's file progress as of its last update
    assert "50%" in out  # skill-a: 2/4 files
    assert "Overall" in out


def test_collection_progress_shows_totals_upfront_for_queued_rows():
    # A row that hasn't started scanning yet should still show its real file
    # total (known via the file_counts pre-pass), not a bare placeholder — the
    # Overall row's own total must be accurate from the very first frame too.
    console, buf = _console(no_color=True)
    with CollectionProgress(console, ["skill-a", "skill-b"], [4, 6]):
        pass
    out = buf.getvalue()
    assert "0/4" in out
    assert "0/6" in out
    assert "0/10" in out  # Overall: 0 done out of 4+6 total


def test_collection_progress_sandbox_phase_pulses_instead_of_freezing_at_100():
    # Regression case: once the static file pass hits N/N (100%), a full
    # (non-static) scan still has the Docker run ahead of it - the row must
    # not sit showing "Scanning, 100%" for that whole wait, which reads as
    # stuck rather than as a distinct, still-in-progress phase.
    console, buf = _console(no_color=True)
    with CollectionProgress(console, ["skill-a"], [2]) as progress:
        progress.start(0, "skill-a")
        progress.advance_file(0, 0)
        progress.advance_file(0, 0)
        progress.running_sandbox(0)
    out = buf.getvalue()
    assert "Sandbox" in out
    assert "2/2" in out  # files pass genuinely finished
    # A brief "Scanning, 100%" frame is expected right as the last file
    # lands (real, momentary) - what must NOT happen is the *final* state
    # (after running_sandbox()) still showing that misleading 100%.
    skill_a_lines = [line for line in out.splitlines() if "skill-a" in line]
    assert skill_a_lines and "100%" not in skill_a_lines[-1]


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


def test_file_scan_progress_quiet_yields_noop_callback():
    console, buf = _console()
    with file_scan_progress(console, 3, quiet=True) as advance:
        advance("a.py")
    assert buf.getvalue() == ""


def test_file_scan_progress_zero_files_yields_noop_callback():
    console, buf = _console()
    with file_scan_progress(console, 0, quiet=False) as advance:
        advance("a.py")
    assert buf.getvalue() == ""


def test_file_scan_progress_non_tty_yields_noop_callback():
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, markup=False, highlight=False)
    with file_scan_progress(console, 3, quiet=False) as advance:
        advance("a.py")
    assert buf.getvalue() == ""


def test_file_scan_progress_terminal_advances_without_crashing():
    console, buf = _console()
    with file_scan_progress(console, 2, quiet=False) as advance:
        advance("a.py")
        advance("b.py")
    assert "Scanning files" in buf.getvalue()


def test_file_scan_progress_does_not_interpret_bracket_markup_in_filename():
    # A scanned file's relative path is attacker-controlled content — must
    # render literally, not be parsed as Rich markup (same guard as
    # test_report_table_does_not_interpret_bracket_markup_in_skill_content).
    console, buf = _console()
    with file_scan_progress(console, 1, quiet=False) as advance:
        advance("[bold red]evil[/bold red].py")
    assert "[bold red]evil[/bold red].py" in buf.getvalue()
