"""Terminal presentation for the CLI: wordmark, welcome screen, styled
errors/warnings, and Rich-rendered reports. Replaces the old hand-rolled
ANSI banner/mascot.

`markup=False` on every Console is load-bearing, not cosmetic: finding
summaries, skill descriptions, and source strings come from scanned skill
content, which is adversarial input. Rich's default bracket markup
(`[bold red]...[/]`, and `[link=...]` in particular — a known OSC-8
hyperlink-injection vector) must not be live on attacker-controlled text,
the same reason report.py's HTML renderer runs everything through
html.escape().
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from sentinel.findings import Severity
from sentinel.report import Report

SEVERITY_STYLE = {
    Severity.LOW: "green",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "dark_orange",
    Severity.CRITICAL: "bold red",
}

_QUICKSTART = [
    ("skilltrace scan ./my-skill", "scan a local skill directory"),
    ("skilltrace scan <git-url>", "scan a skill, or a whole collection repo, from git"),
    ("skilltrace scan ./my-skill --static", "static-only scan, no Docker required"),
    ("skilltrace scan ./my-skill --html", "also write a self-contained HTML report"),
]


def make_console(*, stderr: bool, no_color: bool = False) -> Console:
    # No `file=` kwarg: leaving it unset makes Rich resolve sys.stdout/sys.stderr
    # dynamically on every write (via Console.file's property), not a reference
    # captured at construction time — matters for pytest's capsys, which swaps
    # the streams after the test body starts.
    #
    # no_color=None (not False) when --no-color wasn't passed: Rich only reads
    # the NO_COLOR env var itself when no_color is None — passing an explicit
    # False, even as a default, would silently defeat NO_COLOR support.
    #
    # color_system=None (not just no_color=True) when --no-color *was* passed:
    # Rich's no_color only strips color codes and leaves attribute codes (bold,
    # dim, ...) in place, which isn't what a user asking for --no-color expects.
    # color_system=None disables ANSI rendering entirely, the same code path
    # Rich itself takes for a non-terminal/non-color-capable stream.
    return Console(
        stderr=stderr,
        no_color=True if no_color else None,
        color_system=None if no_color else "auto",
        markup=False,
        highlight=False,
    )


def maybe_print_wordmark(console: Console) -> None:
    if not console.is_terminal:
        return
    console.print("SkillTrace", style="bold cyan", end="")
    console.print(" — behavioral scanner for Claude Skills", style="dim")
    console.print()


def print_welcome(console: Console) -> None:
    console.print("Get started", style="bold")
    console.print()
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="cyan")
    grid.add_column()
    for cmd, blurb in _QUICKSTART:
        grid.add_row(cmd, blurb)
    console.print(grid)
    console.print()
    console.print("Run 'skilltrace scan --help' for the full list of options.")


def print_error(console: Console, message: str) -> None:
    console.print(f"error: {message}", style="bold red")


def print_warning(console: Console, message: str) -> None:
    console.print(f"warning: {message}", style="yellow")


def _findings_table(findings: list) -> Table:
    table = Table(show_lines=False)
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Summary", ratio=1, overflow="fold")
    table.add_column("Confidence")
    table.add_column("ATT&CK")
    for f in findings:
        table.add_row(
            f.severity.value.upper(),
            f.category,
            f.summary,
            f.confidence.value,
            f.mitre_technique or "-",
            style=SEVERITY_STYLE.get(f.severity),
        )
    return table


def print_report(console: Console, report: Report) -> None:
    console.print(report.skill_name or report.skill_path, style="bold")
    if report.skill_description:
        console.print(report.skill_description, style="dim")
    console.print(
        f"Risk score: {report.risk_score} ",
        style=SEVERITY_STYLE.get(report.risk_level),
        end="",
    )
    console.print(f"({report.risk_level.value.upper()})", style=SEVERITY_STYLE.get(report.risk_level))
    console.print()
    if report.findings:
        console.print(_findings_table(report.findings))
    else:
        console.print("No findings.", style="green")


def print_summary_table(console: Console, reports: list[Report]) -> None:
    table = Table(show_lines=False)
    table.add_column("Skill")
    table.add_column("Risk")
    table.add_column("Score")
    for r in reports:
        table.add_row(
            r.skill_name or r.skill_path,
            r.risk_level.value.upper(),
            str(r.risk_score),
            style=SEVERITY_STYLE.get(r.risk_level),
        )
    console.print(table)
