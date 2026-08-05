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

import importlib.metadata
from contextlib import contextmanager
from dataclasses import dataclass

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

from sentinel.findings import Severity
from sentinel.report import Report

SEVERITY_STYLE = {
    Severity.LOW: "green",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "dark_orange",
    Severity.CRITICAL: "bold red",
}

# figlet "ansi_shadow" font, generated once (`pyfiglet.Figlet(font="ansi_shadow").renderText("SKILLTRACE")`)
# and pasted as a literal constant — a fixed word never needs a runtime ASCII-art
# generator dependency.
_WORDMARK_ART = "\n".join(
    line.rstrip()
    for line in r"""
███████╗██╗  ██╗██╗██╗     ██╗  ████████╗██████╗  █████╗  ██████╗███████╗
██╔════╝██║ ██╔╝██║██║     ██║  ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
███████╗█████╔╝ ██║██║     ██║     ██║   ██████╔╝███████║██║     █████╗
╚════██║██╔═██╗ ██║██║     ██║     ██║   ██╔══██╗██╔══██║██║     ██╔══╝
███████║██║  ██╗██║███████╗███████╗██║   ██║  ██║██║  ██║╚██████╗███████╗
╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
""".strip("\n").splitlines()
)
_WORDMARK_WIDTH = max(len(line) for line in _WORDMARK_ART.splitlines())


def _package_version() -> str:
    try:
        return importlib.metadata.version("skilltrace")
    except importlib.metadata.PackageNotFoundError:
        return "dev"


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


def maybe_print_banner(console: Console) -> None:
    if not console.is_terminal:
        return
    try:
        console.print(_WORDMARK_ART, style="bold cyan")
        version_line = f"v{_package_version()} — behavioral scanner for agent skills (Claude, Cursor, Codex)"
        capability_line = "Static heuristics · Dynamic sandbox tracing · Semantic review (opt-in)"
        console.print(version_line.center(_WORDMARK_WIDTH), style="white")
        console.print(capability_line.center(_WORDMARK_WIDTH), style="cyan")
        console.print()
    except UnicodeEncodeError:
        # Rich's legacy-Windows console writer (old cmd.exe / non-VT-capable
        # consoles) talks to the Win32 console API directly rather than through
        # sys.stdout, bypassing the UTF-8 stream reconfigure in cli.main() — it
        # can fail outright on some non-VT consoles regardless of content.
        # Plain builtin print() sidesteps that code path entirely. A purely
        # decorative banner must never crash the CLI over it.
        print(f"SKILLTRACE v{_package_version()}")


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


@dataclass
class SkillProgress:
    name: str
    status: str = "Queued"  # "Queued" | "Scanning" | "Skipped" | "Done"
    risk_level: Severity | None = None
    risk_score: int | None = None


_STATUS_TEXT = {
    "Queued": ("◦ Queued", "dim"),
    "Scanning": ("⟳ Scanning", "yellow"),
    "Skipped": ("- Skipped", "dim"),
    "Done": ("✓ Done", "green"),
}


def _build_progress_table(rows: list[SkillProgress]) -> Table:
    table = Table(show_header=True, header_style="bold cyan", border_style="dim", pad_edge=True, expand=False)
    table.add_column("Skill")
    table.add_column("Status")
    table.add_column("Risk")
    for row in rows:
        label, style = _STATUS_TEXT[row.status]
        if row.risk_level is not None:
            risk_text = Text(f"{row.risk_level.value.upper()} ({row.risk_score})", style=SEVERITY_STYLE[row.risk_level])
        else:
            risk_text = Text("·", style="dim")
        table.add_row(row.name, Text(label, style=style), risk_text)
    return table


class CollectionProgress:
    """Live-updating stderr table for a multi-skill collection scan. Only
    meaningful on a real terminal — callers should check `console.is_terminal`
    themselves and fall back to plain print lines otherwise (Live is silent
    off-TTY anyway when transient, so this doesn't guard against that itself)."""

    def __init__(self, console: Console, skill_names: list[str]):
        self._rows = [SkillProgress(name) for name in skill_names]
        self._live = Live(_build_progress_table(self._rows), console=console, transient=True, refresh_per_second=4)

    def __enter__(self) -> "CollectionProgress":
        self._live.__enter__()
        return self

    def __exit__(self, *exc_info) -> None:
        self._live.__exit__(*exc_info)

    def start(self, idx: int, name: str) -> None:
        self._rows[idx].name = name
        self._rows[idx].status = "Scanning"
        self._live.update(_build_progress_table(self._rows))

    def skip(self, idx: int) -> None:
        self._rows[idx].status = "Skipped"
        self._live.update(_build_progress_table(self._rows))

    def finish(self, idx: int, risk_level: Severity, risk_score: int) -> None:
        self._rows[idx].status = "Done"
        self._rows[idx].risk_level = risk_level
        self._rows[idx].risk_score = risk_score
        self._live.update(_build_progress_table(self._rows))


@contextmanager
def busy_status(console: Console, message: str, *, quiet: bool):
    """Spinner (TTY) or a single plain line (non-TTY) around a step that can
    take a while with otherwise zero feedback (git clone, sandbox run).
    Suppressed entirely under --quiet, same as other progress chatter."""
    if quiet:
        yield
    elif console.is_terminal:
        with console.status(message):
            yield
    else:
        console.print(message)
        yield


def _findings_table(findings: list) -> Table:
    table = Table(show_lines=False)
    table.add_column("Severity")
    table.add_column("Category", overflow="fold")
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


def _scan_summary_grid(report: Report) -> Table:
    # Context that's always worth showing, findings or not — otherwise a
    # clean result ("Risk score: 0, No findings.") looks identical to the
    # tool having done nothing at all, rather than having checked thoroughly.
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim")
    grid.add_column()
    grid.add_row("Sandbox:", "ran" if report.sandbox_ran else "not run (--static)")
    grid.add_row(
        "Semantic review:", "ran" if report.semantic_review_ran else "not run (--semantic-review to enable)"
    )
    grid.add_row("Invocations:", ", ".join(report.invocations) if report.invocations else "none attempted")
    if report.allowed_tools:
        grid.add_row("Allowed tools:", ", ".join(report.allowed_tools))
    return grid


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
    console.print(_scan_summary_grid(report))
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
