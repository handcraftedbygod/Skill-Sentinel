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

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TaskProgressColumn, TextColumn
from rich.table import Table
from rich.text import Text

from sentinel.findings import Severity
from sentinel.report import RISK_LEVEL_GUIDANCE, Report, collection_risk

SEVERITY_STYLE = {
    Severity.LOW: "green",
    # gold3, not the default ANSI "yellow" — reads as amber against a dark
    # terminal background instead of a harsh caution-siren yellow.
    Severity.MEDIUM: "gold3",
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


@contextmanager
def file_scan_progress(console: Console, total: int, *, quiet: bool):
    """Real percentage bar over a skill's bundled files during the static
    pass — total is known upfront (discover_bundled_files has already run),
    so this is an honest count, not a fake/simulated fill. Yields a callback
    to advance it; a no-op callback when there's nothing to show (--quiet,
    non-terminal, zero files, or nested inside a collection scan's own Live
    table — Rich doesn't support two Live displays at once, same constraint
    busy_status already works around for the sandbox spinner).

    markup=False on every TextColumn here, not just the Console: a scanned
    file's own relative path — attacker-controlled content — is interpolated
    directly into the filename column, and Rich's TextColumn has its own
    independent markup flag (default True) that Console's markup=False does
    not implicitly override."""
    if quiet or not console.is_terminal or total == 0:
        yield lambda _filename: None
        return
    progress = Progress(
        TextColumn("Scanning files", markup=False),
        BarColumn(),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TextColumn("{task.fields[filename]}", markup=False, style="dim"),
        console=console,
        transient=True,
    )
    with progress:
        task_id = progress.add_task("scan", total=total, filename="")

        def advance(filename: str) -> None:
            progress.update(task_id, filename=filename)
            progress.advance(task_id)

        yield advance


def _findings_table(findings: list) -> Table:
    # show_lines + vertical="middle": the Summary column often wraps to several
    # lines while Severity/Category/Confidence/ATT&CK don't, which without a
    # row separator and middle alignment reads as one cramped, undifferentiated
    # block of text rather than distinct rows.
    table = Table(show_lines=True)
    table.add_column("Severity", vertical="middle")
    table.add_column("Category", overflow="fold", vertical="middle")
    table.add_column("Summary", ratio=1, overflow="fold", vertical="middle")
    table.add_column("Confidence", vertical="middle")
    table.add_column("ATT&CK", vertical="middle")
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
    console.print(RISK_LEVEL_GUIDANCE[report.risk_level], style="dim")
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

    worst = collection_risk(reports)
    console.print()
    console.print(f"Overall risk score: {worst.risk_score} ", style=SEVERITY_STYLE.get(worst.risk_level), end="")
    console.print(
        f"({worst.risk_level.value.upper()}, driven by {worst.skill_name or worst.skill_path})",
        style=SEVERITY_STYLE.get(worst.risk_level),
    )
    console.print(RISK_LEVEL_GUIDANCE[worst.risk_level], style="dim")


def print_reports_generated(console: Console, *, html: str, json: str, markdown: str) -> None:
    # Not gated on --quiet, same reasoning as the existing --html "written to"
    # line: this is the only record of where the auto-written files landed.
    console.print()
    console.print("Reports generated:", style="bold")
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="cyan")
    grid.add_column()
    grid.add_row("HTML", html)
    grid.add_row("JSON", json)
    grid.add_row("Markdown", markdown)
    console.print(grid)


def print_scan_complete(
    console: Console,
    *,
    skills_scanned: int,
    files_scanned: int,
    findings_by_severity: dict[Severity, int],
    elapsed_s: float,
) -> None:
    console.print()
    console.print("Scan complete", style="bold green")
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim")
    grid.add_column()
    grid.add_row("Skills scanned:", str(skills_scanned))
    grid.add_row("Files scanned:", str(files_scanned))
    total_findings = sum(findings_by_severity.values())
    grid.add_row("Findings:", str(total_findings))
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        count = findings_by_severity.get(severity, 0)
        if count:
            grid.add_row(f"  {severity.value.upper()}:", Text(str(count), style=SEVERITY_STYLE[severity]))
    grid.add_row("Time:", f"{elapsed_s:.2f}s")
    console.print(grid)
