"""skill-sentinel CLI: scan <path|git-url> [--invoke CMD] [--allow-network] [--json]"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import re
import sys
import tempfile
from pathlib import Path

from sentinel.findings import Severity
from sentinel.heuristics import run_heuristics
from sentinel.report import build_report, diff_sandbox_results, render_html_multi, render_json_multi, render_markdown_multi
from sentinel.sandbox import (
    DIFFERENTIAL_ENV,
    DIFFERENTIAL_HOSTNAME,
    DockerUnavailableError,
    SentinelError,
    build_invocation_candidates,
    ensure_docker_available,
    resolve_skill_source,
    run_skill_in_sandbox,
)
from sentinel.semantic_review import SemanticReviewError, review_skill_instructions
from sentinel.skillmd import (
    SkillMdNotFoundError,
    SkillMdParseError,
    discover_bundled_files,
    discover_skill_directories,
    parse_skill_md,
)

FAIL_THRESHOLD_CHOICES = ["low", "medium", "high", "critical"]

DEFAULT_HTML_REPORT = "skill-sentinel-report.html"

# Terminal-only polish: color the severity tags render_markdown() already
# produces rather than build a separate colored-text renderer. Applied only
# when writing to a real terminal (never to -o FILE or --json, which must
# stay exactly what they claim to be — plain text / valid JSON).
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_BY_SEVERITY = {
    "LOW": "\033[32m",  # green
    "MEDIUM": "\033[33m",  # yellow
    "HIGH": "\033[38;5;208m",  # orange
    "CRITICAL": "\033[1;31m",  # bold red
}
_SEVERITY_TAG_RE = re.compile(r"\*\*\[(LOW|MEDIUM|HIGH|CRITICAL)\]\*\*|\((LOW|MEDIUM|HIGH|CRITICAL)\)")


def _colorize_severity_tags(markdown: str) -> str:
    def _replace(match: re.Match) -> str:
        severity = match.group(1) or match.group(2)
        color = ANSI_BY_SEVERITY[severity]
        return f"{color}{match.group(0)}{ANSI_RESET}"

    return _SEVERITY_TAG_RE.sub(_replace, markdown)


def _write_line(text: str, stream) -> None:
    # Same fix as the report writer below: the hero/welcome screen always
    # contains block-art and box-drawing characters, and sys.stdout/stderr's
    # encoding defaults to the console's legacy codepage (e.g. cp1252 on
    # Windows) when not attached to a real interactive terminal — plain
    # print() would crash outright rather than just render imperfectly.
    stream.buffer.write(text.encode("utf-8", errors="replace"))
    stream.buffer.write(b"\n")


ANSI_PRIMARY = "\033[38;5;33m"  # defensive blue — the wordmark's and shield's fill
ANSI_WHITE = "\033[97m"  # tagline/footer text, and the wordmark's 3D outline
ANSI_MASCOT_NAVY = "\033[38;5;60m"  # mascot helmet/face fill, nearest-256 match to the source art
ANSI_MASCOT_GOGGLE = "\033[38;5;74m"  # mascot goggle-band accent, same source

# Built from rectangles instead of hand-typed strings — a 47-cell row typed
# by hand is exactly how the N glyph got silently mis-sized earlier. Bars
# are 2 cells thick, not 1: any full-width bar gets a full-width outline
# row immediately above AND below it regardless of thickness (every column
# there sits directly next to the bar), so a 1-thick bar is 100% outline
# on its own two neighbor rows. Thickening the bar itself is what keeps
# blue, not white, the dominant color near it. Buffer rows keep that
# unavoidable bleed from also washing into the strokes further away.
_GLYPH_HEIGHT = 14


def _rect_glyph(width: int, rects: list[tuple[int, int, int, int]]) -> list[str]:
    """rects: (row_start, row_end_inclusive, col_start, col_end_inclusive)."""
    grid = [[False] * width for _ in range(_GLYPH_HEIGHT)]
    for r0, r1, c0, c1 in rects:
        for r in range(r0, r1 + 1):
            for c in range(c0, c1 + 1):
                grid[r][c] = True
    return ["".join("█" if cell else " " for cell in row) for row in grid]


def _n_glyph() -> list[str]:
    # Side verticals plus a staircase diagonal, computed rather than typed
    # so it's guaranteed symmetric and every row is the same width.
    width = 9
    grid = [[False] * width for _ in range(_GLYPH_HEIGHT)]
    for r in range(_GLYPH_HEIGHT):
        grid[r][0] = True
        grid[r][width - 1] = True
        diag_col = 1 + round(r * (width - 3) / (_GLYPH_HEIGHT - 1))
        grid[r][diag_col] = True
    return ["".join("█" if cell else " " for cell in row) for row in grid]


_LETTER_GLYPHS = {
    "S": _rect_glyph(7, [(0, 1, 0, 6), (3, 4, 0, 0), (6, 7, 0, 6), (9, 10, 6, 6), (12, 13, 0, 6)]),
    "E": _rect_glyph(7, [(0, 1, 0, 6), (3, 4, 0, 0), (6, 7, 0, 6), (9, 10, 0, 0), (12, 13, 0, 6)]),
    "N": _n_glyph(),
    "T": _rect_glyph(7, [(0, 1, 0, 6), (3, 13, 3, 3)]),
    "I": _rect_glyph(7, [(0, 1, 0, 6), (3, 10, 3, 3), (12, 13, 0, 6)]),
    "L": _rect_glyph(7, [(0, 10, 0, 0), (12, 13, 0, 6)]),
}

# Sampled directly from the reference mockup (a helmeted mascot with a
# lighter goggle band and white body), not hand-designed: box-downsampled
# to a 20x20 grid, each cell nearest-color-classified against the mockup's
# own sampled navy/goggle-blue/white/background tones, then mirrored
# left-right (the source has natural pixel noise from how it was generated;
# forcing symmetry cleans that up the same way the letter glyphs above are
# guaranteed symmetric by construction rather than hand-typed). 'F' = navy
# helmet/face, 'G' = goggle-band accent, 'W' = white body, ' ' = background.
_MASCOT_ROWS = [
    "        FFFF        ",
    "       FFFFFF       ",
    "    FFFFFFFFFFFF    ",
    "    FFFFFFFFFFFF    ",
    "   FFFFFFFFFFFFFF   ",
    "   FFFFFFFFFFFFFF   ",
    "  FFFFFFFFFFFFFFFF  ",
    "  FFFFFFFFFFFFFFFF  ",
    " FFFFFFFFFFFFFFFFFF ",
    "  FFGWWGFGGFGWWGFF  ",
    "  FGGWF  GG  FWGGF  ",
    "  FGGWF  GG  FWGGF  ",
    " FFWGGGGGFFGGGGGWFF ",
    "FWWWFFFFFFFFFFFFWWWF",
    "WWWWFFFFGFFGFFFFWWWW",
    "WWWWFFFFWFFWFFFFWWWW",
    "WWWWFFFFGFFGFFFFWWWW",
    "FWWWGFFFFFFFFFFGWWWF",
    "  FWWWWWWWWWWWWWWF  ",
    "    FWWWWWWWWWWF    ",
]

_HERO_GAP = 3  # columns between the wordmark and the mascot


_LETTER_GAP = "   "  # 3 cells: a 1-cell gap gets fully swallowed by the outline pass


def _block_wordmark(word: str) -> list[str]:
    glyphs = [_LETTER_GLYPHS[letter] for letter in word]
    return [_LETTER_GAP.join(glyph[row] for glyph in glyphs) for row in range(_GLYPH_HEIGHT)]


def _add_outline(rows: list[str]) -> tuple[list[str], list[str]]:
    """Sticker-style outline: every empty cell touching a filled cell in any
    of the 8 surrounding directions becomes a 1-cell white outline hugging
    the whole silhouette — this is the actual effect GitHub Copilot's CLI
    banner uses on its wordmark, not a corner-only drop shadow.

    fill_rows preserves each cell's own original character rather than
    collapsing every filled cell to one glyph, the wordmark only ever uses
    a single fill character, but the mascot's multiple fill colors (navy/
    goggle-blue/white) need to survive this pass so _compose_hero_rows can
    still tell them apart afterward."""
    height = len(rows)
    width = max(len(row) for row in rows)
    padded = [row.ljust(width) for row in rows]

    pad_h, pad_w = height + 2, width + 2
    fill = [[" "] * pad_w for _ in range(pad_h)]
    filled = [[False] * pad_w for _ in range(pad_h)]
    for r in range(height):
        for c in range(width):
            if padded[r][c] != " ":
                fill[r + 1][c + 1] = padded[r][c]
                filled[r + 1][c + 1] = True

    outline = [[False] * pad_w for _ in range(pad_h)]
    for r in range(pad_h):
        for c in range(pad_w):
            if filled[r][c]:
                continue
            neighbors = (
                filled[nr][nc]
                for nr in (r - 1, r, r + 1)
                for nc in (c - 1, c, c + 1)
                if (nr, nc) != (r, c) and 0 <= nr < pad_h and 0 <= nc < pad_w
            )
            outline[r][c] = any(neighbors)

    fill_rows = ["".join(row) for row in fill]
    outline_rows = ["".join("█" if cell else " " for cell in row) for row in outline]
    return fill_rows, outline_rows


def _compose_hero_rows() -> list[str]:
    """Tagged (not yet colored) rows, shared between the wordmark and the
    mascot: '█' wordmark fill, 'F'/'G'/'W' mascot navy/goggle/white fill,
    'S' outline, ' ' empty. Plain-text composition first, so alignment
    never has to account for ANSI escape width."""

    def _tag(fill_rows: list[str], outline_rows: list[str]) -> list[str]:
        return [
            "".join(f if f != " " else ("S" if s != " " else " ") for f, s in zip(fr, oro))
            for fr, oro in zip(fill_rows, outline_rows)
        ]

    word_tagged = _tag(*_add_outline(_block_wordmark("SENTINEL")))
    icon_tagged = _tag(*_add_outline(_MASCOT_ROWS))

    height = max(len(word_tagged), len(icon_tagged))
    word_width = len(word_tagged[0])
    icon_width = len(icon_tagged[0])
    word_tagged += [" " * word_width] * (height - len(word_tagged))
    icon_tagged += [" " * icon_width] * (height - len(icon_tagged))

    return [w + " " * _HERO_GAP + i for w, i in zip(word_tagged, icon_tagged)]


def _render_tagged_row(tagged_row: str, color: bool) -> str:
    code_by_tag = {
        "█": ANSI_PRIMARY,  # wordmark fill
        "F": ANSI_MASCOT_NAVY,
        "G": ANSI_MASCOT_GOGGLE,
        "W": ANSI_WHITE,
        "S": ANSI_WHITE,  # outline
    }
    out = []
    for tag in tagged_row:
        if tag == " ":
            out.append(" ")
        elif color:
            out.append(f"{code_by_tag[tag]}█{ANSI_RESET}")
        else:
            out.append("█")
    return "".join(out)


def _package_version() -> str:
    try:
        return importlib.metadata.version("skill-sentinel")
    except importlib.metadata.PackageNotFoundError:
        return "dev"


def _installed_commit() -> str | None:
    # Only present for a `pip install git+https://...` install (see
    # README's own install command); a local editable/dev install has no
    # vcs_info, so this quietly returns None rather than fabricating one.
    # Decorative footer detail — must never crash the CLI over it.
    try:
        raw = importlib.metadata.distribution("skill-sentinel").read_text("direct_url.json")
        commit = json.loads(raw).get("vcs_info", {}).get("commit_id") if raw else None
        return commit[:8] if commit else None
    except Exception:
        return None


def _build_banner(color: bool) -> str:
    def _styled(text: str, code: str) -> str:
        return f"{code}{text}{ANSI_RESET}" if color else text

    hero_rows_tagged = _compose_hero_rows()
    width = len(hero_rows_tagged[0])
    tagline = "Behavioral scanner for Claude Skills"
    caption = f"CLI v{_package_version()}"

    lines = [
        "⌜" + " " * (width + 2) + "⌝",
        "",
        "  " + _styled(tagline, ANSI_WHITE),
        "",
    ]
    lines += ["  " + _render_tagged_row(row, color) for row in hero_rows_tagged]
    lines += [
        "  " + " " * (width - len(caption)) + _styled(caption, ANSI_WHITE),
        "",
        "⌞" + " " * (width + 2) + "⌟",
    ]
    return "\n".join(lines)


def _build_footer(color: bool) -> str:
    version_line = f"skill-sentinel v{_package_version()}"
    commit = _installed_commit()
    if commit:
        version_line += f" · {commit}"
    return "  " + (f"{ANSI_WHITE}{version_line}{ANSI_RESET}" if color else version_line)


def _maybe_print_banner() -> None:
    if sys.stderr.isatty():
        _write_line(_build_banner(color=True), sys.stderr)
        _write_line("", sys.stderr)
        _write_line(_build_footer(color=True), sys.stderr)
        _write_line("", sys.stderr)


_QUICKSTART = [
    ("skill-sentinel scan ./my-skill", "scan a local skill directory"),
    ("skill-sentinel scan <git-url>", "scan a skill, or a whole collection repo, from git"),
    ("skill-sentinel scan ./my-skill --html", "also write a self-contained HTML report"),
]


def _build_welcome(color: bool) -> str:
    def _styled(text: str, code: str) -> str:
        return f"{code}{text}{ANSI_RESET}" if color else text

    cmd_width = max(len(cmd) for cmd, _ in _QUICKSTART)
    bullet_lines = [f"● {cmd.ljust(cmd_width)}   {blurb}" for cmd, blurb in _QUICKSTART]
    help_line = "Run 'skill-sentinel scan --help' for the full list of options."
    # Same ⌜⌝/⌞⌟ frame the banner above uses, same design language, not a
    # coincidence, so the two blocks read as one connected piece of output
    # rather than an unrelated banner glued to plain unstyled help text.
    content_width = max(len(line) for line in bullet_lines + [help_line, "Get started"])

    dot = _styled("●", ANSI_PRIMARY)
    heading = _styled("Get started", ANSI_BOLD + ANSI_WHITE)
    divider = _styled("─" * len("Get started"), ANSI_PRIMARY)

    lines = [
        "⌜" + " " * (content_width + 4) + "⌝",
        "",
        "  " + heading,
        "  " + divider,
        "",
    ]
    for cmd, blurb in _QUICKSTART:
        colored_cmd = _styled(cmd.ljust(cmd_width), ANSI_PRIMARY)
        lines.append(f"  {dot} {colored_cmd}   {blurb}")
    lines += [
        "",
        "  " + help_line,
        "",
        "⌞" + " " * (content_width + 4) + "⌟",
    ]
    return "\n".join(lines)


def _print_welcome() -> None:
    _write_line(_build_welcome(color=sys.stdout.isatty()), sys.stdout)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skill-sentinel",
        description="A behavioral scanner for Claude Skills — sandboxes a skill and "
        "reports what it actually does, instead of trusting its description.",
    )
    # Not required: a bare `skill-sentinel` invocation shows the welcome screen
    # (see _print_welcome) instead of an argparse usage error.
    subparsers = parser.add_subparsers(dest="command", required=False)

    scan = subparsers.add_parser("scan", help="Scan a skill directory or git URL")
    scan.add_argument("path_or_url", help="Local path to a skill directory, or a git URL")
    scan.add_argument("--invoke", metavar="CMD", help="An explicit command to run inside the sandbox")
    scan.add_argument(
        "--allow-network",
        action="store_true",
        help="Skip the DNS/TLS sinkhole and allow real network egress (no decrypted "
        "traffic visibility for this run — opts into real egress at your own risk)",
    )
    scan.add_argument("--json", action="store_true", help="Output the report as JSON instead of Markdown")
    scan.add_argument("--timeout", type=int, default=60, help="Per-invocation sandbox timeout in seconds")
    scan.add_argument("-o", "--output", metavar="FILE", help="Write the report to FILE instead of stdout")
    scan.add_argument(
        "--fail-threshold",
        choices=FAIL_THRESHOLD_CHOICES,
        default=None,
        help="Exit non-zero if the report's risk level is at or above this severity "
        "(for CI gating; see .github/workflows/skill-ci.yml.example)",
    )
    scan.add_argument(
        "--no-sandbox",
        action="store_true",
        help="Skip the Docker sandbox entirely and only run the static heuristics pass",
    )
    scan.add_argument(
        "--semantic-review",
        action="store_true",
        help="Send each skill's own instructions to Claude for adversarial review "
        "(prompt-injection-style manipulation of the agent, not visible to file-content "
        "or behavioral checks). Costs one Anthropic API call per skill; requires "
        "ANTHROPIC_API_KEY. Opt-in — off by default.",
    )
    scan.add_argument(
        "--differential",
        action="store_true",
        help="Re-run each candidate a second time with a different container hostname "
        "and interactive-session-looking env vars, and flag behavior that only shows up "
        "in one of the two runs (a real sandbox-evasion signal). Opt-in, roughly doubles "
        "sandbox runtime, off by default.",
    )
    scan.add_argument(
        "--html",
        metavar="FILE",
        nargs="?",
        const=DEFAULT_HTML_REPORT,
        help=f"Also write a self-contained HTML report to FILE (default: {DEFAULT_HTML_REPORT}) "
        "for a full visual review, in addition to the normal terminal/--json/-o output. "
        "No external assets — works offline and as a CI artifact.",
    )

    return parser


def _run_scan(args: argparse.Namespace) -> int:
    # Checked once, up front — not per skill_dir in the loop below. A missing key
    # is a one-time configuration problem; printing the same "set ANTHROPIC_API_KEY"
    # warning once per skill in a multi-hundred-skill collection scan would be noise
    # a user could easily miss, then wrongly assume --semantic-review actually ran.
    if args.semantic_review and not os.environ.get("ANTHROPIC_API_KEY"):
        print(
            "error: --semantic-review requires ANTHROPIC_API_KEY to be set "
            "(get a key at https://console.anthropic.com/)",
            file=sys.stderr,
        )
        return 5

    with tempfile.TemporaryDirectory(prefix="skill-sentinel-") as tmpdir:
        try:
            source_dir = resolve_skill_source(args.path_or_url, Path(tmpdir))
        except SentinelError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        # Most sources are a single skill (SKILL.md at source_dir's own root).
        # Some are collections — one repo bundling many skills, each in its own
        # subdirectory, with no root SKILL.md at all — see
        # skillmd.discover_skill_directories.
        skill_dirs = discover_skill_directories(source_dir)
        if not skill_dirs:
            print(f"error: {SkillMdNotFoundError(source_dir)}", file=sys.stderr)
            return 2

        docker_checked = False
        reports = []
        total = len(skill_dirs)
        for idx, skill_dir in enumerate(skill_dirs, start=1):
            try:
                metadata = parse_skill_md(skill_dir)
            except (SkillMdNotFoundError, SkillMdParseError) as exc:
                print(f"warning: skipping {skill_dir}: {exc}", file=sys.stderr)
                continue

            # Only for collection scans (total > 1) — a single-skill scan doesn't
            # need progress noise, but scanning a repo with dozens or hundreds of
            # skills with zero visibility into where it is was a real pain point
            # while building this tool.
            if total > 1:
                print(f"[{idx}/{total}] scanning {metadata.name or skill_dir.name}...", file=sys.stderr)

            heuristic_findings = run_heuristics(skill_dir)
            bundled_files = discover_bundled_files(skill_dir)
            candidates = build_invocation_candidates(skill_dir, bundled_files, metadata.body, args.invoke)

            semantic_review_ran = False
            if args.semantic_review:
                try:
                    heuristic_findings = heuristic_findings + review_skill_instructions(
                        metadata.name, metadata.description, metadata.body, source=str(skill_dir)
                    )
                    semantic_review_ran = True
                except SemanticReviewError as exc:
                    print(f"warning: semantic review skipped for {skill_dir}: {exc}", file=sys.stderr)

            sandbox_results = None
            if not args.no_sandbox:
                if not docker_checked:
                    try:
                        ensure_docker_available()
                    except DockerUnavailableError as exc:
                        print(f"error: {exc}", file=sys.stderr)
                        return 3
                    docker_checked = True

                if candidates:
                    try:
                        sandbox_results = run_skill_in_sandbox(
                            skill_dir,
                            candidates,
                            allow_network=args.allow_network,
                            timeout_s=args.timeout,
                        )
                        if args.differential:
                            varied_results = run_skill_in_sandbox(
                                skill_dir,
                                candidates,
                                allow_network=args.allow_network,
                                timeout_s=args.timeout,
                                hostname=DIFFERENTIAL_HOSTNAME,
                                env_overrides=DIFFERENTIAL_ENV,
                            )
                            for baseline_result, varied_result in zip(sandbox_results, varied_results):
                                heuristic_findings = heuristic_findings + diff_sandbox_results(
                                    baseline_result, varied_result
                                )
                    except SentinelError as exc:
                        print(f"error: {exc}", file=sys.stderr)
                        return 4

            report = build_report(
                skill_dir, metadata, heuristic_findings, sandbox_results, candidates, semantic_review_ran
            )
            reports.append(report)
            if total > 1:
                print(f"    -> {report.risk_level.value.upper()} ({report.risk_score})", file=sys.stderr)

        if not reports:
            print(f"error: No valid SKILL.md could be parsed under {source_dir}", file=sys.stderr)
            return 2

    if args.html:
        Path(args.html).write_text(render_html_multi(reports), encoding="utf-8")
        print(f"HTML report written to {args.html}", file=sys.stderr)

    output = render_json_multi(reports) if args.json else render_markdown_multi(reports)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        # Not print(): a scanned skill's own description/findings can contain
        # arbitrary Unicode (em dashes, non-English text, ...), and the console's
        # default encoding (e.g. cp1252 on Windows) can't represent all of it —
        # print() would crash the whole scan over the skill's own text content.
        # Color only applies here: a real terminal, plain Markdown — never to
        # -o FILE (must stay plain text) or --json (must stay valid JSON).
        if not args.json and sys.stdout.isatty():
            output = _colorize_severity_tags(output)
        sys.stdout.buffer.write(output.encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(b"\n")

    if args.fail_threshold:
        threshold = Severity(args.fail_threshold)
        if any(r.risk_level.rank >= threshold.rank for r in reports):
            return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    _maybe_print_banner()
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _run_scan(args)

    _print_welcome()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
