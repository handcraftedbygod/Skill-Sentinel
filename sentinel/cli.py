"""skill-sentinel CLI: scan <path|git-url> [--invoke CMD] [--allow-network] [--json]"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from pathlib import Path

from sentinel.findings import Severity
from sentinel.heuristics import run_heuristics
from sentinel.report import build_report, render_html_multi, render_json_multi, render_markdown_multi
from sentinel.sandbox import (
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


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skill-sentinel",
        description="A behavioral scanner for Claude Skills — sandboxes a skill and "
        "reports what it actually does, instead of trusting its description.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

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
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _run_scan(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
