"""skilltrace CLI: scan <path|git-url> [--invoke CMD] [--allow-network] [--json]"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

from rich.console import Console
from rich_argparse import RichHelpFormatter

from sentinel.console import (
    make_console,
    maybe_print_wordmark,
    print_error,
    print_report,
    print_summary_table,
    print_warning,
    print_welcome,
)
from sentinel.findings import Finding, Severity
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
    SkillMetadata,
    discover_bundled_files,
    discover_skill_directories,
    parse_skill_md,
)

FAIL_THRESHOLD_CHOICES = ["low", "medium", "high", "critical"]

DEFAULT_HTML_REPORT = "skilltrace-report.html"

EXIT_CODES_EPILOG = (
    "Exit codes: 0 success (no findings at/above --fail-threshold, or no threshold set) · "
    "1 findings at/above --fail-threshold · 2 could not resolve the skill source (bad "
    "path/URL) or every SKILL.md found failed to parse · 3 Docker unavailable · "
    "4 sandbox error · 5 --semantic-review requested without ANTHROPIC_API_KEY set. "
    "A repo with no SKILL.md anywhere is no longer a hard failure: it's scanned as a "
    "single unlabeled directory instead (see the no_skill_md finding)."
)


def _common_flags_parser() -> argparse.ArgumentParser:
    # add_help=False: argparse's parents= mechanism errors on a duplicate -h/--help
    # if the parent parser defines its own. This parser exists only to be shared
    # (via parents=[...]) by both the top-level parser and the scan subparser, so
    # flags like --quiet work in either position: `skilltrace --quiet scan ...`
    # or `skilltrace scan --quiet ...`.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress the startup banner and per-skill progress messages on stderr. "
        "Errors, warnings, and the report itself are unaffected.",
    )
    common.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color in terminal output. Also respected automatically via "
        "the NO_COLOR env var, or whenever stdout/stderr isn't a real terminal.",
    )
    return common


def _build_arg_parser() -> argparse.ArgumentParser:
    common = _common_flags_parser()
    parser = argparse.ArgumentParser(
        prog="skilltrace",
        description="A behavioral scanner for Claude Skills — sandboxes a skill and "
        "reports what it actually does, instead of trusting its description.",
        parents=[common],
        formatter_class=RichHelpFormatter,
    )
    # Not required: a bare `skilltrace` invocation shows the welcome screen
    # (see sentinel.console.print_welcome) instead of an argparse usage error.
    subparsers = parser.add_subparsers(dest="command", required=False)

    scan = subparsers.add_parser(
        "scan",
        help="Scan a skill directory or git URL",
        parents=[common],
        formatter_class=RichHelpFormatter,
        epilog=EXIT_CODES_EPILOG,
    )
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
        "--static",
        "--no-sandbox",
        dest="no_sandbox",
        action="store_true",
        help="Static-only scan: skip the Docker sandbox entirely and only run the "
        "static heuristics pass. No Docker required. (--no-sandbox still works, "
        "kept as an alias.)",
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
    stderr_console = make_console(stderr=True, no_color=args.no_color)

    # Checked once, up front — not per skill_dir in the loop below. A missing key
    # is a one-time configuration problem; printing the same "set ANTHROPIC_API_KEY"
    # warning once per skill in a multi-hundred-skill collection scan would be noise
    # a user could easily miss, then wrongly assume --semantic-review actually ran.
    if args.semantic_review and not os.environ.get("ANTHROPIC_API_KEY"):
        print_error(
            stderr_console,
            "--semantic-review requires ANTHROPIC_API_KEY to be set "
            "(get a key at https://console.anthropic.com/)",
        )
        return 5

    with tempfile.TemporaryDirectory(prefix="skilltrace-") as tmpdir:
        try:
            source_dir = resolve_skill_source(args.path_or_url, Path(tmpdir))
        except SentinelError as exc:
            print_error(stderr_console, str(exc))
            return 2

        # Most sources are a single skill (SKILL.md at source_dir's own root).
        # Some are collections — one repo bundling many skills, each in its own
        # subdirectory, with no root SKILL.md at all — see
        # skillmd.discover_skill_directories.
        skill_dirs = discover_skill_directories(source_dir)
        # Zero anywhere in the tree usually means this isn't a Claude Skill at
        # all (wrong path/URL, or an ordinary code repo) — worth a best-effort
        # static read of what's actually there rather than a hard stop, since
        # that's exactly the shape of "point SkillTrace at some repo to see if
        # it's safe to install" triage.
        raw_directory_scan = not skill_dirs
        if raw_directory_scan:
            skill_dirs = [source_dir]

        reports = []
        total = len(skill_dirs)
        for idx, skill_dir in enumerate(skill_dirs, start=1):
            if raw_directory_scan:
                metadata = SkillMetadata(
                    name=None,
                    description=None,
                    license=None,
                    allowed_tools=None,
                    when_to_use=None,
                    raw_frontmatter={},
                    body="",
                    path=skill_dir,
                )
            else:
                try:
                    metadata = parse_skill_md(skill_dir)
                except (SkillMdNotFoundError, SkillMdParseError) as exc:
                    print_warning(stderr_console, f"skipping {skill_dir}: {exc}")
                    continue

            # Only for collection scans (total > 1) — a single-skill scan doesn't
            # need progress noise, but scanning a repo with dozens or hundreds of
            # skills with zero visibility into where it is was a real pain point
            # while building this tool. --quiet suppresses this chatter but never
            # errors/warnings.
            if total > 1 and not args.quiet:
                stderr_console.print(f"[{idx}/{total}] scanning {metadata.name or skill_dir.name}...")

            heuristic_findings = run_heuristics(skill_dir, metadata)
            if raw_directory_scan:
                heuristic_findings = heuristic_findings + [
                    Finding(
                        category="no_skill_md",
                        severity=Severity.MEDIUM,
                        summary=f"No SKILL.md found anywhere under {skill_dir} — this doesn't look "
                        "like a Claude Skill. Static checks still ran against the raw directory "
                        "contents, but there's no declared usage example or metadata to sandbox-run "
                        "or evaluate against.",
                        source="cli",
                    )
                ]
            bundled_files = discover_bundled_files(skill_dir)
            candidates = build_invocation_candidates(skill_dir, bundled_files, metadata.body, args.invoke)

            semantic_review_ran = False
            if args.semantic_review:
                try:
                    heuristic_findings = heuristic_findings + review_skill_instructions(
                        metadata.name,
                        metadata.description,
                        metadata.body,
                        when_to_use=metadata.when_to_use,
                        source=str(skill_dir),
                    )
                    semantic_review_ran = True
                except SemanticReviewError as exc:
                    print_warning(stderr_console, f"semantic review skipped for {skill_dir}: {exc}")

            sandbox_results = None
            if not args.no_sandbox:
                # run_skill_in_sandbox() below also calls ensure_docker_available()
                # itself (it's a public function other callers may use directly) —
                # this call exists only to fail fast with a distinct exit code
                # before doing any candidate-building work, not to avoid the
                # (cheap, subprocess-level) check that follows.
                try:
                    ensure_docker_available()
                except DockerUnavailableError as exc:
                    print_error(stderr_console, str(exc))
                    return 3

                if not candidates:
                    # A pure-prose skill (no bundled scripts, no --invoke, no
                    # SKILL.md usage examples) has nothing for the sandbox to run —
                    # exactly the attack shape this project's own threat model
                    # names first. Without this, the report renders identically to
                    # a genuinely clean sandboxed run; static heuristics still ran
                    # against the SKILL.md body, but dynamic behavior was never observed.
                    heuristic_findings = heuristic_findings + [
                        Finding(
                            category="sandbox_not_attempted",
                            severity=Severity.MEDIUM,
                            summary="No invocable candidate found (no bundled script, --invoke flag, or "
                            "SKILL.md usage example) — the sandbox never ran, so dynamic behavior was not "
                            "observed; only the static pass applies to this result",
                            source="sandbox",
                        )
                    ]
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
                        print_error(stderr_console, str(exc))
                        return 4

            report = build_report(
                skill_dir,
                metadata,
                heuristic_findings,
                sandbox_results,
                candidates,
                semantic_review_ran,
                sandbox_ran=not args.no_sandbox,
            )
            reports.append(report)
            if total > 1 and not args.quiet:
                stderr_console.print(f"    -> {report.risk_level.value.upper()} ({report.risk_score})")

        if not reports:
            print_error(stderr_console, f"No valid SKILL.md could be parsed under {source_dir}")
            return 2

    if args.html:
        Path(args.html).write_text(render_html_multi(reports), encoding="utf-8")
        # Not gated on --quiet: the only indication of where --html's output
        # landed (the filename can be an implicit default), so it's useful
        # signal rather than progress noise.
        stderr_console.print(f"HTML report written to {args.html}")

    if args.output:
        output = render_json_multi(reports) if args.json else render_markdown_multi(reports)
        Path(args.output).write_text(output, encoding="utf-8")
    elif args.json:
        sys.stdout.buffer.write(render_json_multi(reports).encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(b"\n")
    else:
        stdout_console = make_console(stderr=False, no_color=args.no_color)
        if stdout_console.is_terminal:
            if len(reports) > 1:
                print_summary_table(stdout_console, reports)
            else:
                print_report(stdout_console, reports[0])
        else:
            # Not print(): a scanned skill's own description/findings can contain
            # arbitrary Unicode (em dashes, non-English text, ...), and the console's
            # default encoding (e.g. cp1252 on Windows) can't represent all of it —
            # print() would crash the whole scan over the skill's own text content.
            output = render_markdown_multi(reports)
            sys.stdout.buffer.write(output.encode("utf-8", errors="replace"))
            sys.stdout.buffer.write(b"\n")

    if args.fail_threshold:
        threshold = Severity(args.fail_threshold)
        if any(r.risk_level.rank >= threshold.rank for r in reports):
            return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    # Windows picks the console's ambient codepage (often cp1252) for stdout/stderr
    # regardless of the source file's own UTF-8 encoding — an em-dash then encodes
    # as a single cp1252 byte that's invalid UTF-8, rendering as mojibake on any
    # UTF-8 terminal. Force UTF-8 so output is correct independent of the caller's
    # environment. errors="replace" (not the reconfigure default of "strict") keeps
    # this crash-safe for the same reason the -o/--json byte-write path below is:
    # scanned skill content can contain arbitrary Unicode. Guarded: test doubles
    # for sys.stdout may lack reconfigure().
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    # -h/--help exits during parser.parse_args() below, before args.no_color
    # exists — a raw argv pre-scan is the only way to make --no-color affect
    # --help output too. Always (re)assigned, not just when --no-color is
    # present: RichHelpFormatter.console is a class attribute, so leaving a
    # prior no-color override in place would leak into later main() calls in
    # the same process (e.g. across tests) that didn't pass --no-color.
    argv_list = list(sys.argv[1:]) if argv is None else list(argv)
    RichHelpFormatter.console = (
        Console(no_color=True, color_system=None) if "--no-color" in argv_list else Console()
    )

    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    # After parse_args(): -h/--help exits during parsing, so this naturally
    # never prints before help text.
    if not args.quiet:
        maybe_print_wordmark(make_console(stderr=True, no_color=args.no_color))

    if args.command == "scan":
        return _run_scan(args)

    print_welcome(make_console(stderr=False, no_color=args.no_color))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
