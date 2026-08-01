"""skill-sentinel CLI: scan <path|git-url> [--invoke CMD] [--allow-network] [--json]"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from sentinel.findings import Severity
from sentinel.heuristics import run_heuristics
from sentinel.report import build_report, render_json_multi, render_markdown_multi
from sentinel.sandbox import (
    DockerUnavailableError,
    SentinelError,
    build_invocation_candidates,
    ensure_docker_available,
    resolve_skill_source,
    run_skill_in_sandbox,
)
from sentinel.skillmd import (
    SkillMdNotFoundError,
    SkillMdParseError,
    discover_bundled_files,
    discover_skill_directories,
    parse_skill_md,
)

FAIL_THRESHOLD_CHOICES = ["low", "medium", "high", "critical"]


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

    return parser


def _run_scan(args: argparse.Namespace) -> int:
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
        for skill_dir in skill_dirs:
            try:
                metadata = parse_skill_md(skill_dir)
            except (SkillMdNotFoundError, SkillMdParseError) as exc:
                print(f"warning: skipping {skill_dir}: {exc}", file=sys.stderr)
                continue

            heuristic_findings = run_heuristics(skill_dir)
            bundled_files = discover_bundled_files(skill_dir)
            candidates = build_invocation_candidates(skill_dir, bundled_files, metadata.body, args.invoke)

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

            reports.append(build_report(skill_dir, metadata, heuristic_findings, sandbox_results, candidates))

        if not reports:
            print(f"error: No valid SKILL.md could be parsed under {source_dir}", file=sys.stderr)
            return 2

    output = render_json_multi(reports) if args.json else render_markdown_multi(reports)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        # Not print(): a scanned skill's own description/findings can contain
        # arbitrary Unicode (em dashes, non-English text, ...), and the console's
        # default encoding (e.g. cp1252 on Windows) can't represent all of it —
        # print() would crash the whole scan over the skill's own text content.
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
