"""skill-sentinel CLI: scan <path|git-url> [--invoke CMD] [--allow-network] [--json]"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from sentinel.findings import Severity
from sentinel.heuristics import run_heuristics
from sentinel.report import build_report, render_json, render_markdown
from sentinel.sandbox import (
    DockerUnavailableError,
    SentinelError,
    build_invocation_candidates,
    ensure_docker_available,
    resolve_skill_source,
    run_skill_in_sandbox,
)
from sentinel.skillmd import SkillMdNotFoundError, SkillMdParseError, discover_bundled_files, parse_skill_md

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
            skill_dir = resolve_skill_source(args.path_or_url, Path(tmpdir))
        except SentinelError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        try:
            metadata = parse_skill_md(skill_dir)
        except (SkillMdNotFoundError, SkillMdParseError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        heuristic_findings = run_heuristics(skill_dir)
        bundled_files = discover_bundled_files(skill_dir)
        candidates = build_invocation_candidates(skill_dir, bundled_files, metadata.body, args.invoke)

        sandbox_results = None
        if not args.no_sandbox:
            try:
                ensure_docker_available()
            except DockerUnavailableError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 3

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

        report = build_report(skill_dir, metadata, heuristic_findings, sandbox_results, candidates)

    output = render_json(report) if args.json else render_markdown(report)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output)

    if args.fail_threshold:
        threshold = Severity(args.fail_threshold)
        if report.risk_level.rank >= threshold.rank:
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
