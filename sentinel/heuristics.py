"""Cheap static red flags — the first pass, catches structural obfuscation before any sandboxing."""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path

from sentinel.findings import Finding, Severity
from sentinel.skillmd import discover_bundled_files

BASE64_BLOB_RE = re.compile(rb"[A-Za-z0-9+/]{%d,}={0,2}" % 200)

# A blob immediately preceded by a standard data: URI prefix is a declared inline
# asset (badge logos, favicons, embedded images in READMEs) — unambiguous, since
# nothing about SkillCloak's threat model (a payload assigned to a variable for
# later decode-and-exec) needs to masquerade as one. Found repeated 3x
# independently in real README.md badges during the launch scan (shields.io-style
# custom-logo badges all embed an SVG this way).
DATA_URI_PREFIX_RE = re.compile(rb"data:[\w.+-]+/[\w.%+-]+;base64,$")

DIGIT_RE = re.compile(rb"[0-9]")
LOWERCASE_RE = re.compile(rb"[a-z]")


def _looks_like_real_base64(blob: bytes) -> bool:
    """Real base64-encoded binary/text draws roughly uniformly from all 64
    symbols, so a 200+ char run has virtually no chance of containing zero
    digits or zero lowercase letters. Plain-text data that happens to satisfy
    the base64 charset — most notably amino-acid sequences (the 20-letter
    protein alphabet is a subset of base64's, all-uppercase, no digits) — does
    not. Found flagging the canonical GFP sequence
    ("MSKGEELFTGVVPILVELDGDVNG...", ubiquitous in bioinformatics
    tutorials/examples) identically to an actual payload across 3 independent
    skills in a 158-skill scientific-skills scan.
    """
    return bool(DIGIT_RE.search(blob)) and bool(LOWERCASE_RE.search(blob))

DECODE_CALL_NAMES = {
    "b64decode",
    "b64decode".upper(),
    "urlsafe_b64decode",
    "decodebytes",
    "decodestring",
    "unhexlify",
    "fromhex",
    "decompress",
}

JS_EVAL_DECODE_RE = re.compile(
    r"\beval\s*\([^)]*\b(atob|Buffer\.from\s*\([^)]*['\"]base64['\"])",
    re.DOTALL,
)

TEXT_EXTENSIONS = {".py", ".js", ".ts", ".sh", ".rb", ".pl", ".txt", ".md", ".json", ".yaml", ".yml"}

# git ships these ~13 sample hooks, byte-identical, in every `git init`/`git clone`.
# They're executable/shebanged by git itself, never attacker-controlled, and never
# run (git only executes a hook file WITHOUT the .sample suffix) — flagging them is
# a guaranteed false positive on literally every git-cloned skill. Deliberately
# narrow: this does NOT exclude .git/ wholesale, since hiding a real payload behind
# .git/ is exactly the SkillCloak technique this heuristic exists to catch — only
# this one well-known, inert, git-shipped pattern is allowlisted.
GIT_HOOK_SAMPLE_RE = re.compile(r"^\.git/hooks/[^/]+\.sample$")

# Well-known maintainer/CI/packaging tooling directories. Unlike GIT_HOOK_SAMPLE_RE
# this is real, custom, attacker-writable content — not suppressed, just downgraded
# from CRITICAL to MEDIUM (still flagged, still visible; an attacker could still
# hide here). Found repeated 6x independently across the launch scan, always CI
# lint/test/commit-hook scripts, never referenced by or invoked as part of
# running the skill itself: .github/scripts/*.sh (swaponline/MultiCurrencyWallet,
# marmotdata/marmot x2, dreamwing/clawbridge), .githooks/* (Dicklesworthstone/
# mcp_agent_mail, wgzhao/Addax x2), .claude/hooks/* (sheeki03/tirith).
# .codex-marketplace/ added after sergebulaev/linkedin-skills: confirmed benign —
# the repo's own scripts/sync_codex_marketplace.py generates it as a byte-for-byte
# mirror of the already-visible top-level content, for OpenAI Codex's marketplace
# packaging format.
# (?:^|/) instead of a bare ^: found not matching when the same dev-tooling
# dir sits one level deeper than the skill root (jamditis/claude-skills-
# journalism's okf-wiki: "example/.claude/hooks/okf-anchor.py", a worked
# example nested under example/). The (?:^|/) lookback still requires a real
# path-component boundary, so "myexample.claude/hooks/foo.py" (a directory
# that merely ends in ".claude", not a real .claude dir) correctly does not
# match — only used with .search(), never .match().
DEV_TOOLING_DIR_RE = re.compile(
    r"(?:^|/)(\.github/|\.githooks/|\.gitlab-ci/|\.claude/hooks/|\.husky/|\.codex-marketplace/)"
)

# Below this many base64 blobs in one file, list each individually. At or above
# it, collapse into one finding — see scan_file_for_base64_blobs.
BASE64_GROUP_THRESHOLD = 3


def scan_file_for_base64_blobs(path: Path, min_length: int = 200) -> list[Finding]:
    """Flag long base64-looking runs in source/text files — a hallmark of
    self-extracting payloads (arXiv:2607.02357's structural obfuscation).

    Restricted to TEXT_EXTENSIONS, same as scan_file_for_eval_exec_decode: the
    threat model is a payload embedded in source code, not arbitrary bytes.
    Without this, binary image data (which randomly satisfies the base64
    charset over a long enough run) and legitimate embedded data: URIs in SVGs
    get flagged identically to an actual self-decoding payload.
    """
    if path.suffix not in TEXT_EXTENSIONS:
        return []

    # A "cassettes" directory is the well-known VCR.py/vcrpy/pytest-recording
    # convention for recorded HTTP test fixtures — response bodies (often
    # protobuf/gzip) get base64-encoded into committed YAML, never executed.
    # Found producing 52 near-identical MEDIUM findings across a single skill's
    # test suite (teng-lin/notebooklm-py) during the launch scan. Narrow by
    # design (unlike a generic tests/ or fixtures/ exclusion): "cassettes" is a
    # distinctive, purpose-specific library convention, not a name an attacker
    # would need to use for a real hiding spot.
    if "cassettes" in (part.lower() for part in path.parts):
        return []

    try:
        data = path.read_bytes()
    except OSError:
        return []

    pattern = BASE64_BLOB_RE if min_length == 200 else re.compile(rb"[A-Za-z0-9+/]{%d,}={0,2}" % min_length)
    blobs = [
        match.group(0)
        for match in pattern.finditer(data)
        if not DATA_URI_PREFIX_RE.search(data[max(0, match.start() - 100) : match.start()])
        and _looks_like_real_base64(match.group(0))
    ]
    if not blobs:
        return []

    # Below this many blobs in one file, list each individually. At or above it,
    # collapse into one finding — a single minified vendor.js/compiled contract
    # ABI can legitimately contain dozens of long base64-charset runs, and one
    # MEDIUM finding per match was found inflating scores/drowning the report on
    # real skills that bundle build artifacts, same shape as the openat grouping
    # fix in report.py.
    if len(blobs) < BASE64_GROUP_THRESHOLD:
        return [
            Finding(
                category="base64_blob",
                severity=Severity.MEDIUM,
                summary=f"Long base64-looking string ({len(blob)} chars) in {path.name}",
                detail=blob[:60].decode("ascii", errors="replace") + "...",
                source=str(path),
            )
            for blob in blobs
        ]
    return [
        Finding(
            category="base64_blob",
            severity=Severity.MEDIUM,
            summary=f"{len(blobs)} long base64-looking strings in {path.name} "
            f"(longest {max(len(b) for b in blobs)} chars)",
            detail=blobs[0][:60].decode("ascii", errors="replace") + "...",
            source=str(path),
        )
    ]


def _python_ast_has_decode_call(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            func = sub.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name in DECODE_CALL_NAMES:
                return True
    return False


def _scan_python_eval_exec_decode(path: Path, source: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = getattr(node.func, "id", None)
            if func_name in {"eval", "exec"} and _python_ast_has_decode_call(node):
                findings.append(
                    Finding(
                        category="eval_exec_decode",
                        severity=Severity.HIGH,
                        summary=f"{func_name}() of decoded content in {path.name}",
                        detail=f"line {getattr(node, 'lineno', '?')}",
                        source=str(path),
                    )
                )
    return findings


def _scan_js_eval_decode(path: Path, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in JS_EVAL_DECODE_RE.finditer(source):
        line_no = source.count("\n", 0, match.start()) + 1
        findings.append(
            Finding(
                category="eval_exec_decode",
                severity=Severity.HIGH,
                summary=f"eval() of decoded content in {path.name}",
                detail=f"line {line_no}",
                source=str(path),
            )
        )
    return findings


def scan_file_for_eval_exec_decode(path: Path) -> list[Finding]:
    """Flag eval()/exec() calls whose argument chain includes a decode call."""
    if path.suffix not in TEXT_EXTENSIONS:
        return []
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    if path.suffix == ".py":
        return _scan_python_eval_exec_decode(path, source)
    if path.suffix in {".js", ".ts"}:
        return _scan_js_eval_decode(path, source)
    return []


def scan_for_hidden_executable_content(skill_dir: Path) -> list[Finding]:
    """Flag executable content in dotfile/.git-style paths that SKILL.md never references.

    discover_bundled_files() intentionally skips dotfiles/dot-directories (that's what
    "referenced by SKILL.md" bundling means in practice) — this walks everything,
    including hidden paths, to find what fell outside that surface.
    """
    findings: list[Finding] = []
    referenced = {bf.relative_path for bf in discover_bundled_files(skill_dir)}

    for root, dirnames, filenames in os.walk(skill_dir):
        root_path = Path(root)
        for filename in filenames:
            file_path = root_path / filename
            # .as_posix(), not str(): this gets pattern-matched below and shown in
            # the report — a bare str() gives backslash separators on Windows,
            # which wouldn't match GIT_HOOK_SAMPLE_RE and reads oddly to users.
            relative_path = file_path.relative_to(skill_dir).as_posix()
            if relative_path in referenced:
                continue

            is_hidden = any(part.startswith(".") for part in Path(relative_path).parts)
            if not is_hidden:
                continue

            if GIT_HOOK_SAMPLE_RE.match(relative_path):
                continue

            is_executable = False
            try:
                is_executable = bool(file_path.stat().st_mode & 0o111)
            except OSError:
                pass

            has_shebang = False
            if not is_executable:
                try:
                    with open(file_path, "rb") as fh:
                        has_shebang = fh.read(2) == b"#!"
                except OSError:
                    pass

            if is_executable or has_shebang:
                severity = Severity.MEDIUM if DEV_TOOLING_DIR_RE.search(relative_path) else Severity.CRITICAL
                findings.append(
                    Finding(
                        category="hidden_executable",
                        severity=severity,
                        summary=f"Executable content at hidden path {relative_path}, not referenced by SKILL.md",
                        detail="executable bit set" if is_executable else "has shebang",
                        source=str(file_path),
                    )
                )
    return findings


def run_heuristics(skill_dir: Path) -> list[Finding]:
    """Single entry point: run all static heuristics against a skill directory."""
    findings: list[Finding] = []

    for bundled_file in discover_bundled_files(skill_dir):
        findings.extend(scan_file_for_base64_blobs(bundled_file.path))
        findings.extend(scan_file_for_eval_exec_decode(bundled_file.path))

    findings.extend(scan_for_hidden_executable_content(skill_dir))

    return findings
