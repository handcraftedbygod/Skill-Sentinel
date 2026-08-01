"""Cheap static red flags — the first pass, catches structural obfuscation before any sandboxing."""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path

from sentinel.findings import Finding, Severity
from sentinel.skillmd import discover_bundled_files

BASE64_BLOB_RE = re.compile(rb"[A-Za-z0-9+/]{%d,}={0,2}" % 200)

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

    findings: list[Finding] = []
    try:
        data = path.read_bytes()
    except OSError:
        return findings

    pattern = BASE64_BLOB_RE if min_length == 200 else re.compile(rb"[A-Za-z0-9+/]{%d,}={0,2}" % min_length)
    for match in pattern.finditer(data):
        blob = match.group(0)
        findings.append(
            Finding(
                category="base64_blob",
                severity=Severity.MEDIUM,
                summary=f"Long base64-looking string ({len(blob)} chars) in {path.name}",
                detail=blob[:60].decode("ascii", errors="replace") + "...",
                source=str(path),
            )
        )
    return findings


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
                findings.append(
                    Finding(
                        category="hidden_executable",
                        severity=Severity.CRITICAL,
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
