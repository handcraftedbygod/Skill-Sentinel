"""Regression coverage for sentinel.skillmd's skill-directory discovery."""

from pathlib import Path

from sentinel.skillmd import discover_skill_directories, extract_usage_examples, parse_skill_md

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"


def test_single_skill_repo_finds_its_own_root():
    found = discover_skill_directories(EXAMPLES_DIR / "benign-skill")
    assert found == [EXAMPLES_DIR / "benign-skill"]


def test_collection_repo_finds_every_subdirectory_skill(tmp_path):
    # Regression case: a repo bundling multiple skills, each in its own
    # subdirectory, has no root SKILL.md at all — before this, that whole
    # repo was invisible to the scanner (SkillMdNotFoundError on the root).
    (tmp_path / "skills" / "foo").mkdir(parents=True)
    (tmp_path / "skills" / "foo" / "SKILL.md").write_text("---\nname: foo\n---\n", encoding="utf-8")
    (tmp_path / "skills" / "bar").mkdir(parents=True)
    (tmp_path / "skills" / "bar" / "SKILL.md").write_text("---\nname: bar\n---\n", encoding="utf-8")

    found = discover_skill_directories(tmp_path)
    assert found == sorted([tmp_path / "skills" / "bar", tmp_path / "skills" / "foo"])


def test_skill_md_under_a_hidden_directory_is_not_a_real_skill(tmp_path):
    # A .codex-marketplace/-style mirror or a .git/ payload isn't a real,
    # independently-installable skill — same "visible surface" boundary as
    # discover_bundled_files() and the hidden_executable heuristic.
    (tmp_path / "SKILL.md").write_text("---\nname: real\n---\n", encoding="utf-8")
    hidden = tmp_path / ".codex-marketplace" / "mirrored-skill"
    hidden.mkdir(parents=True)
    (hidden / "SKILL.md").write_text("---\nname: mirrored\n---\n", encoding="utf-8")

    assert discover_skill_directories(tmp_path) == [tmp_path]


def test_skill_in_known_agent_tool_install_dir_is_found(tmp_path):
    # Regression test: found via snyk-labs/toxicskills-goof (a third-party
    # security research sample) — every skill in that repo, including the
    # actual malicious demo, lives under .agents/skills/ or .gemini/skills/,
    # standard install locations for those tools. The original blanket
    # "skip all dot-dirs" rule made the whole repo invisible except one
    # skill sitting outside any dot-dir. .git/ and unknown hidden dirs must
    # still be excluded.
    for tool_dir in (".claude", ".agents", ".gemini", ".cursor", ".codex", ".openclaw"):
        skill_dir = tmp_path / tool_dir / "skills" / "vercel"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text("---\nname: vercel\n---\n", encoding="utf-8")

    git_dir = tmp_path / ".git" / "skills" / "payload"
    git_dir.mkdir(parents=True)
    (git_dir / "SKILL.md").write_text("---\nname: hidden-payload\n---\n", encoding="utf-8")

    unknown_dir = tmp_path / ".some-other-tool" / "skills" / "foo"
    unknown_dir.mkdir(parents=True)
    (unknown_dir / "SKILL.md").write_text("---\nname: unknown-tool\n---\n", encoding="utf-8")

    found = discover_skill_directories(tmp_path)
    found_names = {p.relative_to(tmp_path).as_posix() for p in found}
    assert found_names == {
        ".claude/skills/vercel",
        ".agents/skills/vercel",
        ".gemini/skills/vercel",
        ".cursor/skills/vercel",
        ".codex/skills/vercel",
        ".openclaw/skills/vercel",
    }


def test_lowercase_skill_md_is_found_and_parsed(tmp_path):
    # Regression test: a real skill in snyk-labs/toxicskills-goof uses
    # "skill.md" (lowercase) — plausibly specifically to evade tools that
    # hardcode the exact-case "SKILL.md" filename.
    skill_dir = tmp_path / "clawhub"
    skill_dir.mkdir()
    (skill_dir / "skill.md").write_text("---\nname: clawhub\n---\nbody text\n", encoding="utf-8")

    assert discover_skill_directories(tmp_path) == [skill_dir]
    metadata = parse_skill_md(skill_dir)
    assert metadata.name == "clawhub"


def test_extract_usage_examples_skips_doc_placeholders():
    # Regression test: doc-style fill-in-the-blank placeholders were run as
    # literal invocation candidates — found producing a nonsensical
    # network_request finding when a URL containing __OWNER__/__REPO__/
    # __KEYRING__ resolved against the sandbox's own DNS sinkhole
    # (punkscience/agent-skills), and a bogus "sandbox broke" finding when a
    # ${BUN_X} {baseDir}/... command failed to execute (baoyu-skills). A real,
    # literal example must still be extracted.
    body = """
## Usage

```
curl -fsSL https://__OWNER__.github.io/__REPO__/apt/__KEYRING__ -o key.gpg
python3 scripts/main.py <input> [options]
python3 scripts/real_example.py --flag value
```
"""
    examples = extract_usage_examples(body)
    assert examples == ["python3 scripts/real_example.py --flag value"]
