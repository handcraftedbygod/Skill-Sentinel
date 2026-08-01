"""Regression coverage for sentinel.skillmd's skill-directory discovery."""

from pathlib import Path

from sentinel.skillmd import discover_skill_directories, extract_usage_examples

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
