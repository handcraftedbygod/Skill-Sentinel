"""Regression coverage for sentinel.skillmd's skill-directory discovery."""

from pathlib import Path

from sentinel.skillmd import discover_skill_directories

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
