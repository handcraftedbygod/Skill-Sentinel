"""One required check: the hand-composed wordmark and mascot stay aligned,
the outline layer never overlaps the fill layer, nothing leaks ANSI codes
when color is off."""

from sentinel.banner import (
    _MASCOT_ROWS,
    _add_outline,
    _block_wordmark,
    _build_banner,
    _build_footer,
    _build_welcome,
    _compose_hero_rows,
)


def test_block_wordmark_rows_are_equal_length():
    rows = _block_wordmark("SKILLTRACE")
    assert len(rows) == 14
    assert len({len(row) for row in rows}) == 1


def test_mascot_rows_are_equal_length_and_symmetric():
    assert len({len(row) for row in _MASCOT_ROWS}) == 1
    for row in _MASCOT_ROWS:
        assert row == row[::-1]


def test_outline_never_overlaps_fill():
    fill_rows, outline_rows = _add_outline(_block_wordmark("SKILLTRACE"))
    assert len(fill_rows) == len(outline_rows) == 16
    for fill_row, outline_row in zip(fill_rows, outline_rows):
        assert len(fill_row) == len(outline_row)
        for f, s in zip(fill_row, outline_row):
            assert not (f != " " and s != " ")


def test_outline_surrounds_every_fill_cell():
    fill_rows, outline_rows = _add_outline(["███"])
    # A solid 1x3 bar padded by 1 on every side should have its full
    # 8-neighborhood outlined — nothing floats unshaded next to the fill.
    combined = [
        "".join("X" if f != " " else ("o" if o != " " else ".") for f, o in zip(fr, orow))
        for fr, orow in zip(fill_rows, outline_rows)
    ]
    assert combined == [
        "ooooo",
        "oXXXo",
        "ooooo",
    ]


def test_compose_hero_rows_are_equal_length():
    rows = _compose_hero_rows()
    assert len({len(row) for row in rows}) == 1


def test_banner_plain_has_no_ansi_codes():
    banner = _build_banner(color=False)
    assert "\033[" not in banner
    assert "█" in banner


def test_banner_color_has_ansi_codes():
    banner = _build_banner(color=True)
    assert "\033[" in banner


def test_footer_plain_has_no_ansi_codes():
    footer = _build_footer(color=False)
    assert "\033[" not in footer
    assert "skilltrace v" in footer


def test_welcome_plain_has_no_ansi_codes():
    welcome = _build_welcome(color=False)
    assert "\033[" not in welcome
    assert "skilltrace scan ./my-skill" in welcome
