"""Regression coverage for sentinel.allowlist's benign-path matching."""

from sentinel.allowlist import is_benign_path


def test_bare_directory_open_of_allowlisted_prefix_is_benign():
    # os.walk/glob/iterdir on the skill's own root opens "/skill" (no trailing
    # slash) as a directory — must match, not just "/skill/<file>". Found
    # flagging real skills HIGH during the launch scan for listing their own
    # directory.
    assert is_benign_path("/skill")
    assert is_benign_path("/skill/scripts/format.py")


def test_unrelated_path_is_not_benign():
    assert not is_benign_path("/root/.ssh/id_rsa")
