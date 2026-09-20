import tomllib
from pathlib import Path

import databreaker


def test_package_version_matches_pyproject():
    data=tomllib.loads((Path(__file__).parents[1]/"pyproject.toml").read_text(encoding="utf-8"))
    assert databreaker.__version__ == data["project"]["version"]
