from __future__ import annotations

import pytest

from copley.data.fixtures import build_fixtures
from copley.data.split import split


@pytest.fixture
def fixtures():
    return build_fixtures()


@pytest.fixture
def split_result(fixtures):
    return split(fixtures, seed=42)
