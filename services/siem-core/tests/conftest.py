from __future__ import annotations

import fakeredis
import pytest


@pytest.fixture
def fake_redis():
    return fakeredis.FakeAsyncRedis(decode_responses=False)
