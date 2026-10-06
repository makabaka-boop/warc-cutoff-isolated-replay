"""Shared pytest fixtures: in-process ASGI client with a fresh store."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.storage import store  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_store():
    store.reset()
    yield
    store.reset()


@pytest.fixture
def client_factory():
    async def _make():
        from app.main import app
        transport = ASGITransport(app=app)
        return AsyncClient(transport=transport, base_url="http://replay.local")
    return _make


@pytest.fixture
async def client(client_factory):
    c = await client_factory()
    yield c
    await c.aclose()
