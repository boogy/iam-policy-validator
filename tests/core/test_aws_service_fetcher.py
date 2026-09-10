"""Unit tests for AWSServiceFetcher.fetch_multiple_services and ServiceCacheManager I/O."""

import asyncio
import logging
import time

import pytest

from iam_validator.core.aws_service.cache import ServiceCacheManager


class _StubStorage:
    def __init__(self, read_result=None):
        self._read_result = read_result

    def read_from_cache(self, url: str, base_url: str, allow_stale: bool = False):
        return self._read_result

    def write_to_cache(self, url: str, data, base_url: str) -> None:
        pass

    def clear_disk_cache(self) -> None:
        pass


async def test_fetch_multiple_services_returns_successes_when_one_service_fails(monkeypatch):
    from iam_validator.core.aws_service.fetcher import AWSServiceFetcher

    fetcher = AWSServiceFetcher()

    async def fake_fetch(name):
        if name == "brokensvc":
            raise RuntimeError("503 from AWS")
        return object()

    monkeypatch.setattr(fetcher, "fetch_service_by_name", fake_fetch)
    result = await fetcher.fetch_multiple_services(["s3", "brokensvc", "ec2"], strict=False)

    assert set(result) == {"s3", "ec2"}


async def test_fetch_multiple_services_failure_is_logged(monkeypatch, caplog):
    from iam_validator.core.aws_service.fetcher import AWSServiceFetcher

    fetcher = AWSServiceFetcher()

    async def fake_fetch(name):
        raise RuntimeError("503 from AWS")

    monkeypatch.setattr(fetcher, "fetch_service_by_name", fake_fetch)
    with caplog.at_level(logging.WARNING):
        assert await fetcher.fetch_multiple_services(["s3"], strict=False) == {}
    assert any("s3" in r.message for r in caplog.records)


async def test_fetch_multiple_services_strict_raises_original_exception(monkeypatch):
    from iam_validator.core.aws_service.fetcher import AWSServiceFetcher

    fetcher = AWSServiceFetcher()

    async def fake_fetch(name):
        if name == "brokensvc":
            raise RuntimeError("503 from AWS")
        return object()

    monkeypatch.setattr(fetcher, "fetch_service_by_name", fake_fetch)

    with pytest.raises(RuntimeError, match="503 from AWS"):
        await fetcher.fetch_multiple_services(["s3", "brokensvc", "ec2"], strict=True)


async def test_fetch_multiple_services_default_is_strict(monkeypatch):
    from iam_validator.core.aws_service.fetcher import AWSServiceFetcher

    fetcher = AWSServiceFetcher()

    async def fake_fetch(name):
        raise RuntimeError("503 from AWS")

    monkeypatch.setattr(fetcher, "fetch_service_by_name", fake_fetch)

    with pytest.raises(RuntimeError, match="503 from AWS"):
        await fetcher.fetch_multiple_services(["s3"])


async def test_cache_get_does_not_block_the_event_loop(monkeypatch):
    storage = _StubStorage(read_result=None)
    cache = ServiceCacheManager(storage=storage)

    def slow_read(*a, **kw):
        time.sleep(0.3)
        return None

    monkeypatch.setattr(storage, "read_from_cache", slow_read)

    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0.01)

    task = asyncio.create_task(ticker())
    await cache.get("s3", url="https://example/x", base_url="https://example")
    task.cancel()

    assert ticks > 5, "the event loop was blocked during a cache read"


async def test_cache_get_stale_does_not_block_the_event_loop(monkeypatch):
    storage = _StubStorage(read_result=None)
    cache = ServiceCacheManager(storage=storage)

    def slow_read(*a, **kw):
        time.sleep(0.3)
        return None

    monkeypatch.setattr(storage, "read_from_cache", slow_read)

    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0.01)

    task = asyncio.create_task(ticker())
    await cache.get_stale(url="https://example/x", base_url="https://example")
    task.cancel()

    assert ticks > 5, "the event loop was blocked during a stale cache read"
