"""Unit tests for AWSServiceFetcher.fetch_multiple_services and ServiceCacheManager I/O."""

import asyncio
import json
import logging
import os
import time

import pytest

from iam_validator.core.aws_service.cache import ServiceCacheManager


class _StubStorage:
    def __init__(self, read_result=None):
        self._read_result = read_result

    def read_from_cache(self, url: str, base_url: str, allow_stale: bool = False, modified=None):
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


_GLOBAL_KEYS_PAYLOAD = [
    {"Name": "aws:EpochTime", "Types": ["Numeric", "Date"], "DocPage": "/IAM/latest/UserGuide/x.html"},
    {"Name": "aws:RequestTag/${TagKey}", "Types": ["String", "Numeric"]},
]


async def test_global_conditions_load_from_offline_file(tmp_path):
    from iam_validator.core.aws_service.fetcher import AWSServiceFetcher
    from iam_validator.core.aws_service.storage import GLOBAL_CONDITION_KEYS_FILENAME

    (tmp_path / GLOBAL_CONDITION_KEYS_FILENAME).write_text(json.dumps(_GLOBAL_KEYS_PAYLOAD))
    fetcher = AWSServiceFetcher(aws_services_dir=tmp_path, prefetch_common=False)

    keys = await fetcher.get_global_conditions()

    assert keys.source == "aws-api"
    assert keys.get_key_types("aws:EpochTime") == ["Numeric", "Date"]
    assert keys.is_valid_global_key("ec2:RoleDelivery")


async def test_global_conditions_fall_back_to_bundled_without_offline_file(tmp_path):
    from iam_validator.core.aws_service.fetcher import AWSServiceFetcher
    from iam_validator.core.config.aws_global_conditions import get_global_conditions

    fetcher = AWSServiceFetcher(aws_services_dir=tmp_path, prefetch_common=False)

    assert await fetcher.get_global_conditions() is get_global_conditions()


async def test_global_conditions_fall_back_to_bundled_on_corrupt_offline_file(tmp_path):
    from iam_validator.core.aws_service.fetcher import AWSServiceFetcher
    from iam_validator.core.aws_service.storage import GLOBAL_CONDITION_KEYS_FILENAME

    (tmp_path / GLOBAL_CONDITION_KEYS_FILENAME).write_text("{not json")
    fetcher = AWSServiceFetcher(aws_services_dir=tmp_path, prefetch_common=False)

    assert (await fetcher.get_global_conditions()).source == "bundled"


async def test_global_conditions_fetched_once_and_cached_on_disk(tmp_path, monkeypatch):
    from iam_validator.core.aws_service.fetcher import AWSServiceFetcher

    calls = []

    async def fake_fetch(url):
        calls.append(url)
        return _GLOBAL_KEYS_PAYLOAD

    fetcher = AWSServiceFetcher(cache_dir=tmp_path, prefetch_common=False)
    monkeypatch.setattr(fetcher._client, "fetch", fake_fetch)
    assert (await fetcher.get_global_conditions()).source == "aws-api"
    await fetcher.get_global_conditions()

    second = AWSServiceFetcher(cache_dir=tmp_path, prefetch_common=False)
    monkeypatch.setattr(second._client, "fetch", fake_fetch)
    assert (await second.get_global_conditions()).source == "aws-api"

    assert len(calls) == 1


async def test_global_conditions_use_stale_cache_when_api_fails(tmp_path, monkeypatch):
    from iam_validator.core.aws_service.fetcher import AWSServiceFetcher
    from iam_validator.core.config.aws_api import AWS_GLOBAL_CONDITION_KEYS_URL

    seed = AWSServiceFetcher(cache_dir=tmp_path, prefetch_common=False)
    seed._storage.write_to_cache(AWS_GLOBAL_CONDITION_KEYS_URL, _GLOBAL_KEYS_PAYLOAD, seed.BASE_URL)
    for f in tmp_path.rglob("*.json"):
        os.utime(f, (0, 0))

    async def failing_fetch(url):
        raise RuntimeError("503 from AWS")

    fetcher = AWSServiceFetcher(cache_dir=tmp_path, prefetch_common=False)
    monkeypatch.setattr(fetcher._client, "fetch", failing_fetch)

    assert (await fetcher.get_global_conditions()).source == "aws-api"


async def test_global_conditions_fall_back_to_bundled_when_api_fails_without_cache(tmp_path, monkeypatch):
    from iam_validator.core.aws_service.fetcher import AWSServiceFetcher

    async def failing_fetch(url):
        raise RuntimeError("503 from AWS")

    fetcher = AWSServiceFetcher(cache_dir=tmp_path, prefetch_common=False)
    monkeypatch.setattr(fetcher._client, "fetch", failing_fetch)

    assert (await fetcher.get_global_conditions()).source == "bundled"


def _expired_cache_entry(tmp_path):
    from iam_validator.core.aws_service.storage import ServiceFileStorage

    storage = ServiceFileStorage(cache_dir=tmp_path, cache_ttl=60)
    url = "https://example/v1/s3/s3.json"
    storage.write_to_cache(url, {"Name": "s3"}, "https://example/")
    (cache_file,) = tmp_path.rglob("*.json")
    written_at = time.time() - 3600
    os.utime(cache_file, (written_at, written_at))
    return storage, url, int(written_at)


def test_expired_cache_entry_is_reused_when_unchanged_upstream(tmp_path):
    storage, url, written_at = _expired_cache_entry(tmp_path)

    assert storage.read_from_cache(url, "https://example/", modified=written_at - 10) == {"Name": "s3"}


def test_expired_cache_entry_is_refetched_when_changed_upstream(tmp_path):
    storage, url, written_at = _expired_cache_entry(tmp_path)

    assert storage.read_from_cache(url, "https://example/", modified=written_at + 10) is None


def test_expired_cache_entry_is_refetched_without_modified(tmp_path):
    storage, url, _ = _expired_cache_entry(tmp_path)

    assert storage.read_from_cache(url, "https://example/") is None


@pytest.mark.parametrize(
    ("modified", "expected"),
    [(1792604720, 1792604720), ("1792604720", None), (True, None), (None, None)],
)
def test_parse_services_list_reads_modified(modified, expected):
    from iam_validator.core.aws_service.storage import parse_services_list

    entry = {"service": "s3", "url": "https://example/s3.json"}
    if modified is not None:
        entry["modified"] = modified

    (service,) = parse_services_list([entry])

    assert service.modified == expected


async def test_fetch_service_reuses_expired_cache_when_unchanged_upstream(tmp_path, monkeypatch):
    from iam_validator.core.aws_service.fetcher import AWSServiceFetcher
    from iam_validator.core.models import ServiceInfo

    url = "https://servicereference.us-east-1.amazonaws.com/v1/s3/s3.json"
    fetcher = AWSServiceFetcher(cache_dir=tmp_path, cache_ttl=60, prefetch_common=False)
    fetcher._storage.write_to_cache(url, {"Name": "s3", "Actions": []}, fetcher.BASE_URL)
    (cache_file,) = tmp_path.rglob("*.json")
    written_at = time.time() - 3600
    os.utime(cache_file, (written_at, written_at))

    async def fake_services():
        return [ServiceInfo(service="s3", url=url, modified=int(written_at) - 10)]

    calls = []

    async def fake_fetch(fetch_url):
        calls.append(fetch_url)
        return {"Name": "s3", "Actions": []}

    monkeypatch.setattr(fetcher, "fetch_services", fake_services)
    monkeypatch.setattr(fetcher._client, "fetch", fake_fetch)

    assert (await fetcher.fetch_service_by_name("s3")).name == "s3"
    assert calls == []
