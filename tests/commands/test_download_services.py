"""Tests for the sync-services command."""

import json

import httpx

from iam_validator.commands.download_services import DownloadServicesCommand
from iam_validator.core.aws_service.storage import GLOBAL_CONDITION_KEYS_FILENAME
from iam_validator.core.config.aws_api import AWS_GLOBAL_CONDITION_KEYS_URL

PAYLOAD = [{"Name": "aws:EpochTime", "Types": ["Numeric", "Date"]}]


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_global_condition_keys_are_saved(tmp_path):
    requested = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(200, json=PAYLOAD)

    async with _client(handler) as client:
        saved = await DownloadServicesCommand()._download_global_condition_keys(client, tmp_path)

    assert saved is True
    assert requested == [AWS_GLOBAL_CONDITION_KEYS_URL]
    assert json.loads((tmp_path / GLOBAL_CONDITION_KEYS_FILENAME).read_text()) == PAYLOAD


async def test_global_condition_keys_failure_is_not_fatal(tmp_path):
    async with _client(lambda request: httpx.Response(503)) as client:
        saved = await DownloadServicesCommand()._download_global_condition_keys(client, tmp_path)

    assert saved is False
    assert not (tmp_path / GLOBAL_CONDITION_KEYS_FILENAME).exists()


async def test_unexpected_global_condition_keys_shape_is_not_saved(tmp_path):
    async with _client(lambda request: httpx.Response(200, json={"Name": "aws:EpochTime"})) as client:
        saved = await DownloadServicesCommand()._download_global_condition_keys(client, tmp_path)

    assert saved is False
    assert not (tmp_path / GLOBAL_CONDITION_KEYS_FILENAME).exists()
