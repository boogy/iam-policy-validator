"""HTTP client for AWS Service Reference API.

This module provides an async HTTP client with advanced features including
connection pooling, request batching/coalescing, and retry logic.
"""

import asyncio
import logging
from typing import Any

import httpx

from iam_validator.core import constants

logger = logging.getLogger(__name__)


class AWSServiceClient:
    """Async HTTP client with connection pooling and request coalescing.

    This class handles all HTTP operations for fetching AWS service data,
    including retry logic, request batching, and connection management.
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = constants.DEFAULT_HTTP_TIMEOUT_SECONDS,
        retries: int = 3,
        connection_pool_size: int = 50,
        keepalive_connections: int = 20,
    ) -> None:
        """Initialize HTTP client.

        Args:
            base_url: Base URL for AWS service reference API
            timeout: Request timeout in seconds
            retries: Number of retries for failed requests
            connection_pool_size: HTTP connection pool size
            keepalive_connections: Number of keepalive connections
        """
        self.base_url = base_url
        self.timeout = timeout
        self.retries = retries
        self.connection_pool_size = connection_pool_size
        self.keepalive_connections = keepalive_connections

        self._client: httpx.AsyncClient | None = None

        # Batch request queue for request coalescing
        self._batch_queue: dict[str, asyncio.Future[Any]] = {}
        self._batch_lock = asyncio.Lock()

    async def __aenter__(self) -> "AWSServiceClient":
        """Setup httpx client with HTTP/2 and connection pooling."""
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=True,
            limits=httpx.Limits(
                max_keepalive_connections=self.keepalive_connections,
                max_connections=self.connection_pool_size,
                keepalive_expiry=constants.DEFAULT_HTTP_TIMEOUT_SECONDS,
            ),
            http2=True,  # Enable HTTP/2 for multiplexing
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Close HTTP client.

        Args:
            exc_type: Exception type (required by async context manager protocol)
            exc_val: Exception value (required by async context manager protocol)
            exc_tb: Exception traceback (required by async context manager protocol)
        """
        # Parameters required by protocol but not used in this implementation
        del exc_type, exc_val, exc_tb

        if self._client:
            await self._client.aclose()
            self._client = None

    async def fetch(self, url: str) -> Any:
        """Fetch data from URL with retry logic and batching.

        This method implements request coalescing - if multiple coroutines
        request the same URL simultaneously, only one HTTP request is made
        and the result is shared.

        Args:
            url: URL to fetch

        Returns:
            Parsed JSON response data

        Raises:
            RuntimeError: If client is not initialized
            ValueError: If response is not valid JSON or resource not found
            Exception: If all retries fail
        """
        # First check: see if request is already in progress
        existing_future = None
        async with self._batch_lock:
            if url in self._batch_queue:
                existing_future = self._batch_queue[url]

        # Wait for existing request outside the lock
        if existing_future is not None:
            logger.debug(f"Coalescing request for {url}")
            return await existing_future

        # Create new future for this request
        loop = asyncio.get_event_loop()
        future: asyncio.Future[Any] = loop.create_future()

        # Second check: register future or use existing one (double-check pattern)
        async with self._batch_lock:
            if url in self._batch_queue:
                # Another coroutine registered while we were creating the future
                existing_future = self._batch_queue[url]
            else:
                # We're the first, register our future
                self._batch_queue[url] = future

        # If we found an existing future, wait for it
        if existing_future is not None:
            logger.debug(f"Coalescing request for {url} (late check)")
            return await existing_future

        # We're responsible for making the request
        try:
            # Actually make the request
            result = await self._make_request(url)
            if not future.done():
                future.set_result(result)
            return result
        except Exception as e:
            if not future.done():
                future.set_exception(e)
            raise
        finally:
            # Remove from queue
            async with self._batch_lock:
                self._batch_queue.pop(url, None)

    async def _make_request(self, url: str) -> Any:
        """Core HTTP request with exponential backoff.

        Args:
            url: URL to fetch

        Returns:
            Parsed JSON response data

        Raises:
            RuntimeError: If client is not initialized
            ValueError: If response is not valid JSON or resource not found
            Exception: If all retries fail
        """
        if not self._client:
            raise RuntimeError("Client not initialized. Use as async context manager.")

        last_exception: Exception | None = None

        for attempt in range(self.retries):
            try:
                logger.debug(f"Fetching URL: {url} (attempt {attempt + 1})")
                response = await self._client.get(url)
                response.raise_for_status()

                try:
                    data = response.json()
                    return data

                except Exception as json_error:  # pylint: disable=broad-exception-caught
                    logger.error(f"Failed to parse response as JSON: {json_error}")
                    raise ValueError(
                        f"Invalid JSON response from {url}: {json_error}"
                    ) from json_error

            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP error {e.response.status_code} for {url}")
                if e.response.status_code == 404:
                    raise ValueError(f"Service not found: {url}") from e
                last_exception = e

            except httpx.RequestError as e:
                logger.error(f"Request error for {url}: {e}")
                last_exception = e

            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error(f"Unexpected error for {url}: {e}")
                last_exception = e

            if attempt < self.retries - 1:
                wait_time = 2**attempt
                logger.info(f"Retrying in {wait_time} seconds...")
                await asyncio.sleep(wait_time)

        raise last_exception or Exception(f"Failed to fetch {url} after {self.retries} attempts")
