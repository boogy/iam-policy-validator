"""AWS Service Fetcher Module with advanced caching and performance features.

This module provides functionality to fetch AWS service information from the AWS service reference API.
It includes methods to retrieve a list of services, fetch detailed information for specific services,
and handle errors gracefully.

Features:
- TTL-based caching with automatic expiry
- LRU memory cache for frequently accessed services
- Service pre-fetching for common services
- Batch API requests support
- Compiled regex patterns for better performance
- Connection pool optimization
- Request coalescing for duplicate requests

Example usage:
    async with AWSServiceFetcher() as fetcher:
        services = await fetcher.fetch_services()
        service_detail = await fetcher.fetch_service_by_name("S3")
"""

import asyncio
import hashlib
import json
import logging
import re
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

import httpx

from iam_validator.core.models import ServiceDetail, ServiceInfo

logger = logging.getLogger(__name__)


class LRUCache:
    """Thread-safe LRU cache implementation with TTL support."""

    def __init__(self, maxsize: int = 128, ttl: int = 3600):
        """Initialize LRU cache.

        Args:
            maxsize: Maximum number of items in cache
            ttl: Time to live in seconds (default: 1 hour)
        """
        self.cache: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self.maxsize = maxsize
        self.ttl = ttl
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Any | None:
        """Get item from cache if not expired."""
        async with self._lock:
            if key in self.cache:
                value, timestamp = self.cache[key]
                if time.time() - timestamp < self.ttl:
                    # Move to end (most recently used)
                    self.cache.move_to_end(key)
                    return value
                else:
                    # Expired, remove it
                    del self.cache[key]
        return None

    async def set(self, key: str, value: Any) -> None:
        """Set item in cache with current timestamp."""
        async with self._lock:
            if key in self.cache:
                # Move to end if exists
                self.cache.move_to_end(key)
            elif len(self.cache) >= self.maxsize:
                # Remove least recently used
                self.cache.popitem(last=False)

            self.cache[key] = (value, time.time())

    async def clear(self) -> None:
        """Clear the cache."""
        async with self._lock:
            self.cache.clear()


class CompiledPatterns:
    """Pre-compiled regex patterns for validation."""

    _instance = None

    def __new__(cls) -> "CompiledPatterns":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self) -> None:
        """Initialize compiled patterns."""
        # ARN validation pattern
        self.arn_pattern = re.compile(
            r"^arn:(?P<partition>(aws|aws-cn|aws-us-gov|aws-eusc|aws-iso|aws-iso-b|aws-iso-e|aws-iso-f)):"
            r"(?P<service>[a-z0-9\-]+):"
            r"(?P<region>[a-z0-9\-]*):"
            r"(?P<account>[0-9]*):"
            r"(?P<resource>.+)$",
            re.IGNORECASE,
        )

        # Action format pattern
        self.action_pattern = re.compile(
            r"^(?P<service>[a-zA-Z0-9_-]+):(?P<action>[a-zA-Z0-9*_-]+)$"
        )

        # Wildcard detection patterns
        self.wildcard_pattern = re.compile(r"\*")
        self.partial_wildcard_pattern = re.compile(r"^[^*]+\*$")


class AWSServiceFetcher:
    """Fetches AWS service information from the AWS service reference API with enhanced performance features."""

    BASE_URL = "https://servicereference.us-east-1.amazonaws.com/"

    # Common AWS services to pre-fetch
    COMMON_SERVICES = [
        "iam",
        "sts",
        "s3",
        "ec2",
        "lambda",
        "dynamodb",
        "rds",
        "cloudwatch",
        "sns",
        "sqs",
        "kms",
        "cloudformation",
        "elasticloadbalancing",
        "autoscaling",
        "route53",
        "apigateway",
        "ecs",
        "eks",
        "cloudfront",
        "logs",
        "events",
    ]

    def __init__(
        self,
        timeout: float = 30.0,
        retries: int = 3,
        enable_cache: bool = True,
        cache_ttl: int = 3600,
        memory_cache_size: int = 256,
        connection_pool_size: int = 50,
        keepalive_connections: int = 20,
        prefetch_common: bool = True,
    ):
        """Initialize aws service fetcher.

        Args:
            timeout: Request timeout in seconds
            retries: Number of retry attempts
            enable_cache: Enable disk caching
            cache_ttl: Cache time to live in seconds (default: 1 hour)
            memory_cache_size: Max items in memory cache
            connection_pool_size: Max connections in pool
            keepalive_connections: Number of keepalive connections
            prefetch_common: Pre-fetch common services on init
        """
        self.timeout = timeout
        self.retries = retries
        self.enable_cache = enable_cache
        self.cache_ttl = cache_ttl
        self.prefetch_common = prefetch_common

        self._client: httpx.AsyncClient | None = None
        self._memory_cache = LRUCache(maxsize=memory_cache_size, ttl=cache_ttl)
        self._cache_dir = Path.cwd() / ".cache" / "aws_services"
        self._patterns = CompiledPatterns()

        # Batch request queue
        self._batch_queue: dict[str, asyncio.Future[Any]] = {}
        self._batch_lock = asyncio.Lock()

        # Connection pool settings
        self.connection_pool_size = connection_pool_size
        self.keepalive_connections = keepalive_connections

        # Track prefetched services
        self._prefetched_services: set[str] = set()

        # Create cache directory if needed
        if self.enable_cache:
            self._cache_dir.mkdir(parents=True, exist_ok=True)

    async def __aenter__(self) -> "AWSServiceFetcher":
        """Async context manager entry with optimized settings."""
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=True,
            limits=httpx.Limits(
                max_keepalive_connections=self.keepalive_connections,
                max_connections=self.connection_pool_size,
                keepalive_expiry=30.0,  # Keep connections alive for 30 seconds
            ),
            http2=True,  # Enable HTTP/2 for multiplexing
        )

        # Pre-fetch common services if enabled
        if self.prefetch_common:
            await self._prefetch_common_services()

        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        del exc_type, exc_val, exc_tb
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _prefetch_common_services(self) -> None:
        """Pre-fetch commonly used AWS services for better performance."""
        logger.info(f"Pre-fetching {len(self.COMMON_SERVICES)} common AWS services...")

        # First, fetch the services list once to populate the cache
        # This prevents all concurrent calls from fetching the same list
        await self.fetch_services()

        async def fetch_service(name: str) -> None:
            try:
                await self.fetch_service_by_name(name)
                self._prefetched_services.add(name)
            except Exception as e:
                logger.warning(f"Failed to prefetch service {name}: {e}")

        # Fetch in batches to avoid overwhelming the API
        batch_size = 5
        for i in range(0, len(self.COMMON_SERVICES), batch_size):
            batch = self.COMMON_SERVICES[i : i + batch_size]
            await asyncio.gather(*[fetch_service(name) for name in batch])

        logger.info(f"Pre-fetched {len(self._prefetched_services)} services successfully")

    def _get_cache_path(self, url: str) -> Path:
        """Get cache file path with timestamp for TTL checking."""
        url_hash = hashlib.md5(url.encode()).hexdigest()

        # Extract service name for better organization
        filename = f"{url_hash}.json"
        if "/v1/" in url:
            service_name = url.split("/v1/")[1].split("/")[0]
            filename = f"{service_name}_{url_hash[:8]}.json"
        elif url == self.BASE_URL:
            filename = "services_list.json"

        return self._cache_dir / filename

    def _read_from_cache(self, url: str) -> Any | None:
        """Read from disk cache with TTL checking."""
        if not self.enable_cache:
            return None

        cache_path = self._get_cache_path(url)

        if not cache_path.exists():
            return None

        try:
            # Check file modification time for TTL
            mtime = cache_path.stat().st_mtime
            if time.time() - mtime > self.cache_ttl:
                logger.debug(f"Cache expired for {url}")
                cache_path.unlink()  # Remove expired cache
                return None

            with open(cache_path, encoding="utf-8") as f:
                data = json.load(f)
            logger.debug(f"Disk cache hit for {url}")
            return data

        except Exception as e:
            logger.warning(f"Failed to read cache for {url}: {e}")
            return None

    def _write_to_cache(self, url: str, data: Any) -> None:
        """Write to disk cache."""
        if not self.enable_cache:
            return

        cache_path = self._get_cache_path(url)

        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Written to disk cache: {url}")
        except Exception as e:
            logger.warning(f"Failed to write cache for {url}: {e}")

    async def _make_request_with_batching(self, url: str) -> Any:
        """Make request with request batching/coalescing.

        Uses double-check locking pattern to avoid race conditions and deadlocks.
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
        """Make HTTP request with multi-level caching."""
        # Check memory cache first
        cache_key = f"url:{url}"
        cached_data = await self._memory_cache.get(cache_key)
        if cached_data is not None:
            logger.debug(f"Memory cache hit for {url}")
            return cached_data

        # Check disk cache
        cached_data = self._read_from_cache(url)
        if cached_data is not None:
            # Store in memory cache for faster access
            await self._memory_cache.set(cache_key, cached_data)
            return cached_data

        if not self._client:
            raise RuntimeError("Fetcher not initialized. Use as async context manager.")

        last_exception: Exception | None = None

        for attempt in range(self.retries):
            try:
                logger.debug(f"Fetching URL: {url} (attempt {attempt + 1})")
                response = await self._client.get(url)
                response.raise_for_status()

                try:
                    data = response.json()

                    # Cache in both memory and disk
                    await self._memory_cache.set(cache_key, data)
                    self._write_to_cache(url, data)

                    return data

                except Exception as json_error:
                    logger.error(f"Failed to parse response as JSON: {json_error}")
                    raise ValueError(f"Invalid JSON response from {url}: {json_error}")

            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP error {e.response.status_code} for {url}")
                if e.response.status_code == 404:
                    raise ValueError(f"Service not found: {url}")
                last_exception = e

            except httpx.RequestError as e:
                logger.error(f"Request error for {url}: {e}")
                last_exception = e

            except Exception as e:
                logger.error(f"Unexpected error for {url}: {e}")
                last_exception = e

            if attempt < self.retries - 1:
                wait_time = 2**attempt
                logger.info(f"Retrying in {wait_time} seconds...")
                await asyncio.sleep(wait_time)

        raise last_exception or Exception(f"Failed to fetch {url} after {self.retries} attempts")

    async def fetch_services(self) -> list[ServiceInfo]:
        """Fetch list of AWS services with caching."""
        # Check if we have the parsed services list in cache
        services_cache_key = "parsed_services_list"
        cached_services = await self._memory_cache.get(services_cache_key)
        if cached_services is not None and isinstance(cached_services, list):
            logger.debug(f"Retrieved {len(cached_services)} services from parsed cache")
            return cached_services

        # Not in parsed cache, fetch the raw data
        data = await self._make_request_with_batching(self.BASE_URL)

        if not isinstance(data, list):
            raise ValueError("Expected list of services from root endpoint")

        services: list[ServiceInfo] = []
        for item in data:
            if isinstance(item, dict):
                service = item.get("service")
                url = item.get("url")
                if service and url:
                    services.append(ServiceInfo(service=str(service), url=str(url)))

        # Cache the parsed services list
        await self._memory_cache.set(services_cache_key, services)

        # Log only on first fetch (when parsed cache was empty)
        logger.info(f"Fetched and parsed {len(services)} services from AWS API")
        return services

    async def fetch_service_by_name(self, service_name: str) -> ServiceDetail:
        """Fetch service detail with optimized caching."""
        # Normalize service name
        service_name_lower = service_name.lower()

        # Check memory cache with service name as key
        cache_key = f"service:{service_name_lower}"
        cached_detail = await self._memory_cache.get(cache_key)
        if isinstance(cached_detail, ServiceDetail):
            logger.debug(f"Memory cache hit for service {service_name}")
            return cached_detail

        # Fetch service list and find URL
        services = await self.fetch_services()

        for service in services:
            if service.service.lower() == service_name_lower:
                # Fetch service detail
                data = await self._make_request_with_batching(service.url)

                # Validate and parse
                service_detail = ServiceDetail.model_validate(data)

                # Cache with service name as key
                await self._memory_cache.set(cache_key, service_detail)

                return service_detail

        raise ValueError(f"Service '{service_name}' not found")

    async def fetch_multiple_services(self, service_names: list[str]) -> dict[str, ServiceDetail]:
        """Fetch multiple services concurrently with optimized batching."""

        async def fetch_single(name: str) -> tuple[str, ServiceDetail]:
            try:
                detail = await self.fetch_service_by_name(name)
                return name, detail
            except Exception as e:
                logger.error(f"Failed to fetch service {name}: {e}")
                raise

        # Fetch all services concurrently
        tasks = [fetch_single(name) for name in service_names]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        services: dict[str, ServiceDetail] = {}
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Failed to fetch service {service_names[i]}: {result}")
                raise result
            elif isinstance(result, tuple):
                name, detail = result
                services[name] = detail

        return services

    def parse_action(self, action: str) -> tuple[str, str]:
        """Parse IAM action using compiled regex for better performance."""
        match = self._patterns.action_pattern.match(action)
        if not match:
            raise ValueError(f"Invalid action format: {action}")

        return match.group("service").lower(), match.group("action")

    def _match_wildcard_action(self, pattern: str, actions: list[str]) -> tuple[bool, list[str]]:
        """Match wildcard pattern against list of actions.

        Args:
            pattern: Action pattern with wildcards (e.g., "Get*", "*Object", "Describe*")
            actions: List of valid action names

        Returns:
            Tuple of (has_matches, list_of_matched_actions)
        """
        # Convert wildcard pattern to regex
        # Escape special regex chars except *, then replace * with .*
        regex_pattern = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
        compiled_pattern = re.compile(regex_pattern, re.IGNORECASE)

        matched = [a for a in actions if compiled_pattern.match(a)]
        return len(matched) > 0, matched

    async def validate_action(
        self, action: str, allow_wildcards: bool = True
    ) -> tuple[bool, str | None, bool]:
        """Validate IAM action with optimized caching.

        Supports:
        - Exact actions: s3:GetObject
        - Full wildcards: s3:*
        - Partial wildcards: s3:Get*, s3:*Object, s3:*Get*

        Returns:
            Tuple of (is_valid, error_message, is_wildcard)
        """
        try:
            service_prefix, action_name = self.parse_action(action)

            # Quick wildcard check using compiled pattern
            is_wildcard = bool(self._patterns.wildcard_pattern.search(action_name))

            # Handle full wildcard
            if action_name == "*":
                if allow_wildcards:
                    # Just verify service exists
                    await self.fetch_service_by_name(service_prefix)
                    return True, None, True
                else:
                    return False, "Wildcard actions are not allowed", True

            # Fetch service details (will use cache)
            service_detail = await self.fetch_service_by_name(service_prefix)
            available_actions = list(service_detail.actions.keys())

            # Handle partial wildcards (e.g., Get*, *Object, Describe*)
            if is_wildcard:
                if not allow_wildcards:
                    return False, "Wildcard actions are not allowed", True

                has_matches, matched_actions = self._match_wildcard_action(
                    action_name, available_actions
                )

                if has_matches:
                    # Wildcard is valid and matches at least one action
                    match_count = len(matched_actions)
                    sample_actions = matched_actions[:5]  # Show up to 5 examples
                    examples = ", ".join(sample_actions)
                    if match_count > 5:
                        examples += f", ... ({match_count - 5} more)"

                    return True, None, True
                else:
                    # Wildcard doesn't match any actions
                    return (
                        False,
                        f"Action pattern '{action_name}' does not match any actions in service '{service_prefix}'",
                        True,
                    )

            # Check if exact action exists (case-insensitive)
            action_exists = any(a.lower() == action_name.lower() for a in available_actions)

            if action_exists:
                return True, None, False
            else:
                # Suggest similar actions
                similar = [a for a in available_actions if action_name.lower() in a.lower()][:3]

                suggestion = f" Did you mean: {', '.join(similar)}?" if similar else ""
                return (
                    False,
                    f"Action '{action_name}' not found in service '{service_prefix}'.{suggestion}",
                    False,
                )

        except ValueError as e:
            return False, str(e), False
        except Exception as e:
            logger.error(f"Error validating action {action}: {e}")
            return False, f"Failed to validate action: {str(e)}", False

    def validate_arn(self, arn: str) -> tuple[bool, str | None]:
        """Validate ARN format using compiled regex."""
        if arn == "*":
            return True, None

        match = self._patterns.arn_pattern.match(arn)
        if not match:
            return False, f"Invalid ARN format: {arn}"

        return True, None

    async def validate_condition_key(
        self, action: str, condition_key: str
    ) -> tuple[bool, str | None]:
        """Validate condition key with optimized caching."""
        try:
            from iam_validator.core.aws_global_conditions import get_global_conditions

            service_prefix, action_name = self.parse_action(action)

            # Check global conditions first (fast)
            if condition_key.startswith("aws:"):
                global_conditions = get_global_conditions()
                if global_conditions.is_valid_global_key(condition_key):
                    return True, None
                else:
                    return (
                        False,
                        f"Invalid AWS global condition key: '{condition_key}'.",
                    )

            # Fetch service detail (cached)
            service_detail = await self.fetch_service_by_name(service_prefix)

            # Check service-specific condition keys
            if condition_key in service_detail.condition_keys:
                return True, None

            # Check action-specific condition keys
            if action_name in service_detail.actions:
                action_detail = service_detail.actions[action_name]
                if (
                    action_detail.action_condition_keys
                    and condition_key in action_detail.action_condition_keys
                ):
                    return True, None

            return (
                False,
                f"Condition key '{condition_key}' is not valid for action '{action}'",
            )

        except Exception as e:
            logger.error(f"Error validating condition key {condition_key} for {action}: {e}")
            return False, f"Failed to validate condition key: {str(e)}"

    async def clear_caches(self) -> None:
        """Clear all caches (memory and disk)."""
        # Clear memory cache
        await self._memory_cache.clear()

        # Clear disk cache
        if self.enable_cache and self._cache_dir.exists():
            for cache_file in self._cache_dir.glob("*.json"):
                try:
                    cache_file.unlink()
                except Exception as e:
                    logger.warning(f"Failed to delete cache file {cache_file}: {e}")

        logger.info("Cleared all caches")

    def get_stats(self) -> dict[str, Any]:
        """Get fetcher statistics for monitoring."""
        return {
            "prefetched_services": len(self._prefetched_services),
            "memory_cache_size": len(self._memory_cache.cache),
            "batch_queue_size": len(self._batch_queue),
            "cache_ttl": self.cache_ttl,
            "connection_pool_size": self.connection_pool_size,
        }
