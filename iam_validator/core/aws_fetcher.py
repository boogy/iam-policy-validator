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
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from iam_validator.core import constants
from iam_validator.core.config import AWS_SERVICE_REFERENCE_BASE_URL
from iam_validator.core.models import ServiceDetail, ServiceInfo
from iam_validator.utils.cache import LRUCache

logger = logging.getLogger(__name__)


@dataclass
class ConditionKeyValidationResult:
    """Result of condition key validation.

    Attributes:
        is_valid: True if the condition key is valid for the action
        error_message: Short error message if invalid (shown prominently)
        warning_message: Warning message if valid but not recommended
        suggestion: Detailed suggestion with valid keys (shown in collapsible section)
    """

    is_valid: bool
    error_message: str | None = None
    warning_message: str | None = None
    suggestion: str | None = None


class CompiledPatterns:
    """Pre-compiled regex patterns for validation.

    This class implements the Singleton pattern to ensure patterns are compiled only once
    and reused across all instances for better performance.
    """

    _instance = None
    _initialized = False

    def __new__(cls) -> "CompiledPatterns":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialize compiled patterns (only once due to Singleton pattern)."""
        # Only initialize once, even if __init__ is called multiple times
        if CompiledPatterns._initialized:
            return

        CompiledPatterns._initialized = True

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
    """Fetches AWS service information from the AWS service reference API with enhanced performance features.

    This class provides a comprehensive interface for retrieving AWS service metadata,
    including actions, resources, and condition keys. It includes multiple layers of
    caching and optimization for high-performance policy validation.

    Features:
    - Multi-layer caching (memory LRU + disk with TTL)
    - Service pre-fetching for common AWS services
    - Request batching and coalescing
    - Offline mode support with local AWS service files
    - HTTP/2 connection pooling
    - Automatic retry with exponential backoff

    Example:
        >>> async with AWSServiceFetcher() as fetcher:
        ...     # Fetch service list
        ...     services = await fetcher.fetch_services()
        ...
        ...     # Fetch specific service details
        ...     s3_service = await fetcher.fetch_service_by_name("s3")
        ...
        ...     # Validate actions
        ...     is_valid = await fetcher.validate_action("s3:GetObject", s3_service)

    Method Organization:
        Lifecycle Management:
            - __init__: Initialize fetcher with configuration
            - __aenter__, __aexit__: Context manager support

        Caching (Private):
            - _get_cache_directory: Determine cache location
            - _get_cache_path: Generate cache file path
            - _read_from_cache: Read from disk cache
            - _write_to_cache: Write to disk cache
            - clear_caches: Clear all caches

        HTTP Operations (Private):
            - _make_request: Core HTTP request handler
            - _make_request_with_batching: Request coalescing
            - _prefetch_common_services: Pre-load common services

        File I/O (Private):
            - _load_services_from_file: Load service list from local file
            - _load_service_from_file: Load service details from local file

        Public API - Fetching:
            - fetch_services: Get list of all AWS services
            - fetch_service_by_name: Get details for one service
            - fetch_multiple_services: Batch fetch multiple services

        Public API - Validation:
            - validate_action: Check if action exists in service
            - validate_arn: Validate ARN format
            - validate_condition_key: Check condition key validity

        Public API - Parsing:
            - parse_action: Split action into service and name
            - _match_wildcard_action: Match wildcard patterns

        Utilities:
            - get_stats: Get cache statistics
    """

    BASE_URL = AWS_SERVICE_REFERENCE_BASE_URL

    # Common AWS services to pre-fetch
    # All other services will be fetched on-demand (lazy loading if found in policies)
    COMMON_SERVICES = [
        "acm",
        "apigateway",
        "autoscaling",
        "backup",
        "batch",
        "bedrock",
        "cloudformation",
        "cloudfront",
        "cloudtrail",
        "cloudwatch",
        "config",
        "dynamodb",
        "ec2-instance-connect",
        "ec2",
        "ecr",
        "ecs",
        "eks",
        "elasticache",
        "elasticloadbalancing",
        "events",
        "firehose",
        "glacier",
        "glue",
        "guardduty",
        "iam",
        "imagebuilder",
        "inspector2",
        "kinesis",
        "kms",
        "lambda",
        "logs",
        "rds",
        "route53",
        "s3",
        "scheduler",
        "secretsmanager",
        "securityhub",
        "sns",
        "sqs",
        "sts",
        "support",
        "waf",
        "wafv2",
    ]

    def __init__(
        self,
        timeout: float = constants.DEFAULT_HTTP_TIMEOUT_SECONDS,
        retries: int = 3,
        enable_cache: bool = True,
        cache_ttl: int = constants.DEFAULT_CACHE_TTL_SECONDS,
        memory_cache_size: int = 256,
        connection_pool_size: int = 50,
        keepalive_connections: int = 20,
        prefetch_common: bool = True,
        cache_dir: Path | str | None = None,
        aws_services_dir: Path | str | None = None,
    ):
        """Initialize aws service fetcher.

        Args:
            timeout: Request timeout in seconds
            retries: Number of retries for failed requests
            enable_cache: Enable persistent disk caching
            cache_ttl: Cache time-to-live in seconds
            memory_cache_size: Size of in-memory LRU cache
            connection_pool_size: HTTP connection pool size
            keepalive_connections: Number of keepalive connections
            prefetch_common: Prefetch common AWS services
            cache_dir: Custom cache directory path
            aws_services_dir: Directory containing pre-downloaded AWS service JSON files.
                            When set, the fetcher will load services from local files
                            instead of making API calls. Directory should contain:
                            - _services.json: List of all services
                            - {service}.json: Individual service files (e.g., s3.json)
        """
        self.timeout = timeout
        self.retries = retries
        self.enable_cache = enable_cache
        self.cache_ttl = cache_ttl
        self.prefetch_common = prefetch_common

        # AWS services directory for offline mode
        self.aws_services_dir: Path | None = None
        if aws_services_dir:
            self.aws_services_dir = Path(aws_services_dir)
            if not self.aws_services_dir.exists():
                raise ValueError(f"AWS services directory does not exist: {aws_services_dir}")
            logger.info(f"Using local AWS services from: {self.aws_services_dir}")

        self._client: httpx.AsyncClient | None = None
        self._memory_cache = LRUCache(maxsize=memory_cache_size, ttl=cache_ttl)
        self._cache_dir = self._get_cache_directory(cache_dir)
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

    @staticmethod
    def _get_cache_directory(cache_dir: Path | str | None = None) -> Path:
        """Get the cache directory path, using platform-appropriate defaults.

        Priority:
        1. Provided cache_dir parameter
        2. Platform-specific user cache directory
           - Linux/Unix: ~/.cache/iam-validator/aws_services
           - macOS: ~/Library/Caches/iam-validator/aws_services
           - Windows: %LOCALAPPDATA%/iam-validator/cache/aws_services

        Args:
            cache_dir: Optional custom cache directory path

        Returns:
            Path object for the cache directory
        """
        if cache_dir is not None:
            return Path(cache_dir)

        # Determine platform-specific cache directory
        if sys.platform == "darwin":
            # macOS
            base_cache = Path.home() / "Library" / "Caches"
        elif sys.platform == "win32":
            # Windows
            base_cache = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        else:
            # Linux and other Unix-like systems
            base_cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))

        return base_cache / "iam-validator" / "aws_services"

    async def __aenter__(self) -> "AWSServiceFetcher":
        """Async context manager entry with optimized settings."""
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=True,
            limits=httpx.Limits(
                max_keepalive_connections=self.keepalive_connections,
                max_connections=self.connection_pool_size,
                keepalive_expiry=constants.DEFAULT_HTTP_TIMEOUT_SECONDS,  # Keep connections alive
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

    def _load_services_from_file(self) -> list[ServiceInfo]:
        """Load services list from local _services.json file.

        Returns:
            List of ServiceInfo objects loaded from _services.json

        Raises:
            FileNotFoundError: If _services.json doesn't exist
            ValueError: If _services.json is invalid
        """
        if not self.aws_services_dir:
            raise ValueError("aws_services_dir is not set")

        services_file = self.aws_services_dir / "_services.json"
        if not services_file.exists():
            raise FileNotFoundError(f"_services.json not found in {self.aws_services_dir}")

        try:
            with open(services_file) as f:
                data = json.load(f)

            if not isinstance(data, list):
                raise ValueError("Expected list of services from _services.json")

            services: list[ServiceInfo] = []
            for item in data:
                if isinstance(item, dict):
                    service = item.get("service")
                    url = item.get("url")
                    if service and url:
                        services.append(ServiceInfo(service=str(service), url=str(url)))

            logger.info(f"Loaded {len(services)} services from local file: {services_file}")
            return services

        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in services.json: {e}")

    def _load_service_from_file(self, service_name: str) -> ServiceDetail:
        """Load service detail from local JSON file.

        Args:
            service_name: Name of the service (case-insensitive)

        Returns:
            ServiceDetail object loaded from {service}.json

        Raises:
            FileNotFoundError: If service JSON file doesn't exist
            ValueError: If service JSON is invalid
        """
        if not self.aws_services_dir:
            raise ValueError("aws_services_dir is not set")

        # Normalize filename (lowercase, replace spaces with underscores)
        filename = f"{service_name.lower().replace(' ', '_')}.json"
        service_file = self.aws_services_dir / filename

        if not service_file.exists():
            raise FileNotFoundError(f"Service file not found: {service_file}")

        try:
            with open(service_file) as f:
                data = json.load(f)

            service_detail = ServiceDetail.model_validate(data)
            logger.debug(f"Loaded service {service_name} from local file: {service_file}")
            return service_detail

        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in {service_file}: {e}")

    async def fetch_services(self) -> list[ServiceInfo]:
        """Fetch list of AWS services with caching.

        When aws_services_dir is set, loads from local services.json file.
        Otherwise, fetches from AWS API.
        """
        # Check if we have the parsed services list in cache
        services_cache_key = "parsed_services_list"
        cached_services = await self._memory_cache.get(services_cache_key)
        if cached_services is not None and isinstance(cached_services, list):
            logger.debug(f"Retrieved {len(cached_services)} services from parsed cache")
            return cached_services

        # Load from local file if aws_services_dir is set
        if self.aws_services_dir:
            services = self._load_services_from_file()
            # Cache the loaded services
            await self._memory_cache.set(services_cache_key, services)
            return services

        # Not in parsed cache, fetch the raw data from API
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
        """Fetch service detail with optimized caching.

        When aws_services_dir is set, loads from local {service}.json file.
        Otherwise, fetches from AWS API.
        """
        # Normalize service name
        service_name_lower = service_name.lower()

        # Check memory cache with service name as key
        cache_key = f"service:{service_name_lower}"
        cached_detail = await self._memory_cache.get(cache_key)
        if isinstance(cached_detail, ServiceDetail):
            logger.debug(f"Memory cache hit for service {service_name}")
            return cached_detail

        # Load from local file if aws_services_dir is set
        if self.aws_services_dir:
            try:
                service_detail = self._load_service_from_file(service_name_lower)
                # Cache the loaded service
                await self._memory_cache.set(cache_key, service_detail)
                return service_detail
            except FileNotFoundError:
                # Try to find the service in services.json to get proper name
                services = await self.fetch_services()
                for service in services:
                    if service.service.lower() == service_name_lower:
                        # Try with the exact service name from services.json
                        try:
                            service_detail = self._load_service_from_file(service.service)
                            await self._memory_cache.set(cache_key, service_detail)
                            return service_detail
                        except FileNotFoundError:
                            pass
                raise ValueError(f"Service `{service_name}` not found in {self.aws_services_dir}")

        # Fetch service list and find URL from API
        services = await self.fetch_services()

        for service in services:
            if service.service.lower() == service_name_lower:
                # Fetch service detail from API
                data = await self._make_request_with_batching(service.url)

                # Validate and parse
                service_detail = ServiceDetail.model_validate(data)

                # Cache with service name as key
                await self._memory_cache.set(cache_key, service_detail)

                return service_detail

        raise ValueError(f"Service `{service_name}` not found")

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
        self, action: str, condition_key: str, resources: list[str] | None = None
    ) -> ConditionKeyValidationResult:
        """
        Validate condition key against action and optionally resource types.

        Args:
            action: IAM action (e.g., "s3:GetObject")
            condition_key: Condition key to validate (e.g., "s3:prefix")
            resources: Optional list of resource ARNs to validate against

        Returns:
            ConditionKeyValidationResult with:
            - is_valid: True if key is valid (even with warning)
            - error_message: Short error message if invalid (shown prominently)
            - warning_message: Warning message if valid but not recommended
            - suggestion: Detailed suggestion with valid keys (shown in collapsible section)
        """
        try:
            from iam_validator.core.config.aws_global_conditions import (
                get_global_conditions,
            )

            service_prefix, action_name = self.parse_action(action)

            # Check if it's a global condition key
            is_global_key = False
            if condition_key.startswith("aws:"):
                global_conditions = get_global_conditions()
                if global_conditions.is_valid_global_key(condition_key):
                    is_global_key = True
                else:
                    return ConditionKeyValidationResult(
                        is_valid=False,
                        error_message=f"Invalid AWS global condition key: `{condition_key}`.",
                    )

            # Fetch service detail (cached)
            service_detail = await self.fetch_service_by_name(service_prefix)

            # Check service-specific condition keys
            if condition_key in service_detail.condition_keys:
                return ConditionKeyValidationResult(is_valid=True)

            # Check action-specific condition keys
            if action_name in service_detail.actions:
                action_detail = service_detail.actions[action_name]
                if (
                    action_detail.action_condition_keys
                    and condition_key in action_detail.action_condition_keys
                ):
                    return ConditionKeyValidationResult(is_valid=True)

                # Check resource-specific condition keys
                # Get resource types required by this action
                if resources and action_detail.resources:
                    for res_req in action_detail.resources:
                        resource_name = res_req.get("Name", "")
                        if not resource_name:
                            continue

                        # Look up resource type definition
                        resource_type = service_detail.resources.get(resource_name)
                        if resource_type and resource_type.condition_keys:
                            if condition_key in resource_type.condition_keys:
                                return ConditionKeyValidationResult(is_valid=True)

                # If it's a global key but the action has specific condition keys defined,
                # AWS allows it but the key may not be available in every request context
                if is_global_key and action_detail.action_condition_keys is not None:
                    warning_msg = (
                        f"Global condition key '{condition_key}' is used with action '{action}'. "
                        f"While global condition keys can be used across all AWS services, "
                        f"the key may not be available in every request context. "
                        f"Verify that '{condition_key}' is available for this specific action's request context. "
                        f"Consider using '*IfExists' operators (e.g., StringEqualsIfExists) if the key might be missing."
                    )
                    return ConditionKeyValidationResult(is_valid=True, warning_message=warning_msg)

            # If it's a global key and action doesn't define specific keys, allow it
            if is_global_key:
                return ConditionKeyValidationResult(is_valid=True)

            # Short error message
            error_msg = f"Condition key `{condition_key}` is not valid for action `{action}`"

            # Collect valid condition keys for this action
            valid_keys = set()

            # Add service-level condition keys
            if service_detail.condition_keys:
                if isinstance(service_detail.condition_keys, dict):
                    valid_keys.update(service_detail.condition_keys.keys())
                elif isinstance(service_detail.condition_keys, list):
                    valid_keys.update(service_detail.condition_keys)

            # Add action-specific condition keys
            if action_name in service_detail.actions:
                action_detail = service_detail.actions[action_name]
                if action_detail.action_condition_keys:
                    if isinstance(action_detail.action_condition_keys, dict):
                        valid_keys.update(action_detail.action_condition_keys.keys())
                    elif isinstance(action_detail.action_condition_keys, list):
                        valid_keys.update(action_detail.action_condition_keys)

                # Add resource-specific condition keys
                if action_detail.resources:
                    for res_req in action_detail.resources:
                        resource_name = res_req.get("Name", "")
                        if resource_name:
                            resource_type = service_detail.resources.get(resource_name)
                            if resource_type and resource_type.condition_keys:
                                if isinstance(resource_type.condition_keys, dict):
                                    valid_keys.update(resource_type.condition_keys.keys())
                                elif isinstance(resource_type.condition_keys, list):
                                    valid_keys.update(resource_type.condition_keys)

            # Build detailed suggestion with valid keys (goes in collapsible section)
            suggestion_parts = []

            if valid_keys:
                # Sort and limit to first 10 keys for readability
                sorted_keys = sorted(valid_keys)
                suggestion_parts.append("**Valid condition keys for this action:**")
                if len(sorted_keys) <= 10:
                    for key in sorted_keys:
                        suggestion_parts.append(f"- `{key}`")
                else:
                    for key in sorted_keys[:10]:
                        suggestion_parts.append(f"- `{key}`")
                    suggestion_parts.append(f"- ... and {len(sorted_keys) - 10} more")

                suggestion_parts.append("")
                suggestion_parts.append(
                    "**Global condition keys** (e.g., `aws:ResourceOrgID`, `aws:RequestedRegion`, `aws:SourceIp`, `aws:SourceVpce`) "
                    "can also be used with any AWS action"
                )
            else:
                # No action-specific keys - mention global keys
                suggestion_parts.append(
                    "This action does not have specific condition keys defined.\n\n"
                    "However, you can use **global condition keys** such as:\n"
                    "- `aws:RequestedRegion`\n"
                    "- `aws:SourceIp`\n"
                    "- `aws:SourceVpce`\n"
                    "- `aws:UserAgent`\n"
                    "- `aws:CurrentTime`\n"
                    "- `aws:SecureTransport`\n"
                    "- `aws:PrincipalArn`\n"
                    "- And many others"
                )

            suggestion = "\n".join(suggestion_parts)

            return ConditionKeyValidationResult(
                is_valid=False,
                error_message=error_msg,
                suggestion=suggestion,
            )

        except Exception as e:
            logger.error(f"Error validating condition key {condition_key} for {action}: {e}")
            return ConditionKeyValidationResult(
                is_valid=False,
                error_message=f"Failed to validate condition key: {str(e)}",
            )

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
