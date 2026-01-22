"""AWS Service Fetcher - Main orchestrator for AWS service data retrieval.

This module provides the main AWSServiceFetcher class that coordinates between
HTTP client, caching, storage, parsing, and validation components.
"""

import asyncio
import logging
from pathlib import Path
from typing import Any

from iam_validator.core import constants
from iam_validator.core.aws_service.cache import ServiceCacheManager
from iam_validator.core.aws_service.client import AWSServiceClient
from iam_validator.core.aws_service.parsers import ServiceParser
from iam_validator.core.aws_service.storage import ServiceFileStorage
from iam_validator.core.aws_service.validators import (
    ConditionKeyValidationResult,
    ServiceValidator,
)
from iam_validator.core.config import AWS_SERVICE_REFERENCE_BASE_URL
from iam_validator.core.models import ServiceDetail, ServiceInfo

logger = logging.getLogger(__name__)


class AWSServiceFetcher:
    """Fetches and validates AWS service information with caching.

    This is the main entry point for AWS service data operations.
    Coordinates between HTTP client, caching, storage, and validation.

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
        ...     is_valid, error, is_wildcard = await fetcher.validate_action("s3:GetObject")
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

    # Default concurrency limits
    DEFAULT_MAX_CONCURRENT_REQUESTS = 10

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
        max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS,
    ):
        """Initialize AWS service fetcher.

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
            max_concurrent_requests: Maximum number of concurrent HTTP requests (default: 10)
        """
        self.prefetch_common = prefetch_common
        self.aws_services_dir = Path(aws_services_dir) if aws_services_dir else None
        self._prefetched_services: set[str] = set()
        # Semaphore for limiting concurrent requests
        self._request_semaphore = asyncio.Semaphore(max_concurrent_requests)

        # Initialize storage component
        self._storage = ServiceFileStorage(
            cache_dir=cache_dir,
            aws_services_dir=aws_services_dir,
            cache_ttl=cache_ttl,
            enable_cache=enable_cache,
        )

        # Initialize cache manager
        self._cache = ServiceCacheManager(
            memory_cache_size=memory_cache_size,
            cache_ttl=cache_ttl,
            storage=self._storage if enable_cache else None,
        )

        # Initialize HTTP client
        self._client = AWSServiceClient(
            base_url=self.BASE_URL,
            timeout=timeout,
            retries=retries,
            connection_pool_size=connection_pool_size,
            keepalive_connections=keepalive_connections,
        )

        # Initialize parser and validator
        self._parser = ServiceParser()
        self._validator = ServiceValidator(parser=self._parser)

    async def __aenter__(self) -> "AWSServiceFetcher":
        """Async context manager entry."""
        await self._client.__aenter__()

        # Pre-fetch common services if enabled
        if self.prefetch_common:
            await self._prefetch_common_services()

        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Async context manager exit."""
        await self._client.__aexit__(exc_type, exc_val, exc_tb)

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
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.warning(f"Failed to prefetch service {name}: {e}")

        # Fetch in batches to avoid overwhelming the API
        batch_size = 5
        for i in range(0, len(self.COMMON_SERVICES), batch_size):
            batch = self.COMMON_SERVICES[i : i + batch_size]
            await asyncio.gather(*[fetch_service(name) for name in batch])

        logger.info(f"Pre-fetched {len(self._prefetched_services)} services successfully")

    async def fetch_services(self) -> list[ServiceInfo]:
        """Fetch list of AWS services with caching.

        When aws_services_dir is set, loads from local _services.json file.
        Otherwise, fetches from AWS API.

        Returns:
            List of ServiceInfo objects

        Example:
            >>> async with AWSServiceFetcher() as fetcher:
            ...     services = await fetcher.fetch_services()
            ...     print(f"Found {len(services)} AWS services")
        """
        # Check if we have the parsed services list in cache
        services_cache_key = "parsed_services_list"
        cached_services = await self._cache.get(services_cache_key)
        if cached_services is not None and isinstance(cached_services, list):
            logger.debug(f"Retrieved {len(cached_services)} services from parsed cache")
            return cached_services

        # Load from local file if aws_services_dir is set
        if self.aws_services_dir:
            loaded_services = self._storage.load_services_from_file()
            # Cache the loaded services
            await self._cache.set(services_cache_key, loaded_services)
            return loaded_services

        # Not in parsed cache, check disk cache then fetch from API
        data = await self._cache.get(
            f"raw:{self.BASE_URL}", url=self.BASE_URL, base_url=self.BASE_URL
        )
        if data is None:
            try:
                data = await self._client.fetch(self.BASE_URL)
                # Cache the raw data (this refreshes the disk cache file)
                await self._cache.set(
                    f"raw:{self.BASE_URL}", data, url=self.BASE_URL, base_url=self.BASE_URL
                )
            except Exception as e:  # pylint: disable=broad-exception-caught
                # API fetch failed - try stale cache as fallback
                logger.warning(f"API fetch failed for services list: {e}")
                stale_data = await self._cache.get_stale(url=self.BASE_URL, base_url=self.BASE_URL)
                if stale_data is not None:
                    logger.info("Using stale cache data for services list due to API failure")
                    data = stale_data
                else:
                    raise

        if not isinstance(data, list):
            raise ValueError("Expected list of services from root endpoint")

        services: list[ServiceInfo] = []
        for item in data:
            if isinstance(item, dict):
                service = item.get("service")
                url = item.get("url")
                if service and url:
                    services.append(ServiceInfo(service=str(service), url=str(url)))

        # Cache the parsed services list (memory only)
        await self._cache.set(services_cache_key, services)

        # Log only on first fetch (when parsed cache was empty)
        logger.info(f"Fetched and parsed {len(services)} services from AWS API")
        return services

    async def fetch_service_by_name(self, service_name: str) -> ServiceDetail:
        """Fetch service detail with optimized caching.

        When aws_services_dir is set, loads from local {service}.json file.
        Otherwise, fetches from AWS API.

        Args:
            service_name: Name of the service (case-insensitive, e.g., "s3", "iam")

        Returns:
            ServiceDetail object with full service definition

        Raises:
            ValueError: If service is not found

        Example:
            >>> async with AWSServiceFetcher() as fetcher:
            ...     s3_service = await fetcher.fetch_service_by_name("s3")
            ...     print(f"S3 has {len(s3_service.actions)} actions")
        """
        # Normalize service name
        service_name_lower = service_name.lower()

        # Check memory cache with service name as key
        cache_key = f"service:{service_name_lower}"
        cached_detail = await self._cache.get(cache_key)
        if isinstance(cached_detail, ServiceDetail):
            logger.debug(f"Memory cache hit for service {service_name}")
            return cached_detail

        # Load from local file if aws_services_dir is set
        if self.aws_services_dir:
            try:
                service_detail = self._storage.load_service_from_file(service_name_lower)
                # Cache the loaded service
                await self._cache.set(cache_key, service_detail)
                return service_detail
            except FileNotFoundError:
                # Try to find the service in services.json to get proper name
                services = await self.fetch_services()
                for service in services:
                    if service.service.lower() == service_name_lower:
                        # Try with the exact service name from services.json
                        try:
                            service_detail = self._storage.load_service_from_file(service.service)
                            await self._cache.set(cache_key, service_detail)
                            return service_detail
                        except FileNotFoundError:
                            pass
                raise ValueError(
                    f"Service `{service_name}` not found in {self.aws_services_dir}"
                ) from FileNotFoundError

        # Fetch service list and find URL from API
        services = await self.fetch_services()

        for service in services:
            if service.service.lower() == service_name_lower:
                # Check disk cache first, then fetch from API
                data = await self._cache.get(
                    f"raw:{service.url}", url=service.url, base_url=self.BASE_URL
                )
                if data is None:
                    try:
                        # Fetch service detail from API
                        data = await self._client.fetch(service.url)
                        # Cache the raw data (this refreshes the disk cache file)
                        await self._cache.set(
                            f"raw:{service.url}", data, url=service.url, base_url=self.BASE_URL
                        )
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        # API fetch failed - try stale cache as fallback
                        logger.warning(f"API fetch failed for {service_name}: {e}")
                        stale_data = await self._cache.get_stale(
                            url=service.url, base_url=self.BASE_URL
                        )
                        if stale_data is not None:
                            logger.info(
                                f"Using stale cache data for {service_name} due to API failure"
                            )
                            data = stale_data
                        else:
                            raise

                # Validate and parse
                service_detail = ServiceDetail.model_validate(data)

                # Cache with service name as key (memory only)
                await self._cache.set(cache_key, service_detail)

                return service_detail

        raise ValueError(f"Service `{service_name}` not found")

    async def fetch_multiple_services(self, service_names: list[str]) -> dict[str, ServiceDetail]:
        """Fetch multiple services concurrently with controlled parallelism.

        Uses a semaphore to limit concurrent requests and prevent overwhelming
        the AWS service reference API.

        Args:
            service_names: List of service names to fetch

        Returns:
            Dictionary mapping service names to ServiceDetail objects

        Raises:
            Exception: If any service fetch fails

        Example:
            >>> async with AWSServiceFetcher() as fetcher:
            ...     services = await fetcher.fetch_multiple_services(["s3", "iam", "ec2"])
            ...     print(f"Fetched {len(services)} services")
        """

        async def fetch_single(name: str) -> tuple[str, ServiceDetail]:
            # Use semaphore to limit concurrent requests
            async with self._request_semaphore:
                try:
                    detail = await self.fetch_service_by_name(name)
                    return name, detail
                except Exception as e:  # pylint: disable=broad-exception-caught
                    logger.error(f"Failed to fetch service {name}: {e}")
                    raise

        # Fetch all services concurrently (semaphore controls parallelism)
        tasks = [fetch_single(name) for name in service_names]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        services: dict[str, ServiceDetail] = {}
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Failed to fetch service {service_names[i]}: {result}")
                raise result
            if isinstance(result, tuple):
                name, detail = result
                services[name] = detail

        return services

    # --- Validation Methods (delegate to validator) ---

    async def validate_action(
        self,
        action: str,
        allow_wildcards: bool = True,
    ) -> tuple[bool, str | None, bool]:
        """Validate IAM action.

        Args:
            action: Full action string (e.g., "s3:GetObject", "iam:CreateUser")
            allow_wildcards: Whether to allow wildcard actions

        Returns:
            Tuple of (is_valid, error_message, is_wildcard)

        Example:
            >>> async with AWSServiceFetcher() as fetcher:
            ...     is_valid, error, is_wildcard = await fetcher.validate_action("s3:GetObject")
            ...     if not is_valid:
            ...         print(f"Invalid action: {error}")
        """
        service_prefix, _ = self._parser.parse_action(action)
        service_detail = await self.fetch_service_by_name(service_prefix)
        return await self._validator.validate_action(action, service_detail, allow_wildcards)

    async def validate_actions_batch(
        self,
        actions: list[str],
        allow_wildcards: bool = True,
    ) -> dict[str, tuple[bool, str | None, bool]]:
        """Validate multiple IAM actions efficiently in batch.

        Groups actions by service prefix and fetches each service definition once,
        reducing network overhead when validating multiple actions.

        Args:
            actions: List of full action strings (e.g., ["s3:GetObject", "iam:CreateUser"])
            allow_wildcards: Whether to allow wildcard actions

        Returns:
            Dictionary mapping action -> (is_valid, error_message, is_wildcard)

        Example:
            >>> async with AWSServiceFetcher() as fetcher:
            ...     results = await fetcher.validate_actions_batch([
            ...         "s3:GetObject",
            ...         "s3:PutObject",
            ...         "iam:CreateUser"
            ...     ])
            ...     for action, (is_valid, error, is_wildcard) in results.items():
            ...         if not is_valid:
            ...             print(f"Invalid: {action} - {error}")
        """
        if not actions:
            return {}

        # Group actions by service prefix
        service_actions: dict[str, list[str]] = {}
        for action in actions:
            service_prefix, _ = self._parser.parse_action(action)
            if service_prefix not in service_actions:
                service_actions[service_prefix] = []
            service_actions[service_prefix].append(action)

        # Fetch all service definitions in parallel
        service_details: dict[str, ServiceDetail] = {}
        fetch_tasks = [self.fetch_service_by_name(service) for service in service_actions.keys()]
        fetched = await asyncio.gather(*fetch_tasks, return_exceptions=True)

        for service, result in zip(service_actions.keys(), fetched):
            if isinstance(result, BaseException):
                # Store None to indicate fetch failure
                service_details[service] = None  # type: ignore
            else:
                service_details[service] = result

        # Validate all actions using cached service details
        results: dict[str, tuple[bool, str | None, bool]] = {}
        for action in actions:
            service_prefix, _ = self._parser.parse_action(action)
            service_detail = service_details.get(service_prefix)

            if service_detail is None:
                # Service fetch failed
                results[action] = (False, f"Failed to fetch service '{service_prefix}'", False)
            else:
                results[action] = await self._validator.validate_action(
                    action, service_detail, allow_wildcards
                )

        return results

    def validate_arn(self, arn: str) -> tuple[bool, str | None]:
        """Validate ARN format.

        Args:
            arn: ARN string to validate

        Returns:
            Tuple of (is_valid, error_message)

        Example:
            >>> fetcher = AWSServiceFetcher()
            >>> is_valid, error = fetcher.validate_arn("arn:aws:s3:::my-bucket/*")
            >>> if not is_valid:
            ...     print(f"Invalid ARN: {error}")
        """
        return self._parser.validate_arn_format(arn)

    async def validate_condition_key(
        self,
        action: str,
        condition_key: str,
        resources: list[str] | None = None,
    ) -> ConditionKeyValidationResult:
        """Validate condition key.

        Args:
            action: IAM action (e.g., "s3:GetObject")
            condition_key: Condition key to validate (e.g., "s3:prefix")
            resources: Optional list of resource ARNs

        Returns:
            ConditionKeyValidationResult with validation details

        Example:
            >>> async with AWSServiceFetcher() as fetcher:
            ...     result = await fetcher.validate_condition_key("s3:GetObject", "s3:prefix")
            ...     if not result.is_valid:
            ...         print(f"Invalid condition key: {result.error_message}")
        """
        service_prefix, _ = self._parser.parse_action(action)
        service_detail = await self.fetch_service_by_name(service_prefix)
        return await self._validator.validate_condition_key(
            action, condition_key, service_detail, resources
        )

    async def is_condition_key_supported(
        self,
        action: str,
        condition_key: str,
    ) -> bool:
        """Check if a condition key is supported for a specific action.

        This checks two locations for the condition key:
        1. Action-level condition keys (ActionConditionKeys)
        2. Resource-level condition keys (for each resource the action operates on)

        Returns True if the condition key is found in either location.

        This is useful for determining if a condition provides meaningful
        restrictions for an action, particularly for resource-scoping conditions
        like aws:ResourceTag/*.

        Args:
            action: IAM action (e.g., "s3:GetObject", "ssm:StartSession")
            condition_key: Condition key to check (e.g., "aws:ResourceTag/Env")

        Returns:
            True if the condition key is supported for this action

        Example:
            >>> async with AWSServiceFetcher() as fetcher:
            ...     # SSM StartSession has aws:ResourceTag in ActionConditionKeys
            ...     supported = await fetcher.is_condition_key_supported(
            ...         "ssm:StartSession", "aws:ResourceTag/Component"
            ...     )
            ...     print(f"Tag support: {supported}")  # True
        """
        from iam_validator.core.aws_service.validators import (  # pylint: disable=import-outside-toplevel
            condition_key_in_list,
        )

        try:
            service_prefix, action_name = self._parser.parse_action(action)
        except ValueError:
            return False  # Invalid action format

        # Can't verify wildcard actions
        if "*" in action_name or "?" in action_name:
            return False

        service_detail = await self.fetch_service_by_name(service_prefix)
        if not service_detail:
            return False

        # Case-insensitive action lookup
        action_detail = None
        action_name_lower = action_name.lower()
        for name, detail in service_detail.actions.items():
            if name.lower() == action_name_lower:
                action_detail = detail
                break

        if not action_detail:
            return False

        # Check 1: Action-level condition keys
        if action_detail.action_condition_keys:
            if condition_key_in_list(condition_key, action_detail.action_condition_keys):
                return True

        # Check 2: Resource-level condition keys
        if action_detail.resources:
            for res_ref in action_detail.resources:
                resource_name = res_ref.get("Name")
                if not resource_name:
                    continue
                resource_type = service_detail.resources.get(resource_name)
                if resource_type and resource_type.condition_keys:
                    if condition_key_in_list(condition_key, resource_type.condition_keys):
                        return True

        return False

    # --- Parsing Methods (delegate to parser) ---

    def parse_action(self, action: str) -> tuple[str, str]:
        """Parse action into service and action name.

        Args:
            action: Full action string (e.g., "s3:GetObject")

        Returns:
            Tuple of (service_prefix, action_name)

        Example:
            >>> fetcher = AWSServiceFetcher()
            >>> service, action_name = fetcher.parse_action("s3:GetObject")
            >>> print(f"Service: {service}, Action: {action_name}")
        """
        return self._parser.parse_action(action)

    def match_wildcard_action(
        self,
        pattern: str,
        actions: list[str],
    ) -> tuple[bool, list[str]]:
        """Match wildcard pattern against actions.

        Args:
            pattern: Action pattern with wildcards (e.g., "Get*", "*Object")
            actions: List of action names to match against

        Returns:
            Tuple of (has_matches, list_of_matched_actions)

        Example:
            >>> fetcher = AWSServiceFetcher()
            >>> actions = ["GetObject", "PutObject", "DeleteObject"]
            >>> has_matches, matched = fetcher.match_wildcard_action("Get*", actions)
            >>> print(f"Matched: {matched}")
        """
        return self._parser.match_wildcard_action(pattern, actions)

    # --- Helper Methods ---

    async def get_resources_for_action(self, action: str) -> list[dict[str, Any]]:
        """Get resource types for action.

        Args:
            action: Full action name (e.g., "s3:GetObject")

        Returns:
            List of resource dictionaries from AWS API

        Example:
            >>> async with AWSServiceFetcher() as fetcher:
            ...     resources = await fetcher.get_resources_for_action("s3:GetObject")
            ...     print(f"Action operates on {len(resources)} resource types")
        """
        service_prefix, _ = self._parser.parse_action(action)
        service_detail = await self.fetch_service_by_name(service_prefix)
        return self._validator.get_resources_for_action(action, service_detail)

    async def get_arn_formats_for_action(self, action: str) -> list[str]:
        """Get ARN formats for action.

        Args:
            action: Full action name (e.g., "s3:GetObject")

        Returns:
            List of ARN format strings

        Example:
            >>> async with AWSServiceFetcher() as fetcher:
            ...     arns = await fetcher.get_arn_formats_for_action("s3:GetObject")
            ...     for arn in arns:
            ...         print(f"ARN format: {arn}")
        """
        service_prefix, _ = self._parser.parse_action(action)
        service_detail = await self.fetch_service_by_name(service_prefix)
        return self._validator.get_arn_formats_for_action(action, service_detail)

    async def get_all_actions_for_service(self, service: str) -> list[str]:
        """Get all actions for service.

        Args:
            service: Service prefix (e.g., "s3", "iam", "ec2")

        Returns:
            Sorted list of action names (without service prefix)

        Example:
            >>> async with AWSServiceFetcher() as fetcher:
            ...     actions = await fetcher.get_all_actions_for_service("s3")
            ...     print(f"S3 has {len(actions)} actions")
        """
        service_detail = await self.fetch_service_by_name(service)
        return sorted(service_detail.actions.keys())

    async def expand_wildcard_action(self, action_pattern: str) -> list[str]:
        """Expand wildcard action to full list.

        Args:
            action_pattern: Action with wildcards (e.g., "iam:Create*", "s3:*Object")

        Returns:
            Sorted list of fully-qualified actions matching the pattern

        Example:
            >>> async with AWSServiceFetcher() as fetcher:
            ...     actions = await fetcher.expand_wildcard_action("iam:Create*")
            ...     print(f"Pattern matches {len(actions)} actions")
        """
        if action_pattern in ("*", "*:*"):
            return ["*"]

        service_prefix, _ = self._parser.parse_action(action_pattern)
        service_detail = await self.fetch_service_by_name(service_prefix)
        available = list(service_detail.actions.keys())
        return self._parser.expand_wildcard_to_actions(action_pattern, available, service_prefix)

    # --- Cache Management ---

    async def clear_caches(self) -> None:
        """Clear all caches (memory and disk).

        Example:
            >>> async with AWSServiceFetcher() as fetcher:
            ...     await fetcher.clear_caches()
        """
        await self._cache.clear()

    def set_cache_directory(self, cache_dir: Path | str) -> None:
        """Set a new cache directory path dynamically.

        This method allows library users to change the cache location at runtime.
        Useful for applications that need to control where cache files are stored.

        Args:
            cache_dir: New cache directory path

        Example:
            >>> async with AWSServiceFetcher() as fetcher:
            ...     fetcher.set_cache_directory("/tmp/my-custom-cache")
            ...     # Future cache operations will use the new directory
        """
        self._storage.set_cache_directory(cache_dir)

    def get_cache_directory(self) -> Path:
        """Get the current cache directory path.

        Returns:
            Current cache directory as Path object

        Example:
            >>> async with AWSServiceFetcher() as fetcher:
            ...     cache_path = fetcher.get_cache_directory()
            ...     print(f"Cache location: {cache_path}")
        """
        return self._storage.cache_directory

    def get_stats(self) -> dict[str, Any]:
        """Get fetcher statistics for monitoring.

        Returns:
            Dictionary with cache and prefetch statistics

        Example:
            >>> async with AWSServiceFetcher() as fetcher:
            ...     stats = fetcher.get_stats()
            ...     print(f"Prefetched {stats['prefetched_services']} services")
        """
        return {
            "prefetched_services": len(self._prefetched_services),
            **self._cache.get_stats(),
        }
