"""File storage operations for AWS service data.

This module handles disk caching and offline file loading for AWS service definitions.
"""

import hashlib
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from iam_validator.core.models import ServiceDetail, ServiceInfo

logger = logging.getLogger(__name__)


class ServiceFileStorage:
    """Handles disk cache and offline AWS service file operations.

    This class manages:
    - Disk-based caching with TTL
    - Loading AWS service definitions from local files
    - Platform-specific cache directory management
    """

    def __init__(
        self,
        cache_dir: Path | str | None = None,
        aws_services_dir: Path | str | None = None,
        cache_ttl: int = 86400,
        enable_cache: bool = True,
    ) -> None:
        """Initialize storage with cache and offline directories.

        Args:
            cache_dir: Custom cache directory path (uses platform default if None)
            aws_services_dir: Directory containing pre-downloaded AWS service JSON files.
                When set, enables offline mode. Directory should contain:
                - _services.json: List of all services
                - {service}.json: Individual service files (e.g., s3.json)
            cache_ttl: Cache time-to-live in seconds
            enable_cache: Enable persistent disk caching
        """
        self.cache_ttl = cache_ttl
        self.enable_cache = enable_cache
        self._cache_dir = self.get_cache_directory(cache_dir)

        # AWS services directory for offline mode
        self.aws_services_dir: Path | None = None
        if aws_services_dir:
            self.aws_services_dir = Path(aws_services_dir)
            if not self.aws_services_dir.exists():
                raise ValueError(f"AWS services directory does not exist: {aws_services_dir}")
            logger.info(f"Using local AWS services from: {self.aws_services_dir}")

        # Create cache directory if needed
        if self.enable_cache:
            self._cache_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def get_cache_directory(cache_dir: Path | str | None = None) -> Path:
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

    def set_cache_directory(self, cache_dir: Path | str) -> None:
        """Set a new cache directory path dynamically.

        This method allows library users to change the cache location at runtime.
        The new directory will be created if it doesn't exist and caching is enabled.

        Args:
            cache_dir: New cache directory path

        Example:
            >>> storage = ServiceFileStorage()
            >>> storage.set_cache_directory("/tmp/my-custom-cache")
            >>> # Future cache operations will use the new directory
        """
        self._cache_dir = Path(cache_dir)

        # Create new cache directory if caching is enabled
        if self.enable_cache:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Cache directory updated to: {self._cache_dir}")

    @property
    def cache_directory(self) -> Path:
        """Get the current cache directory path.

        Returns:
            Current cache directory as Path object

        Example:
            >>> storage = ServiceFileStorage()
            >>> print(storage.cache_directory)
            PosixPath('/Users/username/Library/Caches/iam-validator/aws_services')
        """
        return self._cache_dir

    def _get_cache_path(self, url: str, base_url: str) -> Path:
        """Generate cache file path for URL.

        Args:
            url: URL to generate cache path for
            base_url: Base URL for service reference API

        Returns:
            Path to cache file
        """
        url_hash = hashlib.md5(url.encode()).hexdigest()

        # Extract service name for better organization
        filename = f"{url_hash}.json"
        if "/v1/" in url:
            service_name = url.split("/v1/")[1].split("/")[0]
            filename = f"{service_name}_{url_hash[:8]}.json"
        elif url == base_url:
            filename = "services_list.json"

        return self._cache_dir / filename

    def read_from_cache(self, url: str, base_url: str, allow_stale: bool = False) -> Any | None:
        """Read from disk cache with TTL checking.

        Args:
            url: URL to read from cache
            base_url: Base URL for service reference API
            allow_stale: If True, return stale cache data even if expired

        Returns:
            Cached data if valid (or if allow_stale and data exists), None otherwise
        """
        if not self.enable_cache:
            return None

        cache_path = self._get_cache_path(url, base_url)

        if not cache_path.exists():
            return None

        try:
            # Check file modification time for TTL
            mtime = cache_path.stat().st_mtime
            is_expired = time.time() - mtime > self.cache_ttl

            if is_expired and not allow_stale:
                # Cache expired - don't delete the file, just return None
                # The file will be refreshed (overwritten) on next successful fetch
                logger.debug(f"Cache expired for {url} (keeping file for refresh)")
                return None

            with open(cache_path, encoding="utf-8") as f:
                data = json.load(f)

            if is_expired:
                logger.debug(f"Disk cache stale hit for {url} (allow_stale=True)")
            else:
                logger.debug(f"Disk cache hit for {url}")
            return data

        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.warning(f"Failed to read cache for {url}: {e}")
            return None

    def write_to_cache(self, url: str, data: Any, base_url: str) -> None:
        """Write to disk cache.

        Args:
            url: URL to cache data for
            data: Data to cache
            base_url: Base URL for service reference API
        """
        if not self.enable_cache:
            return

        cache_path = self._get_cache_path(url, base_url)

        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Written to disk cache: {url}")
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.warning(f"Failed to write cache for {url}: {e}")

    def load_services_from_file(self) -> list[ServiceInfo]:
        """Load services list from local _services.json file.

        Returns:
            List of ServiceInfo objects loaded from _services.json

        Raises:
            ValueError: If aws_services_dir is not set or _services.json is invalid
            FileNotFoundError: If _services.json doesn't exist
        """
        if not self.aws_services_dir:
            raise ValueError("aws_services_dir is not set")

        services_file = self.aws_services_dir / "_services.json"
        if not services_file.exists():
            raise FileNotFoundError(f"_services.json not found in {self.aws_services_dir}")

        try:
            with open(services_file, encoding="utf-8") as f:
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
            raise ValueError(f"Invalid JSON in _services.json: {e}") from e

    def load_service_from_file(self, service_name: str) -> ServiceDetail:
        """Load service detail from local JSON file.

        Args:
            service_name: Name of the service (case-insensitive)

        Returns:
            ServiceDetail object loaded from {service}.json

        Raises:
            ValueError: If aws_services_dir is not set or service JSON is invalid
            FileNotFoundError: If service JSON file doesn't exist
        """
        if not self.aws_services_dir:
            raise ValueError("aws_services_dir is not set")

        # Normalize filename (lowercase, replace spaces with underscores)
        filename = f"{service_name.lower().replace(' ', '_')}.json"
        service_file = self.aws_services_dir / filename

        if not service_file.exists():
            raise FileNotFoundError(f"Service file not found: {service_file}")

        try:
            with open(service_file, encoding="utf-8") as f:
                data = json.load(f)

            service_detail = ServiceDetail.model_validate(data)
            logger.debug(f"Loaded service {service_name} from local file: {service_file}")
            return service_detail

        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in {service_file}: {e}") from e

    def clear_disk_cache(self) -> None:
        """Remove all cached files from disk."""
        if not self.enable_cache or not self._cache_dir.exists():
            return

        for cache_file in self._cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.warning(f"Failed to delete cache file {cache_file}: {e}")

        logger.info("Cleared disk cache")
