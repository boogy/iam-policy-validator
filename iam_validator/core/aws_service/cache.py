"""Multi-layer caching for AWS service data.

This module coordinates memory (LRU) and disk caching to optimize
AWS service data retrieval performance.
"""

import logging
from typing import Any

from iam_validator.core.aws_service.storage import ServiceFileStorage
from iam_validator.utils.cache import LRUCache

logger = logging.getLogger(__name__)


class ServiceCacheManager:
    """Coordinates memory and disk caching for service data.

    This class implements a two-tier caching strategy:
    1. Fast in-memory LRU cache for frequently accessed data
    2. Disk-based cache with TTL for persistence across runs

    Cache lookup order:
    1. Check memory cache (fastest)
    2. Check disk cache (if enabled)
    3. Return None if not found in either
    """

    def __init__(
        self,
        memory_cache_size: int = 256,
        cache_ttl: int = 86400,
        storage: ServiceFileStorage | None = None,
    ) -> None:
        """Initialize cache manager.

        Args:
            memory_cache_size: Maximum number of items in memory cache
            cache_ttl: Cache time-to-live in seconds
            storage: Optional storage backend for disk caching
        """
        self._memory_cache = LRUCache(maxsize=memory_cache_size, ttl=cache_ttl)
        self._storage = storage

    async def get(self, cache_key: str, url: str | None = None, base_url: str = "") -> Any | None:
        """Get from memory cache, fallback to disk cache.

        Args:
            cache_key: Key to lookup in memory cache
            url: Optional URL for disk cache lookup
            base_url: Base URL for service reference API (used for disk cache path)

        Returns:
            Cached data if found, None otherwise
        """
        # Check memory cache first (fastest)
        cached = await self._memory_cache.get(cache_key)
        if cached is not None:
            logger.debug(f"Memory cache hit for key: {cache_key}")
            return cached

        # Check disk cache if URL provided and storage available
        if url and self._storage:
            cached = self._storage.read_from_cache(url, base_url)
            if cached is not None:
                logger.debug(f"Disk cache hit for URL: {url}")
                # Populate memory cache for faster future access
                await self._memory_cache.set(cache_key, cached)
                return cached

        return None

    async def get_stale(self, url: str | None = None, base_url: str = "") -> Any | None:
        """Get from disk cache even if expired (stale data fallback).

        Use this method to retrieve stale cache data when a fresh fetch fails.
        The stale data can serve as a fallback to avoid complete failure.

        Args:
            url: URL for disk cache lookup
            base_url: Base URL for service reference API (used for disk cache path)

        Returns:
            Cached data if found (regardless of TTL), None otherwise
        """
        if url and self._storage:
            cached = self._storage.read_from_cache(url, base_url, allow_stale=True)
            if cached is not None:
                logger.info(f"Using stale cache fallback for URL: {url}")
                return cached
        return None

    async def set(
        self, cache_key: str, value: Any, url: str | None = None, base_url: str = ""
    ) -> None:
        """Store in memory and optionally disk cache.

        Args:
            cache_key: Key to store in memory cache
            value: Value to cache
            url: Optional URL for disk cache storage
            base_url: Base URL for service reference API (used for disk cache path)
        """
        # Always store in memory cache
        await self._memory_cache.set(cache_key, value)

        # Store in disk cache if URL provided and storage available
        if url and self._storage:
            self._storage.write_to_cache(url, value, base_url)

    async def clear(self) -> None:
        """Clear memory cache and optionally disk cache."""
        await self._memory_cache.clear()

        if self._storage:
            self._storage.clear_disk_cache()

        logger.info("Cleared all caches")

    def get_stats(self) -> dict[str, int]:
        """Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        return {
            "memory_cache_size": len(self._memory_cache.cache),
        }
