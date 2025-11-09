"""Caching utilities for IAM Policy Validator.

This module provides reusable caching implementations with TTL support.
"""

import asyncio
import time
from collections import OrderedDict
from typing import Any


class LRUCache:
    """Thread-safe LRU (Least Recently Used) cache implementation with TTL support.

    This cache automatically expires items after a specified time-to-live (TTL)
    and evicts the least recently used items when the cache reaches maximum size.

    Features:
    - Async-safe with lock protection
    - Automatic TTL-based expiration
    - LRU eviction when at capacity
    - O(1) get and set operations

    Example:
        >>> cache = LRUCache(maxsize=100, ttl=3600)
        >>> await cache.set("key", "value")
        >>> value = await cache.get("key")
        >>> await cache.clear()

    Args:
        maxsize: Maximum number of items in cache (default: 128)
        ttl: Time to live in seconds (default: 3600 = 1 hour)
    """

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
        """Get item from cache if not expired.

        Args:
            key: Cache key to retrieve

        Returns:
            Cached value if found and not expired, None otherwise

        Note:
            Successfully retrieved items are moved to the end (marked as most recently used).
        """
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
        """Set item in cache with current timestamp.

        Args:
            key: Cache key
            value: Value to cache

        Note:
            If cache is at capacity, the least recently used item will be evicted.
        """
        async with self._lock:
            if key in self.cache:
                # Move to end if exists
                self.cache.move_to_end(key)
            elif len(self.cache) >= self.maxsize:
                # Remove least recently used (first item)
                self.cache.popitem(last=False)

            self.cache[key] = (value, time.time())

    async def clear(self) -> None:
        """Clear the entire cache.

        Removes all cached items.
        """
        async with self._lock:
            self.cache.clear()

    def __len__(self) -> int:
        """Return the current number of items in cache."""
        return len(self.cache)

    def __contains__(self, key: str) -> bool:
        """Check if key exists in cache (does not check expiration)."""
        return key in self.cache
