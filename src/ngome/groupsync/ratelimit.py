"""A token bucket per key, kept in memory.

Each instance has its own buckets, so with several Cloud Run instances a key can get the
limit from each of them; that is fine for abuse control, and it is why the caller's address
can be a key here without ever being stored. A restart refills the buckets.
"""

from collections import OrderedDict


class RateLimiter:
    def __init__(self, capacity: int, per_minute: int, max_keys: int = 10_000) -> None:
        self._capacity = float(capacity)
        self._per_minute = per_minute
        self._max_keys = max_keys
        # key -> [tokens, last seen (ms)], least recently used first.
        self._buckets: OrderedDict[str, list[float]] = OrderedDict()

    def take(self, key: str, now_ms: int, cost: float = 1) -> bool:
        """Take ``cost`` tokens from ``key``'s bucket, or return False when it is short."""
        bucket = self._buckets.get(key)
        if bucket is None:
            if len(self._buckets) >= self._max_keys:
                # Forget whoever has been quiet longest; they come back with a full bucket.
                self._buckets.popitem(last=False)
            bucket = [self._capacity, float(now_ms)]
            self._buckets[key] = bucket
        else:
            self._buckets.move_to_end(key)
        elapsed = max(0.0, now_ms - bucket[1])
        bucket[0] = min(self._capacity, bucket[0] + elapsed * self._per_minute / 60_000)
        bucket[1] = float(now_ms)
        if bucket[0] < cost:
            return False
        bucket[0] -= cost
        return True

    def __len__(self) -> int:
        return len(self._buckets)
