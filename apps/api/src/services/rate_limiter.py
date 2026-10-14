import time
from typing import Optional, Tuple
import redis.asyncio as aioredis


class RateLimiter:
    """
    Distributed Token-Bucket rate limiter backed by Redis.
    Falls back gracefully to in-memory tracking when Redis is not connected.
    """

    def __init__(self, redis_client: Optional[aioredis.Redis] = None):
        self.redis = redis_client
        self._local_buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_update_ts)

    async def check_rate_limit(
        self,
        identifier: str,
        limit_rpm: int = 60,
        cost_tokens: int = 1,
    ) -> Tuple[bool, int, float]:
        """
        Checks whether the request is within rate limits.
        Returns:
            (is_allowed, remaining_tokens, retry_after_seconds)
        """
        now = time.time()
        capacity = float(limit_rpm)
        refill_rate = capacity / 60.0  # tokens per second

        if self.redis is not None:
            try:
                # Redis token bucket via atomic pipeline
                bucket_key = f"aegis:ratelimit:{identifier}"
                async with self.redis.pipeline(transaction=True) as pipe:
                    pipe.hgetall(bucket_key)
                    results = await pipe.execute()

                data = results[0]
                if not data:
                    tokens = capacity - cost_tokens
                    last_update = now
                else:
                    last_tokens = float(data.get(b"tokens", capacity))
                    last_update = float(data.get(b"last_update", now))
                    elapsed = max(0.0, now - last_update)
                    tokens = min(capacity, last_tokens + elapsed * refill_rate) - cost_tokens

                if tokens >= 0:
                    await self.redis.hset(
                        bucket_key,
                        mapping={"tokens": str(tokens), "last_update": str(now)},
                    )
                    await self.redis.expire(bucket_key, 120)
                    return True, int(tokens), 0.0
                else:
                    missing_tokens = -tokens
                    retry_after = missing_tokens / refill_rate
                    return False, 0, round(retry_after, 2)
            except Exception:
                # Fallback to local memory if Redis connection dropped
                pass

        # In-memory Token Bucket Fallback
        last_tokens, last_update = self._local_buckets.get(identifier, (capacity, now))
        elapsed = max(0.0, now - last_update)
        current_tokens = min(capacity, last_tokens + elapsed * refill_rate)

        if current_tokens >= cost_tokens:
            new_tokens = current_tokens - cost_tokens
            self._local_buckets[identifier] = (new_tokens, now)
            return True, int(new_tokens), 0.0
        else:
            missing_tokens = cost_tokens - current_tokens
            retry_after = missing_tokens / refill_rate
            return False, 0, round(retry_after, 2)
