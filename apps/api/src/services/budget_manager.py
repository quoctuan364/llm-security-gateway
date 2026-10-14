from typing import Optional, Tuple

import redis.asyncio as aioredis


class BudgetManager:
    """
    Manages daily and monthly token budgets with atomic reservation & settlement.
    Prevents race conditions in high-concurrency environments.
    """

    def __init__(self, redis_client: Optional[aioredis.Redis] = None):
        self.redis = redis_client
        self._local_budgets: dict[str, int] = {}  # key -> current_used_tokens

    async def reserve_budget(
        self,
        api_key_id: str,
        estimated_tokens: int,
        daily_limit: int = 100_000,
    ) -> Tuple[bool, int, str]:
        """
        Attempts to atomically reserve tokens before calling the LLM provider.
        Returns:
            (is_allowed, remaining_budget, reason)
        """
        if self.redis is not None:
            try:
                budget_key = f"aegis:budget:{api_key_id}:daily"
                # Atomic increment
                current_used = await self.redis.incrby(budget_key, estimated_tokens)
                if current_used > daily_limit:
                    # Exceeded limit: revert the reservation
                    await self.redis.decrby(budget_key, estimated_tokens)
                    remaining = max(0, daily_limit - (current_used - estimated_tokens))
                    return False, remaining, f"Daily token budget of {daily_limit} exceeded"
                return True, max(0, daily_limit - current_used), "Reservation successful"
            except Exception:
                pass

        # In-memory Fallback
        current_used = self._local_budgets.get(api_key_id, 0)
        if current_used + estimated_tokens > daily_limit:
            remaining = max(0, daily_limit - current_used)
            return False, remaining, f"Daily token budget of {daily_limit} exceeded"

        self._local_budgets[api_key_id] = current_used + estimated_tokens
        remaining = max(0, daily_limit - (current_used + estimated_tokens))
        return True, remaining, "Reservation successful"

    async def settle_budget(
        self,
        api_key_id: str,
        estimated_tokens: int,
        actual_tokens: int,
    ) -> int:
        """
        Settles the budget discrepancy once the LLM returns exact token usage.
        adjustment = actual_tokens - estimated_tokens.
        """
        adjustment = actual_tokens - estimated_tokens
        if self.redis is not None:
            try:
                budget_key = f"aegis:budget:{api_key_id}:daily"
                if adjustment != 0:
                    new_val = await self.redis.incrby(budget_key, adjustment)
                    return int(new_val)
                else:
                    val = await self.redis.get(budget_key)
                    return int(val) if val else 0
            except Exception:
                pass

        # In-memory Fallback
        current = self._local_budgets.get(api_key_id, 0)
        settled = max(0, current + adjustment)
        self._local_budgets[api_key_id] = settled
        return settled
