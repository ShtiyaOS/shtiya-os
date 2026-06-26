# dependencies.py
# ==============================================================================
# SHTIYA OS: FASTAPI DEPENDENCIES & ALGORITHMIC RATE LIMITER
# ==============================================================================

import time
from fastapi import Request, HTTPException
from typing import Optional
from cache import redis_client

# Atomic Lua Script for Sliding Window Log
LUA_SLIDING_WINDOW = """
local key = KEYS[1]
local now_sec = tonumber(ARGV[1])
local now_usec = tonumber(ARGV[2])
local window_size = tonumber(ARGV[3])
local limit = tonumber(ARGV[4])
local window_start = now_sec - window_size
local member = now_sec.. '.'.. now_usec

-- Purge timestamps older than the configured sliding window
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

-- Aggregate remaining entries
local current_count = redis.call('ZCARD', key)

if current_count < limit then
    redis.call('ZADD', key, now_sec, member)
    redis.call('EXPIRE', key, window_size)
    return 1 -- Allowed
else
    return 0 -- Throttled
end
"""

async def register_lua_script():
    return await redis_client.script_load(LUA_SLIDING_WINDOW)

async def check_rate_limit(user_id: str, limit: int = 55, window: int = 60) -> bool:
    """
    Evaluates the sliding window rate limit for external integration syncs.
    """
    now = time.time()
    now_sec = int(now)
    now_usec = int((now - now_sec) * 1000000)
    
    script_sha = await register_lua_script()
    
    result = await redis_client.evalsha(
        script_sha,
        1,
        f"rate_limit:clio_api:{user_id}",
        now_sec,
        now_usec,
        window,
        limit
    )
    
    return result == 1

async def verify_external_api_throughput(request: Request):
    """
    FastAPI Dependency for structural throttling.
    """
    user_id = request.headers.get("X-Clio-User-ID")
    if not user_id:
        raise HTTPException(
            status_code=400, 
            detail="X-Clio-User-ID header is required."
        )
        
    is_allowed = await check_rate_limit(user_id)
    if not is_allowed:
        raise HTTPException(
            status_code=429, 
            detail="Sliding window rate limit exceeded. Retry in 60 seconds."
        )
    return user_id