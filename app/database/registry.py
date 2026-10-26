import os
import logging
import redis.asyncio as redis
from fastapi import HTTPException, status

logger = logging.getLogger("gateway.registry")

REDIS_URL = os.getenv("REDIS_URL")
if not REDIS_URL:
    raise RuntimeError("CRITICAL: REDIS_URL environment variable is missing.")

redis_client = redis.from_url(REDIS_URL, decode_responses=True)

async def get_secure_upstream_url(db_pool, service_name: str, tenant_id: str) -> str:
    """
    Zero Trust Upstream Resolver: Uses connection pooling, tiered failure handling,
    and PostgreSQL Row-Level Security.
    """
    cache_key = f"gateway:upstream:{tenant_id}:{service_name}"
    
    # 1. Try Redis Cache (Fail-Open for cache errors to maintain high availability)
    try:
        cached_url = await redis_client.get(cache_key)
        if cached_url:
            return cached_url
    except redis.RedisError as redis_exc:
        logger.warning(f"Redis cache degraded, falling back to database: {redis_exc}")

    # 2. Query PostgreSQL Control Plane via Connection Pool (Fail-Closed for DB errors)
    try:
        async with db_pool.acquire() as conn:
            async with conn.transaction():
                # Enforce RLS session context securely for this transaction
                await conn.execute("SET LOCAL app.current_tenant_id = $1", tenant_id)
                
                row = await conn.fetchrow(
                    """
                    SELECT upstream_url 
                    FROM upstream_services 
                    WHERE service_name = $1 
                      AND is_active = TRUE
                    """,
                    service_name
                )
                
                if not row:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Target service not found, inactive, or unauthorized."
                    )
                    
                target_url = row["upstream_url"]
                
                # 3. Attempt to update cache asynchronously (non-blocking if redis fails)
                try:
                    await redis_client.setex(cache_key, 30, target_url)
                except redis.RedisError:
                    pass
                    
                return target_url

    except asyncpg.PostgresError as db_exc:
        logger.error(f"Control plane database failure: {db_exc}")
        # FAIL-CLOSED: Secure denial if database control plane fails
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Security control plane temporarily unavailable. Request denied."
        )
