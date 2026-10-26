"""
Main Application Entrypoint (Stateless Zero Trust API)
Enforces strict Tenant Context Binding, Path-to-Claim Verification, RLS integration, and Progressive Rate Limiting.
"""

import os
import sys
import uvicorn
import uuid
from typing import Dict, Any
from fastapi import FastAPI, Depends, HTTPException, status, Path, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from middleware.auth import require_zero_trust
from database.database import get_db, tenant_context, Base, engine
from routers import tenants, proxy
from prometheus_fastapi_instrumentator import Instrumentator

# Prometheus Multi-Process imports for Gunicorn worker aggregation
from prometheus_client import CollectorRegistry, multiprocess, generate_latest, CONTENT_TYPE_LATEST

# SlowAPI & Redis imports for progressive backoff and brute-force protection
import redis
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

Base.metadata.create_all(bind=engine)

# Initialize Rate Limiter & Redis client for progressive penalties
limiter = Limiter(key_func=get_remote_address)

# Dynamically pulls "redis" from Docker environment, defaults to "localhost" for local debugging
redis_host = os.getenv("REDIS_HOST", "localhost")
redis_client = redis.Redis(host=redis_host, port=6379, db=0, decode_responses=True)

app = FastAPI(
    title="Stateless Zero Trust API",
    docs_url=None,  # Hardened: Disable Swagger UI in zero-trust environments
    redoc_url=None,  # Hardened: Disable ReDoc
)

# Attach limiter state and register custom progressive backoff exception handler
app.state.limiter = limiter

async def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded):
    client_ip = get_remote_address(request)
    path = request.url.path.lower()
    
    # Check if IP is permanently banned due to sustained attack patterns
    if redis_client.exists(f"banned:{client_ip}"):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "🚨CRITICAL SECURITY ALERT: IP address has been permanently banned due to sustained attack patterns."}
        )

    # Check if client is under an active temporary lockout
    if redis_client.exists(f"lockout:{client_ip}"):
        ttl = redis_client.ttl(f"lockout:{client_ip}")
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content= {"detail": f"🚨SECURITY ALERT: Too many requests. IP locked out. Try again in {ttl} seconds."}
        )

    # Detect Password Guessing / Credential Stuffing on Auth Routes
    is_auth_endpoint = any(keyword in path for keyword in ["login", "auth", "signin", "token"])
    
    if is_auth_endpoint:
        # Strict 24-hour penalty for password guessing attempts
        lockout_time = 86400  # 24 hours in seconds
        redis_client.setex(f"lockout:{client_ip}", lockout_time, "auth_locked")
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "🚨SECURITY ALERT: Excessive authentication attempts detected. IP temporarily locked out for 24 hours."}
        )

    # Progressive Backoff & Permanent Ban for General API / Brute-forcing / Attack patterns
    violations = redis_client.incr(f"violations:{client_ip}")
    
    # Set a 1-hour sliding TTL on the first violation so accidental mistakes decay over time
    if violations == 1:
        redis_client.expire(f"violations:{client_ip}", 3600)
    
    # Escalating Penalty Matrix for general endpoints
    if violations == 1:
        lockout_time = 60       # 1 minute penalty
    elif violations == 2:
        lockout_time = 300      # 5 minutes penalty
    elif violations == 3:
        lockout_time = 900      # 15 minutes penalty
    elif violations == 4:
        lockout_time = 1800     # 30 minutes penalty
    elif violations == 5:
        lockout_time = 3600     # 1 hour penalty
    elif violations == 6:
        lockout_time = 7200     # 2 hours penalty
    else:
        # 7+ violations: Classified as a deliberate sustained attack -> Permanent Ban
        redis_client.set(f"banned:{client_ip}", "permanent_attack_block")
        redis_client.delete(f"violations:{client_ip}")
        
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "🚨CRITICAL SECURITY ALERT: Sustained attack pattern or brute-force detected. IP address permanently blocked."}
        )

    # Set the temporary dynamic lockout block in Redis
    redis_client.setex(f"lockout:{client_ip}", lockout_time, "blocked")

    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": f"🚨SECURITY ALERT: Rate limit exceeded. Violation count: {violations}. Security lockout applied for {lockout_time}s."}
    )

app.add_exception_handler(RateLimitExceeded, custom_rate_limit_handler)

# Prometheus Metrics Instrumentation with Multi-Process Worker Aggregation
Instrumentator().instrument(app)

@app.get("/metrics", tags=["Observability"])
def metrics():
    registry = CollectorRegistry()
    if "PROMETHEUS_MULTIPROC_DIR" in os.environ:
        multiprocess.MultiProcessCollector(registry)
    else:
        from prometheus_client import REGISTRY
        registry = REGISTRY
    data = generate_latest(registry)
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)

raw_cors = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173,http://127.0.0.1:7010",
)
cors_origins = [origin.strip() for origin in raw_cors.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Tenant-ID"],
    max_age=600,
)


@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    return {"status": "healthy", "architecture": "Stateless Zero Trust"}


@app.get("/api/v1/tenants/{tenant_id}/documents", status_code=status.HTTP_200_OK)
@limiter.limit("3/minute")  # High-security threshold with progressive lockout
def get_tenant_documents(
    request: Request,  # Required for IP tracking via SlowAPI
    tenant_id: str = Path(..., description="Target Tenant Identifier"),
    claims: Dict[str, Any] = Depends(
        require_zero_trust(required_role="admin", required_clearance=2)
    ),
    db: Session = Depends(get_db),
):
    """
    Zero Trust Document Retrieval:
    1. Validates path parameter against authenticated JWT claims (Anti-IDOR/BOLA).
    2. Sets ContextVar and binds PostgreSQL Row-Level Security (RLS) variable.
    3. Queries DB through tenant-isolated session.
    """
    authenticated_tenant = claims.get("tenant_id")

    # Server-Side Zero Trust Validation: Path-to-claim alignment
    if not authenticated_tenant or authenticated_tenant != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Token context does not match target tenant resource.",
        )

    # Sanitize and validate UUID format
    try:
        validated_tenant_id = str(uuid.UUID(authenticated_tenant))
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid tenant identifier format.",
        )

    # ContextVar & PostgreSQL RLS session binding
    tenant_context.set(validated_tenant_id)

    try:
        db.execute(
            text("SELECT set_config('app.current_tenant', :tenant, true)"),
            {"tenant": validated_tenant_id},
        )

        raw_results = db.execute(
            text(
                "SELECT id, title, content, tenant_id FROM documents WHERE tenant_id = :tid"
            ),
            {"tid": validated_tenant_id},
        ).fetchall()

        documents = [dict(row._mapping) for row in raw_results]
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal database error occurred while fetching tenant resources.",
        )

    return {
        "status": "success",
        "tenant_id": validated_tenant_id,
        "caller_sub": claims.get("sub"),
        "documents": documents,
    }

app.include_router(tenants.router)
app.include_router(proxy.router)

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=7010, reload=True)
