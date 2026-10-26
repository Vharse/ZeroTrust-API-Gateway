import os
import httpx
from fastapi import APIRouter, Request, Response, Depends, HTTPException, status
from middleware.auth import require_zero_trust
from config.config import ZT_CONFIG
from slowapi import Limiter
from slowapi.util import get_remote_address

router = APIRouter(prefix="/proxy", tags=["Zero Trust Proxy Shield"])

# Initialize Rate Limiter (tracks requests by remote client IP address)
limiter = Limiter(key_func=get_remote_address)

# Multi-Upstream Service Registry: Maps service identifiers to target backend URLs securely
SERVICE_REGISTRY = {
    "sqi": os.getenv(
        "UPSTREAM_WEB_APP_URL", 
        os.getenv("BACKEND_TARGET_URL", "https://edu.sqi.ng")
    ),
    # You can easily register additional upstream web apps or microservices here:
    # "auth-service": os.getenv("UPSTREAM_AUTH_URL", "http://auth-backend:8081"),
}

@router.api_route("/{service_name}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@limiter.limit("3/minute")  # Aligned High-Security Threshold: Throttles brute-force & flood attacks
async def multi_upstream_proxy_shield(
    request: Request,  # Required by SlowAPI to extract client IP address
    service_name: str,
    path: str,
    claims: dict = Depends(require_zero_trust(required_clearance=1))
):
    """
    Multi-Upstream Zero Trust Proxy Shield: Intercepts incoming requests, validates tokens/tenant claims 
    via require_zero_trust, matches the requested service against the secure registry, and proxies 
    authorized traffic downstream.
    """
    # Security Gate: Ensure the requested upstream service is explicitly registered
    if service_name not in SERVICE_REGISTRY:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target service '{service_name}' is not registered with the Zero Trust gateway."
        )

    target_url = SERVICE_REGISTRY[service_name]

    async with httpx.AsyncClient(base_url=target_url, timeout=30.0) as client:
        body = await request.body()
        headers = dict(request.headers)
        
        # Security Hardening: Remove host header and hop-by-hop headers 
        # to prevent header injection and proxy routing conflicts.
        headers.pop("host", None)
        hop_by_hop = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade"}
        for h in hop_by_hop:
            headers.pop(h, None)
        
        # Inject verified Zero Trust identity headers universally for any downstream backend language
        headers["X-Authenticated-Tenant-ID"] = claims.get("tenant_id")
        headers["X-Authenticated-User-Role"] = claims.get("role")
        headers["X-Authenticated-User-ID"] = claims.get("sub", "")

        try:
            backend_response = await client.request(
                method=request.method,
                url=f"/{path}",
                content=body,
                params=request.query_params,
                headers=headers
            )
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Gateway error connecting to backend service '{service_name}': {str(exc)}"
            )

        return Response(
            content=backend_response.content,
            status_code=backend_response.status_code,
            headers=dict(backend_response.headers)
        )
