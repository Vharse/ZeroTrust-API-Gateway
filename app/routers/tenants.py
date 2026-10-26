from fastapi import APIRouter, Depends, Request
from security.dependencies import require_zero_trust
from slowapi import Limiter
from slowapi.util import get_remote_address

router = APIRouter(prefix="/api/v1/tenants", tags=["Tenants"])

# Initialize Rate Limiter
limiter = Limiter(key_func=get_remote_address)

@router.get("/{tenant_id}/documents")
@limiter.limit("3/minute")
async def get_tenant_documents(
    request: Request,  # Required by SlowAPI to extract client IP address
    tenant_id: str,
    claims: dict = Depends(require_zero_trust(required_role="admin", required_clearance=2))
):
    # RLS is already active via the transaction, and Anti-BOLA is enforced by the dependency.
    return {
        "status": "success",
        "tenant_id": tenant_id,
        "user": claims.get("sub"),
        "documents": [] # Query results from your database model here
    }
