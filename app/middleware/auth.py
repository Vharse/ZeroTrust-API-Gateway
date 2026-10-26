"""
Zero Trust Authentication & ABAC Middleware
Integrates JWT claim verification with PostgreSQL ContextVar tenant binding.
"""
from typing import Optional, Dict, Any
from fastapi import Depends, HTTPException, Security, status, Query, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from security.jwt_validator import validate_jwt
from database.database import tenant_context

security = HTTPBearer(auto_error=True)

def require_zero_trust(
    required_role: Optional[str] = None, 
    required_clearance: int = 0
):
    """
    Dependency factory that enforces ABAC roles/clearance and binds
    the validated tenant_id to the ContextVar for PostgreSQL RLS.
    """
    def dependency(
        request: Request,
        credentials: HTTPAuthorizationCredentials = Security(security),
        tenant_id_query: Optional[str] = Query(None)
    ) -> Dict[str, Any]:
        
        if not credentials or not credentials.credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid Authorization credentials."
            )

        token = credentials.credentials
        
        # Stateless JWT & ABAC Validation
        try:
            claims = validate_jwt(token)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid or expired authentication token: {str(e)}"
            )

        if not isinstance(claims, dict):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload structure."
            )
        
        tenant_id = claims.get("tenant_id") or tenant_id_query
        if not tenant_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing tenant identification in token claims."
            )
            
        user_role = claims.get("role")
        user_clearance = claims.get("clearance", 0)
        
        # RBAC / ABAC Security Gates
        if required_role and user_role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Role '{user_role}' does not meet required '{required_role}'."
            )
            
        if user_clearance < required_clearance:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Clearance level {user_clearance} below required {required_clearance}."
            )

        # Bind validated tenant_id to ContextVar on current worker thread
        tenant_context.set(str(tenant_id))
        request.state.tenant_id = str(tenant_id)
        request.state.user = claims
        
        return claims

    return dependency
