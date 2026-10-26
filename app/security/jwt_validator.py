"""
Hardened RS256 JWT Validator
Enforces cryptographic signature verification, temporal claim checks (exp/iat),
and strict issuer/audience policy bounds via dynamic JWKS or local public key fallback.
"""
import os
import uuid
import jwt
from jwt import PyJWKClient, PyJWKClientError
from dataclasses import dataclass
from typing import Optional, Dict, Any
from fastapi import HTTPException, status
from config.config import ZT_CONFIG

PUBLIC_KEY_PATH = os.getenv("JWT_PUBLIC_KEY_PATH", "jwt_public.pem")

# Safely initialize JWKS Client only if a valid URI is configured
jwks_url = ZT_CONFIG.get('jwks_url')
jwks_client = PyJWKClient(
    uri=jwks_url,
    cache_keys=True,
    max_cached_keys=ZT_CONFIG.get('jwks_max_keys', 10),
    lifespan=ZT_CONFIG.get('jwks_cache_ttl', 3600)
) if jwks_url and jwks_url.strip() else None

@dataclass
class TokenValidationResult:
    is_valid: bool
    claims: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

# Load public key into memory once when the module initializes
_CACHED_PUBLIC_KEY = None

def get_cached_public_key() -> str:
    global _CACHED_PUBLIC_KEY
    if _CACHED_PUBLIC_KEY is None:
        if not os.path.exists(PUBLIC_KEY_PATH):
            raise RuntimeError(f"Public key file not found at '{PUBLIC_KEY_PATH}'")
        with open(PUBLIC_KEY_PATH, "r") as f:
            _CACHED_PUBLIC_KEY = f.read()
    return _CACHED_PUBLIC_KEY

def get_verification_key(token: str):
    """
    Attempts to retrieve key dynamically from JWKS URL first if configured.
    Falls back to reading the local public key file dynamically per request.
    """
    if jwks_client:
        try:
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            return signing_key.key
        except Exception:
            pass

    if os.path.exists(PUBLIC_KEY_PATH):
        return get_cached_public_key()
    raise RuntimeError(f"Public key file not found at '{PUBLIC_KEY_PATH}'")

def validate_jwt(token: str) -> dict:
    try:
        public_key = get_verification_key(token)

        expected_iss = ZT_CONFIG.get('expected_issuer')
        expected_aud = ZT_CONFIG.get('expected_audience')

        # Strict RS256 verification enforcing temporal claims & config policy bounds dynamically
        payload = jwt.decode(
            token,
            public_key,
            algorithms=ZT_CONFIG.get('allowed_algorithms', ['RS256']),
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_iss": bool(expected_iss),
                "verify_aud": bool(expected_aud),
                "require": ZT_CONFIG.get('required_claims', [])
            },
            issuer=expected_iss,
            audience=expected_aud
        )
        
        # Zero-Trust Security: Rigorously enforce that tenant_id is a valid UUID format
        # matching our database native uuid column type constraint.
        raw_tenant_id = payload.get("tenant_id")
        try:
            payload["tenant_id"] = str(uuid.UUID(str(raw_tenant_id)))
        except (ValueError, TypeError, AttributeError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Invalid tenant identifier format."
            )

        return payload
    except PyJWKClientError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unauthorized: Key fetching failed ({str(e)})"
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Token has expired."
        )
    except jwt.InvalidAlgorithmError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Disallowed algorithm."
        )
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unauthorized: Invalid token ({str(e)})"
        )
    except HTTPException:
        raise

def validate_token_zero_trust(token: str) -> TokenValidationResult:
    """Compatibility wrapper for package-level imports."""
    try:
        claims = validate_jwt(token)
        return TokenValidationResult(is_valid=True, claims=claims)
    except HTTPException as e:
        return TokenValidationResult(is_valid=False, error=str(e.detail))
