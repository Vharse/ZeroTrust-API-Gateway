"""
Central Security Configuration & Policy Definitions
Configured for Hybrid SQI Production & Localhost Zero-Trust Testing
"""
import os
import sys

raw_cors = os.getenv(
    'CORS_ORIGINS',  
    'http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173'
)
parsed_cors = [origin.strip() for origin in raw_cors.split(",") if origin.strip()]

if "*" in parsed_cors:
    raise ValueError("CORS_ORIGINS cannot contain wildcards ('*') in a Zero-Trust setup.")

ZT_CONFIG = {
    'jwks_url': os.getenv('JWKS_URL', 'https://127.0.0.1:7010/.well-known/jwks.json'),
    'allowed_algorithms': ['RS256'],
    'expected_issuer': os.getenv('JWT_ISSUER', 'https://127.0.0.1:7010'),
    'expected_audience': os.getenv('JWT_AUDIENCE', 'https://127.0.0.1:7010'),
    'required_claims': [
        'sub', 'tenant_id', 'role', 'department', 'clearance', 
        'iat', 'exp', 'iss', 'aud', 'jti'
    ],
    'max_token_lifetime_seconds': 3600,
    'jwks_cache_ttl': 3600,
    'jwks_max_keys': 10,
    'cors_origins': parsed_cors
}

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL and os.getenv("ENVIRONMENT") == "production":
    raise RuntimeError("CRITICAL: DATABASE_URL environment variable must be set in production.")
