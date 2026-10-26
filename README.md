# ZeroTrust-API-Gateway

![Python](https://img.shields.io/badge/Python-3.13+-3776AB?style=flat&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat&logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-18-4169E1?style=flat&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-Lockout_Defense-DC382D?style=flat&logo=redis&logoColor=white)
![Prometheus](https://img.shields.io/badge/Prometheus-Monitoring-E6522C?style=flat&logo=prometheus&logoColor=white)
![Grafana](https://img.shields.io/badge/Grafana-Observability-F46800?style=flat&logo=grafana&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED?style=flat&logo=docker&logoColor=white)
![Tests](https://img.shields.io/badge/Test_Suite-12%2F12_Passed-brightgreen?style=flat&logo=pytest&logoColor=white)

A hardened, multi-tenant Zero Trust API Gateway engineered around perimeter defense principles, combining Role-Based Access Control (RBAC), Attribute-Based Access Control (ABAC), PostgreSQL Row-Level Security (RLS), Asymmetric (RS256) JWT Validation, Redis-backed progressive lockout rate limiting, and real-time Prometheus/Grafana observability.

Designed to provide defense-in-depth security, strict cryptographic tenant isolation, least-privileged runtime execution, high-performance brute-force protection, and automated security auditing.

---

## Architectural Blueprint & Request Flow

```text
 ┌──────────────┐         Bearer Token (RS256)        ┌──────────────────────────────────────────────────┐
 │ Client / App │ ──────────────────────────────────> │ FastAPI ZeroTrust-API-Gateway (Middleware Layer) │
 └──────────────┘                                     └──────────────────────────────────────────────────┘
                                                                               │
                                                       1. Rate Limiting & Redis Progressive Lockout Check
                                                       2. Cryptographic Validation (RSA Public Key)
                                                       3. Context Injection (Tenant ID, Roles, Attr)
                                                                               │
                                                                               ▼
                                                      ┌──────────────────────────────────────────────────┐
                                                      │              PostgreSQL 18 (Engine)              │
                                                      │      [RLS Policy Enforced Dynamically]           │
                                                      └──────────────────────────────────────────────────┘

##Core Security Matrix

##Permissions, boundaries, and perimeter controls are evaluated at every stage of the request lifecycle:

#1. Role-Based Access Control (RBAC)

    Concept: Rights are assigned based on organizational roles embedded within verified security tokens.

    Implementation: User claims specify distinct operational roles (admin, tenant_user, auditor), gating administrative routers (app/routers/tenants.py) and execution paths.

#2. Attribute-Based Access Control (ABAC)

    Concept: Dynamic evaluation driven by environmental, user, and resource attributes rather than static assignments.

    Implementation: Security dependencies (app/security/dependencies.py) evaluate dynamic context—such as numeric clearance levels (clearance >= 2), department restrictions, resource tags, and tenant scopes—before permitting access.

#3. Database Row-Level Security (RLS) & Dynamic Service Registry

    Concept: Storage-engine level firewall enforcing isolation directly at the database tier combined with tenant-isolated upstream routing.

    Implementation: init_rls.sql forces ROW LEVEL SECURITY on target tables. Policies match rows against runtime session settings (current_setting('app.current_tenant_id', true)), transparently dropping unauthorized cross-tenant data. Administrative endpoints (POST /api/v1/tenants/{tenant_id}/services) allow secure dynamic registration of downstream microservices using composite upserts (ON CONFLICT).

#4. Asymmetric Cryptography & Hardened JWT Parsing

    Concept: Cryptographically verifiable identity claims operating on a Zero Trust trust-boundary model.

    Implementation: Tokens are signed using an offline private key (jwt_private.pem) and verified downstream via an asymmetric public key (jwt_public.pem), enforcing mandatory validation for jti (unique replay prevention IDs), iat (issuance timestamps), department, and UUID-formatted tenant_id claims.

#5. Rate Limiting, Redis Progressive Lockout & Permanent Ban Defense

    Concept: Prevents credential stuffing, brute-force enumeration, and denial-of-service (DoS) attacks at the perimeter through stateful memory tracking.

    Implementation: SlowAPI throttles endpoints, while an integrated Redis persistent store (violations:{client_ip}) tracks client IP violation counters across Docker bridge networks (172.19.0.1).

        Sliding TTL Decay: Initial violations receive a 1-hour TTL so accidental, infrequent mistakes by legitimate users decay over time while preventing stale key bloat.

        Escalating Penalty Matrix: Repeated rate-limit breaches dynamically escalate penalties (1 min, 5 mins, 15 mins, 30 mins, 1 hr, to 2-hr lockouts).

        Automated Permanent IP Bans: Reaching 7+ violations classifies traffic as a deliberate attack, immediately purging temporary counters and applying a permanent Redis ban (banned:{client_ip}) enforced with an immediate HTTP 403 Forbidden.

#6. Zero Trust Asynchronous Reverse Proxy Engine (app/routers/proxy.py)

    Concept: High-performance, secure request forwarding with perimeter trust boundary sanitization.

    Implementation: Utilizes httpx.AsyncClient alongside a resilient upstream resolver (app/database/register.py) featuring fail-open Redis caching and fail-closed database control-plane handling. Strips untrusted client headers (host) and injects verified gateway trust markers (X-Gateway-Authenticated-Tenant, X-Forwarded-For) before streaming requests to downstream services.

#7. Prometheus, Grafana Observability & Automated Alerting

     Concept: Real-time metrics visualization, security telemetry monitoring, and actionable alerting.

    Implementation: prometheus_fastapi_instrumentator exposes internal metrics scraped dynamically via prometheus.yml. Grafana-managed alert rules track core production triads (Service-Down, High-Error-Rate, and Low-Apdex) with robust "No Data" handling.

#8. Graceful Error Handling & SIEM Audit Logging

    Least-Privilege Runtime: Application connection pools utilize a restricted non-superuser role (app_user), preventing schema-level privilege escalation.

    Audit Telemetry: Captures unauthorized access attempts, cross-tenant violations, and malformed payload attempts for SIEM ingestion.



## Zero Trust Test Suite (12 Vectors)

The suites in tests/whitebox/zt_test.py and tests/blackbox/zt_test.py verify all security boundaries against automated vectors:

#	Description				Target Threat / Vulnerability				Expected Response

1. Authorized Request & RLS Check		Cross-tenant data leakage				HTTP 200 + Correct Tenant Data

2. Anti-BOLA Cross-Tenant Gate			Broken Object Level Authorization (IDOR)		HTTP 403 Forbidden

3. Insufficient ABAC Clearance			Privilege Escalation (Low Clearance Tier)		HTTP 403 Forbidden

4. Temporal Claim Expiration			Replay Attacks with Expired JWTs			HTTP 401 Unauthorized

5. Cryptographic Signature Tampering		Payload Munge / Cryptographic Spoofing			HTTP 401 Unauthorized

6. Algorithm Downgrade Attack			alg: "none" Arbitrary Token Bypass			HTTP 401 Unauthorized

7. Missing Authorization Header			Unauthenticated Access					HTTP 401 / 403

8. Malformed Auth Scheme Prefix			Non-Standard Prefix Injection				HTTP 401 / 403

9. RBAC Role Evaluation				Role Mismatch (viewer accessing admin)			Controlled HTTP 403 / 200 Gate

10. Missing Mandatory Claims			Missing jti or tenant_id claims				HTTP 401 Unauthorized

11. Malformed UUID Injection			Type Injection in Path & Token UUIDs			HTTP 400 / 401

12. Issuer / Audience Mismatch			Federated Token Spoofing (iss/aud)			HTTP 401 Unauthorized



## Project Directory Structure
.
├── .github/
│   └── workflows/         # CI/CD DevSecOps automation pipeline & security scripts
├── app/                   # Core application directory
│   ├── app.py             # FastAPI application entrypoint, SlowAPI, and Redis lockout handlers
│   ├── config/            # Environment configurations and global settings
│   ├── database/          # Connection pooling, RLS setup, and secure service registration logic (register.py)
│   ├── middleware/        # Tenant context injection, RBAC/ABAC enforcement, and auth hooks
│   ├── routers/           # Feature-scoped API endpoints (Tenants, Admin Service Registry, Reverse Proxy Shield)
│   └── security/          # Core crypto validation, JWT parsing, and security audit loggers
├── database/              # SQL scripts for PostgreSQL Row-Level Security setup
│   └── init_rls.sql
├── docker-compose.yml     # Multi-container orchestration (Backend + Postgres + Redis + Prometheus + Grafana)
├── Dockerfile             # Non-root container build spec for the FastAPI service
├── env.example            # Required environment configuration template for local setup
├── jwt_private.pem        # RSA private key for token generation and signing
├── jwt_public.pem         # RSA public key for cryptographic signature validation
├── prometheus.yml         # Prometheus scraping configuration for FastAPI telemetry
├── README.md              # Project documentation
├── requirements.txt       # Python dependency manifest
└── tests/                 # Automated Zero Trust test suites
    ├── blackbox/
    │   ├── .env.live      # Live environment configuration for black-box penetration testing
    │   └── zt_test.py     # Production/Staging penetration suite (tests external boundaries & CORS)
    └── whitebox/
        └── zt_test.py     # 12-vector zero-trust local integration test suite

