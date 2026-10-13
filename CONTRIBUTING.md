# Contributing to Enterprise Zero Trust Architecture

Welcome! This repository enforces a strict **Zero Trust** security model. We explicitly assume that the client side, network, and user inputs are untrusted. All security controls, authorization boundaries, and tenant isolation rules are enforced **server-side**.

---

## 1. Division of Labor
To ensure zero structural drift and maintain accountability, our team workflow is divided into two distinct domains:

* **Security & Infrastructure (Security Lead):** Owns `app/middleware/`, `app/security/`, database Row-Level Security (`database/init_rls.sql`), and the automated test suites (`tests/`).

* **Business Logic & Features (Software Engineer):** Owns `app/routers/`, business logic services, and feature implementation, ensuring all code complies with our Zero Trust middleware and test suites.

---

## 2. Core Zero Trust Coding Rules

When building or modifying endpoints, every contributor must adhere to these four security rules:

1. **Never Trust Client Input for Tenant Context:** Never accept `tenant_id` or user privilege levels from query parameters, request headers, or JSON bodies. Tenant context must be derived **exclusively** from verified, cryptographically signed JWT claims injected into `request.state` by the auth middleware.

2. **Enforce Database-Level Isolation:** All database queries interacting with multi-tenant resources must explicitly scope records using the server-derived tenant ID, backed by PostgreSQL Row-Level Security (RLS).

3. **Prevent Mass Assignment / Over-Posting:** Never unpack raw request dictionaries directly into database models. Use strict Pydantic schemas that filter out sensitive administrative fields (`is_admin`, `role`, `id`) on update operations.

4. **Parameterize All Queries:** Avoid raw string concatenation or formatting in database queries. Always use ORM parameter bindings or parameterized SQL statements.

---

## 3. The Quality Gate: Automated Pentesting (`zt_test.py`)

**Your code is not finished until all automated security tests pass.** 

We maintain automated black-box and white-box penetration test suites (`tests/`) that audit the API for BOLA, CORS misconfigurations, JWT tampering, mass assignment, and injection vulnerabilities.

### Running the Test Suite Locally:

With your local application server running via Docker Compose, execute the test suites:

```bash```

# Run local white-box integration checks
pytest tests/whitebox/

# Run black-box boundary checks against live app
python3 tests/blackbox/zt_test.py

**Pass Criteria: All security vectors must return [PASS] with a clean exit code (0). If any vector fails, the CI/CD pipeline will block the pull request from merging.**

## 4. Pull Request & Code Review Checklist

Before submitting a Pull Request for review, ensure your code complies with the following security checklist:

1. Endpoint extracts tenant/user identity from request.state (derived from JWT) rather than trusting client parameters.

2.  Database lookups include strict tenant scoping.

3. Request bodies are validated using explicit Pydantic schemas (preventing mass assignment).

4. All automated tests in tests/ pass successfully.

