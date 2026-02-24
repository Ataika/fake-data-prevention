# Project Gap Checklist

## Already covered
- End-to-end crypto pipeline (digest/signature/JWT/encryption)
- API split by layers (`app.py`, `db.py`, `crypto_service.py`)
- Frontend connected to API with fallback mode
- Merkle root endpoint and dashboard panel
- Multi-party chain endpoints and dashboard panel
- Automated unit tests for crypto/db/merkle/multiparty

## Partially covered
- Production deployment hardening
  - Has env config + request size limits
  - Missing: reverse proxy, TLS, WAF, proper secrets manager
- Replay controls
  - Has `exp` and `jti` in payload
  - Missing: persistent nonce/jti blacklist store
- Monitoring
  - Has API logs/attack_logs table
  - Missing: metrics, alerts, centralized observability

## Missing for full production
- Authentication/authorization on API endpoints
- Rate limiting per IP/user
- PostgreSQL migration and schema migrations
- CI pipeline with dependency scan + SAST
- Integration tests with running Flask app
- Threat model document (assets, actors, trust boundaries)

## Submission readiness verdict
- Exam/demo readiness: **Yes**
- Industrial production readiness: **Baseline only**, requires hardening items above.

