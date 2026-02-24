# Professor Report
## Fake Data Prevention with Conventional Cryptotools

### 1. Abstract
This project presents a practical system-security implementation for protecting financial transaction data against three threat classes: fabrication, modification, and replay.  
The solution combines cryptographic controls (digest/signature/token checks), a verification backend API, and an interactive dashboard for live analysis.  
Two additional modules extend the baseline: Merkle-root dataset integrity and a multi-party signature chain workflow.

### 2. Problem Statement
Transactional records are often assumed trustworthy after insertion, but they can be:
- forged by unauthorized entities (fabrication),
- altered after creation (modification),
- re-submitted from previously valid artifacts (replay).

The objective is to provide cryptographic evidence that records are authentic and unchanged, and to detect attack attempts deterministically.

### 3. Objectives
- Implement an end-to-end secure transaction verification flow.
- Detect fabrication/modification/replay conditions with explicit verdicts.
- Provide API endpoints and visual analytics for reproducible demonstrations.
- Extend integrity guarantees with Merkle tree root computation.
- Demonstrate sequential approval via multi-party signature chain.

### 4. System Architecture
#### 4.1 Core Pipeline
Sender side:
`transaction -> canonical representation -> SHA-256 digest -> signature -> token -> encrypted storage`

Verifier side:
`retrieve -> decrypt/parse -> token checks -> digest recomputation -> signature validation -> verdict`

#### 4.2 API Layer
Main components:
- `api/app.py` (routes/orchestration)
- `api/db.py` (persistence/statistics)
- `api/crypto_service.py` (validation, digest/signature helpers)

Main endpoints:
- `/api/health`
- `/api/sign`
- `/api/verify`
- `/api/transactions`
- `/api/transactions/verified`
- `/api/stats`
- `/api/attack_logs`
- `/api/merkle/root`
- `/api/multiparty/init`
- `/api/multiparty/sign/<tx_id>`
- `/api/multiparty/<tx_id>`

#### 4.3 Frontend
Dashboard tabs:
- Overview
- Transaction Log
- Attack Simulator
- Merkle Integrity
- Multi-Party Chain

The frontend operates in API-first mode and has fallback behavior for local demo data.

### 5. Cryptographic Rationale
- **SHA-256**: deterministic integrity fingerprint; any data change changes digest.
- **Signature checks**: authenticity and anti-fabrication.
- **JWT claims (`exp`, `jti`)**: replay-window reduction and token identity semantics.
- **Merkle root**: compact integrity commitment for a set of transactions.
- **Multi-party chain**: staged approval model where each signer extends a validated chain state.

### 6. Security Testing and Validation
Performed validation:
- module-level syntax checks,
- unit tests for crypto/db/merkle/multiparty modules,
- API functional checks (`health`, `sign`, `verify`),
- positive and negative verification scenarios (valid vs tampered payload),
- multi-party chain full scenario (Alice -> Bob -> Charlie, valid chain).

Observed expected results:
- valid transaction is accepted,
- tampered transaction triggers modification verdict,
- multi-party chain reaches valid state with 3 signatures.

### 7. Threat Coverage
- **Fabrication**: detected via signature verification inconsistencies.
- **Modification**: detected via digest mismatch.
- **Replay**: constrained via token semantics (`exp`, `jti`) and verification logic.

### 8. Deliverables
- Source code repository (GitHub)
- API backend + frontend dashboard
- tests (`tests/`)
- documentation (`docs/`)
- generated dataset and output artifacts

### 9. Limitations and Future Work
Current project scope is exam-ready and demonstrable, but not enterprise-complete.  
Potential improvements:
- API authN/authZ,
- rate limiting,
- PostgreSQL migration + migrations,
- persistent anti-replay `jti` store,
- TLS/reverse proxy hardening,
- CI/CD + security scanning + observability stack.

### 10. Conclusion
The project demonstrates a complete and testable security workflow that maps concrete cryptographic mechanisms to explicit threat classes.  
It is suitable for academic evaluation due to reproducibility, practical demonstration capability, and clear security rationale.

