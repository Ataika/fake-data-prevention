#  Fake Data Prevention with Conventional Cryptotools

> **System Security Project** — Università degli Studi di Messina, Data Analysis  
> Academic Year 2025/2026

---

## Overview

This project implements a **complete cryptographic pipeline** to prevent two fundamental data integrity threats:

| Threat | Description | Tool Used |
|--------|-------------|-----------|
| **Fabrication** | An attacker creates fake data and injects it as if it were legitimate | Digital Signature + Certificate |
| **Modification** | An attacker intercepts and alters existing data in transit or at rest | Message Digest (SHA-256) |
| **Replay** | An attacker reuses a previously captured valid token | JWT (`exp` + `jti` claims) |

The project applies these tools to a **real-world scenario**: protecting a dataset of 100 synthetic bank transactions through the full pipeline of signing, encryption, attack simulation, and verification.

---

## Architecture

```
SENDER SIDE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CSV Row → SHA-256 Digest → RSA-PSS Signature → JWT (RS256)
                                              → AES-256-CBC Encrypt
                                              → SQLite DB Storage

ATTACK SIMULATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Attack A: Fabrication  — inject forged row with attacker's key
Attack B: Modification — flip bytes in encrypted ciphertext
Attack C: Replay       — duplicate a valid row under new ID

RECEIVER SIDE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DB Row → Certificate Validate → AES Decrypt → JWT Verify (RS256)
       → SHA-256 Recompute → RSA-PSS Verify → ✅ VALID or ❌ FAKE
```

---

## Project Structure

```
fake-data-prevention/
├── main.py                     ← Entry point (run this)
├── requirements.txt
├── README.md
│
├── src/
│   ├── crypto_engine.py        ← RSA keys, X.509 certs, SHA-256, RSA-PSS, JWT, AES
│   ├── pipeline.py             ← Sender pipeline, attack simulation, verifier
│   └── visualizer.py          ← All charts and figures
│
├── data/
│   ├── generate_dataset.py     ← Synthetic transaction generator
│   └── transactions.csv        ← 100 synthetic bank transactions (auto-generated)
│
├── frontend/
│   └── index.html              ← Dashboard (open in browser, reads results.json)
│
├── keys/                       ← RSA PEM files (auto-generated, not committed)
│
└── output/                     ← Generated at runtime
    ├── transactions_protected.db
    ├── results.json
    ├── chart_overview.png
    ├── chart_pie.png
    ├── chart_dataflow.png
    └── chart_heatmap.png
```

---

## Cryptographic Tools

### 1. Message Digest — `hashlib.sha256`
Every transaction row is serialised to canonical JSON (sorted keys) and hashed with SHA-256. Any modification to even a single character produces a completely different hash.

### 2. Digital Signature — `RSA-PSS` (via `cryptography` library)
The SHA-256 digest is signed with the sender's 2048-bit RSA private key using the PSS padding scheme. The receiver verifies with the public key extracted from the X.509 certificate.

### 3. X.509 Certificate — `cryptography.x509`
A self-signed certificate binds the sender's identity to their public key. In production this would be issued by a Certificate Authority (CA). The receiver validates the certificate before trusting the embedded public key.

### 4. JWT — `PyJWT` with RS256
The transaction data, digest, and RSA signature are packaged into a JWT signed with RS256 (RSA + SHA-256). The `exp` claim limits token lifetime; the `jti` (JWT ID) claim is a unique identifier that prevents replay attacks.

### 5. Hybrid Encryption — `AES-256-CBC` + `RSA-OAEP`
The JWT string is encrypted with a random 256-bit AES session key (CBC mode). The session key itself is encrypted with the recipient's RSA public key using OAEP padding. Only the intended recipient can recover the session key and decrypt the JWT.

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/fake-data-prevention.git
cd fake-data-prevention

# 2. Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the full pipeline
python main.py

# 5. Open the dashboard
# Copy output/results.json to frontend/
cp output/results.json frontend/
# Then open frontend/index.html in your browser
```

---

## Expected Output

```
════════════════════════════════════════════════════════════════════════
  STEP 1 — Key Generation & Certificates
════════════════════════════════════════════════════════════════════════
  [OK] Sender RSA-2048 key-pair generated
  [OK] Sender X.509 certificate created (self-signed, valid 365 days)

  ...

════════════════════════════════════════════════════════════════════════
  STEP 6 — Verification Report
════════════════════════════════════════════════════════════════════════
  Total rows verified  : 103
  ✅ Valid             : 100
  ❌ Modification      :   1
  ❌ Fabrication       :   1
  ❌ Replay            :   1
  Detection rate       : 100.0% of injected attacks caught
```

---

## Dependencies

```
cryptography>=42.0.0
PyJWT>=2.8.0
matplotlib>=3.8.0
pandas>=2.1.0
reportlab>=4.0.0
```

---

## Security Design Decisions

- **RSA-PSS over PKCS1v15**: PSS is probabilistic and resistant to chosen-message attacks; preferred for new systems.
- **Hybrid encryption**: RSA is computationally expensive for large payloads; AES-256 is used for the data, RSA-OAEP for the key exchange.
- **Canonical JSON**: `json.dumps(..., sort_keys=True)` ensures the SHA-256 digest is deterministic regardless of key insertion order.
- **jti claim**: Each JWT gets a UUID v4 token ID. A production system would maintain a seen-jti store to detect replays even within the validity window.
- **Self-signed certificates**: Acceptable for academic demonstration. In production: use certificates from a real CA (e.g., Let's Encrypt, internal enterprise CA).

---

## Author

Student Project — System Security  
Università degli Studi di Messina  
Faculty of Science — Data Analysis  
Academic Year 2025/2026
