# Fake Data Prevention with Conventional Cryptotools

System Security project (UniMe) focused on protecting financial transaction data against:
- fabrication
- modification
- replay

The repository contains a complete demo stack:
- core cryptographic pipeline (`main.py`, `src/`)
- Flask API (`api/`)
- dashboard frontend (`frontend/index.html`)
- unit tests (`tests/`)

## Project Structure

```text
fake-data-prevention/
├── main.py
├── requirements.txt
├── README.md
├── api/
│   ├── app.py
│   ├── db.py
│   ├── crypto_service.py
│   ├── requirements.txt
│   └── wsgi.py
├── src/
│   ├── crypto_engine.py
│   ├── pipeline.py
│   ├── merkle.py
│   ├── multiparty.py
│   └── visualizer.py
├── data/
│   ├── generate_dataset.py
│   └── transactions.csv
├── frontend/
│   └── index.html
├── tests/
│   ├── test_crypto_service.py
│   ├── test_db.py
│   ├── test_merkle.py
│   └── test_multiparty.py
└── output/
```

## Main Security Concepts

- **SHA-256 Digest**: detects any transaction field modification.
- **Signatures**: protects authenticity and prevents forged records.
- **JWT claims (`exp`, `jti`)**: supports replay-risk reduction.
- **Merkle Root**: integrity snapshot for a set of transactions.
- **Multi-party chain**: sequential approvals (Alice -> Bob -> Charlie).

## Local Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r api/requirements.txt
```

## Run Tests

```bash
python3 -m unittest discover -s tests -v
```

Or with make:

```bash
make test
```

## Run Core Pipeline

```bash
python3 main.py
```

Output artifacts are generated in `output/` (JSON and charts).

## Run API

```bash
python3 api/app.py
```

Default API base URL:
- `http://localhost:5000`

If port `5000` is busy:

```bash
PORT=5050 python3 api/app.py
```

Or with make:

```bash
make api
```

## API Endpoints

- `GET /api/health`
- `POST /api/sign`
- `POST /api/verify`
- `GET /api/transactions`
- `GET /api/transactions/verified`
- `GET /api/stats`
- `GET /api/attack_logs`
- `GET /api/merkle/root`
- `POST /api/multiparty/init`
- `POST /api/multiparty/sign/<tx_id>`
- `GET /api/multiparty/<tx_id>`

## Run Frontend

Recommended (avoid `file://` CORS issues):

```bash
cd frontend
python3 -m http.server 8080
```

Then open:
- `http://localhost:8080/index.html`

If API runs on non-default port (for example `5050`), set in browser console:

```js
localStorage.setItem('FDP_API_BASE', 'http://localhost:5050');
location.reload();
```

## Quick Demo Flow (for presentation)

1. Start API: `python3 api/app.py` (or `PORT=5050 ...`).
2. Open dashboard and check Overview + Transaction Log.
3. Use `/api/sign` and `/api/verify` once for valid case.
4. Repeat `/api/verify` with changed `amount_eur` to show modification detection.
5. Open Merkle tab and refresh root.
6. Open Multi-Party tab: init Alice, then Bob and Charlie signatures.
