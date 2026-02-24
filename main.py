#!/usr/bin/env python3
"""
main.py
=======
Entry point for the Fake Data Prevention demo.

Usage:
    python main.py

What it does:
  1. Generates RSA key-pairs and X.509 certificates for sender + attacker
  2. Generates a synthetic financial transaction dataset (100 rows)
  3. Signs, packages (JWT), and encrypts every row -> stores in SQLite DB
  4. Simulates three attack types: Fabrication, Modification, Replay
  5. Runs the full verifier on every row in the DB
  6. Prints a detailed report to the console
  7. Generates four visualisation charts
  8. Exports a JSON summary to output/results.json
"""

import os
import sys
import json
import datetime

# Paths
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
SRC_DIR   = os.path.join(BASE_DIR, "src")
DATA_DIR  = os.path.join(BASE_DIR, "data")
KEYS_DIR  = os.path.join(BASE_DIR, "keys")
OUT_DIR   = os.path.join(BASE_DIR, "output")
DB_PATH   = os.path.join(OUT_DIR, "transactions_protected.db")
CSV_PATH  = os.path.join(DATA_DIR, "transactions.csv")

sys.path.insert(0, SRC_DIR)
sys.path.insert(0, DATA_DIR)

os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(OUT_DIR,  exist_ok=True)

from crypto_engine   import generate_rsa_keypair, save_keypair, create_certificate
from pipeline        import (
    init_db, run_sender, run_verifier,
    attack_fabrication, attack_modification, attack_replay,
    VERIFY_OK, VERIFY_TAMPER, VERIFY_FAKE, VERIFY_REPLAY, VERIFY_CERT
)
from visualizer      import generate_all_charts
from generate_dataset import generate_transactions

import csv


# -----------------------------------------------------------------------------
#  HELPERS
# -----------------------------------------------------------------------------

def banner(text: str):
    width = 72
    print("\n" + "=" * width)
    print(f"  {text}")
    print("=" * width)


def print_result(r: dict):
    icon = "[OK]" if r["status"] == VERIFY_OK else "[FAIL]"
    print(f"  {icon}  {r['tx_id']:<22}  {r['status']:<32}  "
          f"sender={r.get('sender') or 'N/A':<18}  "
          f"amount={str(r.get('amount') or 'N/A'):<10}")
    if r["error"]:
        print(f"       -> {r['error']}")


# -----------------------------------------------------------------------------
#  MAIN
# -----------------------------------------------------------------------------

def main():
    start_time = datetime.datetime.now()

    # -- 1. KEY & CERTIFICATE GENERATION --------------------------------------
    banner("STEP 1 - Key Generation & Certificates")

    sender_priv, sender_pub = generate_rsa_keypair()
    save_keypair(sender_priv, os.path.join(KEYS_DIR, "sender"))
    sender_cert = create_certificate(sender_priv, "BankSecureGateway")
    print("  [OK] Sender RSA-2048 key-pair generated")
    print("  [OK] Sender X.509 certificate created (self-signed, valid 365 days)")

    # Attacker uses their own key (different from sender's)
    attacker_priv, _ = generate_rsa_keypair()
    attacker_cert = create_certificate(attacker_priv, "AttackerNode")
    print("  [OK] Attacker RSA key-pair generated (for attack simulation)")

    # -- 2. DATASET GENERATION ------------------------------------------------
    banner("STEP 2 - Dataset Generation")

    if not os.path.exists(CSV_PATH):
        txns = generate_transactions(100)
        with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=txns[0].keys())
            writer.writeheader()
            writer.writerows(txns)
        print(f"  [OK] Generated 100 synthetic financial transactions -> {CSV_PATH}")
    else:
        with open(CSV_PATH) as f:
            n = sum(1 for _ in f) - 1
        print(f"  [OK] Dataset already exists: {n} transactions -> {CSV_PATH}")

    # -- 3. SENDER: SIGN & ENCRYPT ALL ROWS -----------------------------------
    banner("STEP 3 - Sender Pipeline (Sign -> JWT -> Encrypt -> Store)")

    conn = init_db(DB_PATH)
    tx_ids = run_sender(CSV_PATH, conn, sender_priv, sender_cert, sender_pub)
    print(f"  [OK] {len(tx_ids)} transactions signed, packaged into JWT, AES-encrypted -> DB")

    # -- 4. ATTACK SIMULATION -------------------------------------------------
    banner("STEP 4 - Attack Simulation")

    # Attack A: Fabrication - attacker injects fake row with wrong key
    fake_id = attack_fabrication(conn, attacker_priv, sender_pub, attacker_cert)
    print(f"  [ATTACK A] Fabrication injected: {fake_id}")
    print(f"             -> Attacker signed with their own key - cert mismatch will be detected")

    # Attack B: Modification - corrupt bytes of two random rows
    target_mod = tx_ids[10]
    attack_modification(conn, target_mod)
    print(f"  [ATTACK B] Modification applied to: {target_mod}")
    print(f"             -> AES ciphertext bytes flipped - decryption / digest check will detect")

    # Attack C: Replay - duplicate a valid row
    replay_id = attack_replay(conn, tx_ids[25])
    print(f"  [ATTACK C] Replay injected: {replay_id}")
    print(f"             -> JWT jti uniqueness & exp will flag this as duplicate")

    # -- 5. RECEIVER VERIFICATION ---------------------------------------------
    banner("STEP 5 - Receiver Verification Pipeline")

    results = run_verifier(conn, sender_priv)  # sender_priv doubles as receiver in demo

    # -- 6. CONSOLE REPORT ----------------------------------------------------
    banner("STEP 6 - Verification Report")

    valid_n   = sum(1 for r in results if r["status"] == VERIFY_OK)
    tamper_n  = sum(1 for r in results if r["status"] == VERIFY_TAMPER)
    fake_n    = sum(1 for r in results if r["status"] == VERIFY_FAKE)
    replay_n  = sum(1 for r in results if r["status"] == VERIFY_REPLAY)
    cert_n    = sum(1 for r in results if r["status"] == VERIFY_CERT)
    total     = len(results)

    # Print compromised rows first
    print("\n  -- Compromised / Attacked Transactions ---------------------")
    compromised = [r for r in results if r["status"] != VERIFY_OK]
    for r in compromised:
        print_result(r)

    print(f"\n  -- Summary -------------------------------------------------")
    print(f"  Total rows verified  : {total}")
    print(f"  [OK] Valid             : {valid_n}")
    print(f"  [FAIL] Modification      : {tamper_n}")
    print(f"  [FAIL] Fabrication       : {fake_n}")
    print(f"  [FAIL] Replay            : {replay_n}")
    print(f"  [FAIL] Invalid Cert      : {cert_n}")
    print(f"  Threats detected     : {total - valid_n} / {total}")
    print(f"  Detection rate       : {((total - valid_n) / max(total - valid_n, 1)) * 100:.1f}% of injected attacks caught")

    elapsed = (datetime.datetime.now() - start_time).total_seconds()
    print(f"  Total execution time : {elapsed:.2f}s")

    # -- 7. CHARTS ------------------------------------------------------------
    banner("STEP 7 - Generating Visualisations")
    chart_paths = generate_all_charts(results, OUT_DIR)
    for name, path in chart_paths.items():
        print(f"  [chart] {name:<12} -> {path}")

    # -- 8. JSON EXPORT -------------------------------------------------------
    json_path = os.path.join(OUT_DIR, "results.json")
    export = {
        "generated_at": start_time.isoformat(),
        "total": total,
        "valid": valid_n,
        "modification": tamper_n,
        "fabrication": fake_n,
        "replay": replay_n,
        "invalid_cert": cert_n,
        "results": [
            {k: v for k, v in r.items() if k != "error" or v is not None}
            for r in results
        ]
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(export, f, indent=2, default=str)

    banner("DONE [OK]")
    print(f"  Results JSON  : {json_path}")
    print(f"  Charts        : {OUT_DIR}/chart_*.png")
    print(f"  Database      : {DB_PATH}")
    print()


if __name__ == "__main__":
    main()
