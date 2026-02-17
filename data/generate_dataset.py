"""
Dataset Generator — Synthetic Financial Transactions
Generates a realistic CSV of 100 bank transactions for the project demo.
"""

import csv
import random
import datetime
import os

random.seed(42)

SENDERS = [
    "Alice Rossi", "Marco Bianchi", "Giulia Ferrari",
    "Luca Esposito", "Sara Conti", "Ahmed Malik",
    "Chen Wei", "Fatima Al-Sayed", "Ivan Petrov", "Ana Garcia"
]

RECIPIENTS = [
    "UniMe Fees Office", "Enel Energia", "Amazon IT",
    "Lidl Messina", "Trenitalia", "Vodafone IT",
    "PayPal Europe", "Netflix IT", "Rent — Via Roma 14", "Insurance Plus"
]

CATEGORIES = ["Utilities", "Education", "Retail", "Transport", "Rent", "Telecom", "Streaming", "Insurance"]

BANKS = ["Unicredit", "Intesa Sanpaolo", "BNL", "BPER", "Fineco", "ING Direct"]

def generate_transactions(n=100):
    transactions = []
    base_date = datetime.date(2024, 1, 1)

    for i in range(n):
        delta_days = random.randint(0, 364)
        tx_date = base_date + datetime.timedelta(days=delta_days)
        tx_time = datetime.time(
            random.randint(6, 22),
            random.randint(0, 59),
            random.randint(0, 59)
        )
        amount = round(random.uniform(5.00, 4500.00), 2)
        sender = random.choice(SENDERS)
        recipient = random.choice([r for r in RECIPIENTS])

        tx = {
            "tx_id":        f"TXN-2024-{str(i+1).zfill(4)}",
            "timestamp":    f"{tx_date}T{tx_time.strftime('%H:%M:%S')}",
            "sender":       sender,
            "sender_iban":  f"IT{random.randint(10,99)}{''.join([str(random.randint(0,9)) for _ in range(23)])}",
            "recipient":    recipient,
            "recipient_iban": f"IT{random.randint(10,99)}{''.join([str(random.randint(0,9)) for _ in range(23)])}",
            "amount_eur":   amount,
            "currency":     "EUR",
            "category":     random.choice(CATEGORIES),
            "bank":         random.choice(BANKS),
            "status":       "COMPLETED",
            "note":         f"Payment ref #{random.randint(100000, 999999)}"
        }
        transactions.append(tx)

    # Sort by date
    transactions.sort(key=lambda x: x["timestamp"])
    return transactions


if __name__ == "__main__":
    out_path = os.path.join(os.path.dirname(__file__), "transactions.csv")
    txns = generate_transactions(100)

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=txns[0].keys())
        writer.writeheader()
        writer.writerows(txns)

    print(f"[OK] Dataset generated: {len(txns)} transactions → {out_path}")
