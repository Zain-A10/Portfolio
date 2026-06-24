import pandas as pd
import random
from datetime import datetime, timedelta

rows = []

merchant_categories = [
    "Electronics",
    "Grocery",
    "Restaurant",
    "Gas",
    "Retail",
    "Travel"
]

states = [
    "NY",
    "CA",
    "TX",
    "FL",
    "IL"
]

payment_methods = [
    "Credit Card",
    "Debit Card",
    "Mobile Wallet"
]

fraud_types = [
    "Stolen Card",
    "Account Takeover",
    "Friendly Fraud"
]

for i in range(5000):

    fraud = random.random() < 0.04

    rows.append({
        "customer_id": random.randint(1000, 1500),
        "merchant_id": random.randint(200, 250),
        "merchant_category": random.choice(merchant_categories),
        "transaction_amount": round(random.uniform(5, 2000), 2),
        "transaction_date": (
            datetime.now()
            - timedelta(days=random.randint(0, 365))
        ).date(),
        "transaction_time": f"{random.randint(0,23):02}:{random.randint(0,59):02}:00",
        "state": random.choice(states),
        "payment_method": random.choice(payment_methods),
        "transaction_status": "Approved",
        "is_fraud": fraud,
        "fraud_type": random.choice(fraud_types) if fraud else "None"
    })

df = pd.DataFrame(rows)

df.to_csv("transactions.csv", index=False)

print("transactions.csv created")