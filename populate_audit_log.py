"""
Script to populate the audit_log table with sample data for benchmarking.

This script inserts 1,000,000 entries with a mix of operations (PASSWORD_RESET, INSERT, DELETE)
and timestamps spanning 90 days.
"""

import psycopg2
from datetime import datetime, timedelta
import random

# Connect to the PostgreSQL database
conn = psycopg2.connect(
    dbname="postgres",
    user="postgres",
    password="mysecretpassword",
    host="localhost",
    port="5432"
)
cursor = conn.cursor()

# Clear the audit_log table
cursor.execute("TRUNCATE TABLE audit_log;")

# Define operations and their probabilities
operations = [
    ("PASSWORD_RESET", 0.6),  # 60% of entries
    ("INSERT", 0.2),          # 20% of entries
    ("DELETE", 0.2)           # 20% of entries
]

# Generate 1,000,000 sample entries
start_date = datetime(2025, 5, 1)  # Start date for timestamps
num_entries = 1000000
for i in range(num_entries):
    # Select operation based on probability
    r = random.random()
    cumulative_prob = 0
    operation = None
    for op, prob in operations:
        cumulative_prob += prob
        if r <= cumulative_prob:
            operation = op
            break
    
    # Generate a random timestamp within 90 days from start_date
    days_offset = random.randint(0, 90)
    timestamp = start_date + timedelta(days=days_offset, hours=random.randint(0, 23), minutes=random.randint(0, 59))
    email = f"user{i}@example.com"
    cursor.execute(
        "INSERT INTO audit_log (operation, email, timestamp) VALUES (%s, %s, %s)",
        (operation, email, timestamp)
    )

# Commit the changes
conn.commit()
print(f"Inserted {num_entries} sample entries into audit_log.")

# Clean up
cursor.close()
conn.close()