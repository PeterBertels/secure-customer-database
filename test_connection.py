import psycopg2
from Crypto.Cipher import AES
import os
import re
import bcrypt
import logging
from collections import defaultdict
from time import time
import json

# Configure logging
logging.basicConfig(filename='security.log', level=logging.INFO)

# Rate limiting setup
MAX_ATTEMPTS = 5
TIME_WINDOW = 60  # 60 seconds

# Load attempts from file (if exists)
def load_attempts():
    try:
        with open('attempts.json', 'r') as f:
            data = json.load(f)
            return defaultdict(list, {k: [float(t) for t in v] for k, v in data.items()})
    except (FileNotFoundError, json.JSONDecodeError):
        return defaultdict(list)

# Save attempts to file
def save_attempts(attempts):
    with open('attempts.json', 'w') as f:
        json.dump({k: v for k, v in attempts.items()}, f)

attempts = load_attempts()

def validate_email(email):
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(pattern, email):
        logging.error(f"Invalid email attempt: {email}")
        raise ValueError("Invalid email format")

def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return nonce + ciphertext + tag

def decrypt_data(encrypted_data, key):
    if encrypted_data is None:
        return None
    nonce = encrypted_data[:16]
    tag = encrypted_data[-16:]
    ciphertext = encrypted_data[16:-16]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

try:
    key = bytes.fromhex(os.getenv("ENCRYPTION_KEY"))

    conn = psycopg2.connect(
        dbname="postgres",
        user="postgres",
        password="mysecretpassword",
        host="localhost",
        port="5432"
    )
    cursor = conn.cursor()

    # Encrypt the email
    email = "john@example.com"
    validate_email(email)
    encrypted_email = encrypt_data(email, key)

    # Hash the password
    password = "mypassword"
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert into database, handle duplicate emails
    try:
        cursor.execute(
            "INSERT INTO customers (name, email, encrypted_data, password) VALUES (%s, %s, %s, %s)",
            ("John Doe", email, encrypted_email, hashed_password)
        )
    except psycopg2.errors.UniqueViolation:
        print(f"Email {email} already exists")
        conn.rollback()
    else:
        conn.commit()

    # Retrieve and decrypt
    cursor.execute("SELECT name, email, encrypted_data, password FROM customers")
    rows = cursor.fetchall()
    for row in rows:
        name, email, encrypted, hashed = row
        decrypted_email = decrypt_data(encrypted, key)
        print(f"Name: {name}, Email: {email}, Decrypted Email: {decrypted_email}")

        # Rate limiting for password verification
        current_time = time()
        attempts[email] = [t for t in attempts[email] if current_time - t < TIME_WINDOW]
        if len(attempts[email]) >= MAX_ATTEMPTS:
            print(f"Too many password attempts for {email}. Please wait.")
            logging.warning(f"Rate limit exceeded for email: {email}")
            save_attempts(attempts)
            continue
        attempts[email].append(current_time)
        save_attempts(attempts)

        # Verify password
        if hashed:
            hashed_bytes = bytes(hashed)
            if bcrypt.checkpw(password.encode('utf-8'), hashed_bytes):
                print("Password verified successfully")
            else:
                print("Password verification failed")
                logging.warning(f"Failed password attempt for email: {email}")
        else:
            print("No password set for this record")

except Exception as e:
    print(f"Error: {e}")
finally:
    cursor.close()
    conn.close()