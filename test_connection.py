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

def sanitize_name(name):
    if not re.match(r'^[a-zA-Z\s-]+$', name):
        logging.error(f"Invalid name attempt: {name}")
        raise ValueError("Invalid name format (only letters, spaces, and hyphens allowed)")

def validate_email(email):
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(pattern, email):
        logging.error(f"Invalid email attempt: {email}")
        raise ValueError("Invalid email format")

from encrypt_data import encrypt_data, decrypt_data

def login(cursor, email, password):
    # Rate limiting for login attempts
    current_time = time()
    attempts[email] = [t for t in attempts[email] if current_time - t < TIME_WINDOW]
    if len(attempts[email]) >= MAX_ATTEMPTS:
        print(f"Too many login attempts for {email}. Please wait.")
        logging.warning(f"Rate limit exceeded for email: {email}")
        save_attempts(attempts)
        return False
    attempts[email].append(current_time)
    save_attempts(attempts)

    # Verify credentials
    cursor.execute("SELECT password FROM customers WHERE email = %s", (email,))
    row = cursor.fetchone()
    if row and row[0]:
        hashed = bytes(row[0])  # Convert memoryview to bytes
        if bcrypt.checkpw(password.encode('utf-8'), hashed):
            print("Login successful")
            logging.info(f"Successful login for email: {email}")
            return True
        else:
            print("Login failed: Incorrect password")
            logging.warning(f"Failed login attempt for email: {email} - Incorrect password")
            return False
    else:
        print("Login failed: Email not found")
        logging.warning(f"Failed login attempt - Email not found: {email}")
        return False

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

    # Prompt for login
    print("=== User Login ===")
    email = input("Enter email: ")
    validate_email(email)  # Validate email format
    password = input("Enter password: ")

    # Attempt to log in
    if login(cursor, email, password):
        # If login is successful, display user data
        cursor.execute("SELECT name, email, encrypted_data, password FROM customers WHERE email = %s", (email,))
        row = cursor.fetchone()
        if row:
            name, email, encrypted, hashed = row
            decrypted_email = decrypt_data(encrypted, key)
            print(f"\nUser Data:")
            print(f"Name: {name}, Email: {email}, Decrypted Email: {decrypted_email}")
            print("Password verified successfully")
    else:
        print("Access denied.")

    # Optionally insert new user (for testing purposes)
    print("\n=== Register New User ===")
    insert_new = input("Would you like to register a new user? (y/n): ").lower()
    if insert_new == 'y':
        name = input("Enter name: ")
        sanitize_name(name)
        email = input("Enter email: ")
        validate_email(email)
        password = input("Enter password: ")

        encrypted_email = encrypt_data(email, key)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            cursor.execute(
                "INSERT INTO customers (name, email, encrypted_data, password) VALUES (%s, %s, %s, %s)",
                (name, email, encrypted_email, hashed_password)
            )
            cursor.execute(
                "INSERT INTO audit_log (operation, email) VALUES (%s, %s)",
                ("INSERT", email)
            )
            conn.commit()
            print("User registered successfully")
        except psycopg2.errors.UniqueViolation:
            print(f"Email {email} already exists")
            conn.rollback()

except Exception as e:
    print(f"Error: {e}")
finally:
    cursor.close()
    conn.close()