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
SESSION_TIMEOUT = 300  # 5 minutes in seconds

# Session state
current_session = {
    "email": None,
    "role": None,
    "last_activity": None
}

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

def validate_password(password):
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if not re.search(r'[A-Z]', password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r'[a-z]', password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r'[0-9]', password):
        raise ValueError("Password must contain at least one digit")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValueError("Password must contain at least one special character")

from encrypt_data import encrypt_data, decrypt_data

def login(cursor, email, password):
    current_time = time()
    attempts[email] = [t for t in attempts[email] if current_time - t < TIME_WINDOW]
    if len(attempts[email]) >= MAX_ATTEMPTS:
        print(f"Too many login attempts for {email}. Please wait.")
        logging.warning(f"Rate limit exceeded for email: {email}")
        save_attempts(attempts)
        return False, None
    attempts[email].append(current_time)
    save_attempts(attempts)

    cursor.execute("SELECT password, role FROM customers WHERE email = %s", (email,))
    row = cursor.fetchone()
    if row and row[0]:
        hashed, role = row
        hashed = bytes(hashed)
        if bcrypt.checkpw(password.encode('utf-8'), hashed):
            print("Login successful")
            logging.info(f"Successful login for email: {email}")
            current_session["email"] = email
            current_session["role"] = role
            current_session["last_activity"] = time()
            return True, role
        else:
            print("Login failed: Incorrect password")
            logging.warning(f"Failed login attempt for email: {email} - Incorrect password")
            return False, None
    else:
        print("Login failed: Email not found")
        logging.warning(f"Failed login attempt - Email not found: {email}")
        return False, None

def reset_password(cursor, conn, email):
    cursor.execute("SELECT id FROM customers WHERE email = %s", (email,))
    row = cursor.fetchone()
    if not row:
        print("Email not found")
        logging.warning(f"Password reset attempt - Email not found: {email}")
        return False

    new_password = input("Enter new password: ")
    validate_password(new_password)
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    cursor.execute(
        "UPDATE customers SET password = %s WHERE email = %s",
        (hashed_password, email)
    )
    cursor.execute(
        "INSERT INTO audit_log (operation, email) VALUES (%s, %s)",
        ("PASSWORD_RESET", email)
    )
    conn.commit()
    print("Password reset successfully")
    logging.info(f"Password reset for email: {email}")
    return True

def view_all_users(cursor, key):
    cursor.execute("SELECT name, email, encrypted_data, role FROM customers")
    rows = cursor.fetchall()
    if not rows:
        print("No users found.")
        return
    print("\nAll Users:")
    for row in rows:
        encrypted_name, email, encrypted_email, role = row
        decrypted_name = decrypt_data(encrypted_name, key)
        decrypted_email = decrypt_data(encrypted_email, key)
        print(f"Name: {decrypted_name if decrypted_name else 'N/A'}, Email: {email}, Decrypted Email: {decrypted_email}, Role: {role}")

def delete_user(cursor, conn, email):
    cursor.execute("SELECT id, role FROM customers WHERE email = %s", (email,))
    row = cursor.fetchone()
    if not row:
        print("User not found.")
        return False
    if row[1] == 'admin':
        print("Cannot delete an admin user.")
        return False

    cursor.execute("DELETE FROM customers WHERE email = %s", (email,))
    cursor.execute(
        "INSERT INTO audit_log (operation, email) VALUES (%s, %s)",
        ("DELETE", email)
    )
    conn.commit()
    print(f"User {email} deleted successfully")
    logging.info(f"User deleted: {email}")
    return True

def check_session():
    if not current_session["email"]:
        return False
    current_time = time()
    if current_time - current_session["last_activity"] > SESSION_TIMEOUT:
        print("Session timed out. Please log in again.")
        logging.info(f"Session timed out for email: {current_session['email']}")
        current_session["email"] = None
        current_session["role"] = None
        current_session["last_activity"] = None
        return False
    current_session["last_activity"] = current_time
    return True

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

    # Main menu
    print("=== Secure Customer Database System ===")
    while True:
        print("\nOptions:")
        print("1. Login")
        print("2. Reset Password")
        print("3. Register New User")
        print("4. Exit")
        choice = input("Enter your choice (1-4): ")

        if choice == '1':
            print("\n=== User Login ===")
            email = input("Enter email: ")
            validate_email(email)
            password = input("Enter password: ")

            success, role = login(cursor, email, password)
            if success:
                cursor.execute("SELECT name, email, encrypted_data, password FROM customers WHERE email = %s", (email,))
                row = cursor.fetchone()
                if row:
                    encrypted_name, email, encrypted_email, hashed = row
                    decrypted_name = decrypt_data(encrypted_name, key)
                    decrypted_email = decrypt_data(encrypted_email, key)
                    print(f"\nUser Data:")
                    print(f"Name: {decrypted_name if decrypted_name else 'N/A'}, Email: {email}, Decrypted Email: {decrypted_email}")
                    print("Password verified successfully")
            else:
                print("Access denied.")

        elif choice == '2':
            print("\n=== Password Reset ===")
            email = input("Enter email: ")
            validate_email(email)
            reset_password(cursor, conn, email)

        elif choice == '3':
            print("\n=== Register New User ===")
            name = input("Enter name: ")
            sanitize_name(name)
            email = input("Enter email: ")
            validate_email(email)
            password = input("Enter password: ")
            validate_password(password)
            role = input("Enter role (user/admin, default is user): ").lower() or 'user'
            if role not in ['user', 'admin']:
                print("Invalid role. Defaulting to 'user'.")
                role = 'user'

            encrypted_name = encrypt_data(name, key)
            encrypted_email = encrypt_data(email, key)
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            try:
                cursor.execute(
                    "INSERT INTO customers (name, email, encrypted_data, password, role) VALUES (%s, %s, %s, %s, %s)",
                    (encrypted_name, email, encrypted_email, hashed_password, role)
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

        elif choice == '4':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")

        # Admin menu after login
        if current_session["email"] and check_session():
            if current_session["role"] == 'admin':
                while True:
                    print("\nAdmin Options:")
                    print("1. View All Users")
                    print("2. Delete User")
                    print("3. Back to Main Menu")
                    admin_choice = input("Enter your choice (1-3): ")
                    if not check_session():
                        break
                    if admin_choice == '1':
                        view_all_users(cursor, key)
                    elif admin_choice == '2':
                        email_to_delete = input("Enter email of user to delete: ")
                        validate_email(email_to_delete)
                        delete_user(cursor, conn, email_to_delete)
                    elif admin_choice == '3':
                        break
                    else:
                        print("Invalid choice. Please try again.")

except Exception as e:
    print(f"Error: {e}")
finally:
    cursor.close()
    conn.close()