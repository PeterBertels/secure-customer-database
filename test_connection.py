"""
Secure Customer Database System

This script implements a command-line application for managing customer data in a PostgreSQL database.
It includes features like user authentication with 2FA, AES-256 encryption for sensitive data, password history,
rate limiting, session management, and admin functionalities. Security events are logged to 'security.log', and
user actions are recorded in an audit log table.

Dependencies:
- psycopg2: For PostgreSQL database connectivity.
- pycryptodome: For AES-256 encryption (via encrypt_data.py).
- bcrypt: For secure password hashing.
- logging, json, csv: Standard libraries for logging, persistence, and data export.
"""

import psycopg2
from Crypto.Cipher import AES
import os
import re
import bcrypt
import logging
from collections import defaultdict
from time import time
import json
import csv
import random

# Configure logging to write security events to 'security.log'
logging.basicConfig(filename='security.log', level=logging.INFO)

# Constants for rate limiting, session timeout, and password history
MAX_ATTEMPTS = 5  # Maximum login attempts before rate limiting
TIME_WINDOW = 60  # Time window for rate limiting (in seconds)
SESSION_TIMEOUT = 300  # Session timeout duration (in seconds, 5 minutes)
MAX_PASSWORD_HISTORY = 3  # Number of previous passwords to store in history

# Session state to track the current user
current_session = {
    "email": None,  # Current user's email
    "role": None,   # Current user's role (user/admin)
    "last_activity": None  # Timestamp of last activity for session timeout
}

def load_attempts():
    """
    Load login attempt history from 'attempts.json' for rate limiting.

    Returns:
        defaultdict: A dictionary mapping email addresses to lists of attempt timestamps.
    """
    try:
        with open('attempts.json', 'r') as f:
            data = json.load(f)
            # Convert timestamps to floats for consistency
            return defaultdict(list, {k: [float(t) for t in v] for k, v in data.items()})
    except (FileNotFoundError, json.JSONDecodeError):
        # Return an empty defaultdict if the file doesn't exist or is invalid
        return defaultdict(list)

def save_attempts(attempts):
    """
    Save login attempt history to 'attempts.json' for persistence.

    Args:
        attempts (defaultdict): A dictionary mapping email addresses to lists of attempt timestamps.
    """
    with open('attempts.json', 'w') as f:
        json.dump({k: v for k, v in attempts.items()}, f)

# Initialize login attempts history for rate limiting
attempts = load_attempts()

def sanitize_name(name):
    """
    Sanitize name input to allow only letters, spaces, and hyphens.

    Args:
        name (str): The name to sanitize.

    Raises:
        ValueError: If the name contains invalid characters.
    """
    if not re.match(r'^[a-zA-Z\s-]+$', name):
        logging.error(f"Invalid name attempt: {name}")
        raise ValueError("Invalid name format (only letters, spaces, and hyphens allowed)")

def validate_email(email):
    """
    Validate email format using a regex pattern.

    Args:
        email (str): The email to validate.

    Raises:
        ValueError: If the email format is invalid.
    """
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(pattern, email):
        logging.error(f"Invalid email attempt: {email}")
        raise ValueError("Invalid email format")

def validate_password(password):
    """
    Validate password strength based on defined criteria.

    Args:
        password (str): The password to validate.

    Raises:
        ValueError: If the password does not meet the strength requirements.
    """
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

def check_password_history(cursor, user_id, new_password):
    """
    Check if the new password has been used in the last MAX_PASSWORD_HISTORY entries.

    Args:
        cursor: Database cursor for executing queries.
        user_id (int): The ID of the user.
        new_password (str): The new password to check.

    Raises:
        ValueError: If the password has been used before.
    """
    cursor.execute(
        "SELECT password FROM password_history WHERE user_id = %s ORDER BY created_at DESC LIMIT %s",
        (user_id, MAX_PASSWORD_HISTORY)
    )
    history = cursor.fetchall()
    for (hashed,) in history:
        # Ensure hashed is in bytes format for bcrypt comparison
        hashed = bytes(hashed) if isinstance(hashed, memoryview) else hashed
        if bcrypt.checkpw(new_password.encode('utf-8'), hashed):
            raise ValueError("Password has been used before. Please choose a different password.")

def store_password_history(cursor, conn, user_id, hashed_password):
    """
    Store a new password in the password history and prune older entries.

    Args:
        cursor: Database cursor for executing queries.
        conn: Database connection for committing transactions.
        user_id (int): The ID of the user.
        hashed_password (bytes): The hashed password to store.
    """
    # Ensure hashed_password is in bytes format
    hashed_password = bytes(hashed_password) if isinstance(hashed_password, memoryview) else hashed_password
    # Insert the new password into history and commit
    cursor.execute(
        "INSERT INTO password_history (user_id, password) VALUES (%s, %s) RETURNING id",
        (user_id, hashed_password)
    )
    new_entry_id = cursor.fetchone()[0]
    conn.commit()
    # Count total entries before pruning
    cursor.execute(
        "SELECT COUNT(*) FROM password_history WHERE user_id = %s",
        (user_id,)
    )
    total_entries = cursor.fetchone()[0]
    logging.info(f"Total password history entries before pruning for user_id {user_id}: {total_entries}")
    # Prune history to keep only the latest MAX_PASSWORD_HISTORY entries
    cursor.execute(
        """
        DELETE FROM password_history
        WHERE user_id = %s
        AND id NOT IN (
            SELECT id
            FROM password_history
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT %s
        )
        """,
        (user_id, user_id, MAX_PASSWORD_HISTORY)
    )
    # Log the number of deleted rows
    deleted_rows = cursor.rowcount
    logging.info(f"Pruned {deleted_rows} old password history entries for user_id {user_id}")
    # Count total entries after pruning
    cursor.execute(
        "SELECT COUNT(*) FROM password_history WHERE user_id = %s",
        (user_id,)
    )
    total_entries_after = cursor.fetchone()[0]
    logging.info(f"Total password history entries after pruning for user_id {user_id}: {total_entries_after}")
    conn.commit()

# Import encryption/decryption functions from encrypt_data.py
from encrypt_data import encrypt_data, decrypt_data

def generate_2fa_code():
    """
    Generate a random 6-digit 2FA code.

    Returns:
        str: A 6-digit code as a string.
    """
    code = str(random.randint(100000, 999999))
    return code

def verify_2fa(email):
    """
    Simulate sending a 2FA code and verify user input with 3 attempts.

    Args:
        email (str): The email address for which to generate the 2FA code.

    Returns:
        bool: True if verification is successful, False otherwise.
    """
    # Simulate sending a 2FA code via email by printing to console
    code = generate_2fa_code()
    print(f"[Simulated Email] Your 2FA code for {email} is: {code}")
    logging.info(f"2FA code generated for {email}: {code}")
    
    # Prompt user to enter the code with 3 attempts
    attempts = 3
    while attempts > 0:
        user_code = input(f"Enter the 2FA code sent to {email} (Attempts left: {attempts}): ").strip()
        if user_code == code:
            print("2FA verification successful")
            logging.info(f"2FA verification successful for {email}")
            return True
        else:
            attempts -= 1
            print("Invalid 2FA code. Please try again.")
            logging.warning(f"Failed 2FA attempt for {email}")
    
    print("Too many failed 2FA attempts. Login aborted.")
    logging.warning(f"2FA verification failed for {email} after max attempts")
    return False

def login(cursor, email, password):
    """
    Authenticate a user with email, password, and 2FA; enforce rate limiting.

    Args:
        cursor: Database cursor for executing queries.
        email (str): The email address of the user.
        password (str): The password to verify.

    Returns:
        tuple: (bool, str) indicating success (True/False) and the user's role (or None).
    """
    # Check rate limiting based on recent login attempts
    current_time = time()
    attempts[email] = [t for t in attempts[email] if current_time - t < TIME_WINDOW]
    if len(attempts[email]) >= MAX_ATTEMPTS:
        print(f"Too many login attempts for {email}. Please wait.")
        logging.warning(f"Rate limit exceeded for email: {email}")
        save_attempts(attempts)
        return False, None
    attempts[email].append(current_time)
    save_attempts(attempts)

    # Verify email and password against the database
    cursor.execute("SELECT password, role FROM customers WHERE email = %s", (email,))
    row = cursor.fetchone()
    if row and row[0]:
        hashed, role = row
        hashed = bytes(hashed) if isinstance(hashed, memoryview) else hashed
        if bcrypt.checkpw(password.encode('utf-8'), hashed):
            # Perform 2FA verification after password check
            if not verify_2fa(email):
                return False, None
            print("Login successful")
            logging.info(f"Successful login for email: {email}")
            # Update session state
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

def logout():
    """Log out the current user and clear the session."""
    if current_session["email"]:
        email = current_session["email"]
        # Clear session state
        current_session["email"] = None
        current_session["role"] = None
        current_session["last_activity"] = None
        print("Logged out successfully.")
        logging.info(f"User logged out: {email}")
    else:
        print("No user is currently logged in.")

def reset_password(cursor, conn, email):
    """
    Reset a user's password after validation and store in history.

    Args:
        cursor: Database cursor for executing queries.
        conn: Database connection for committing transactions.
        email (str): The email address of the user.

    Returns:
        bool: True if the password reset is successful, False otherwise.
    """
    # Check if the email exists in the database
    cursor.execute("SELECT id FROM customers WHERE email = %s", (email,))
    row = cursor.fetchone()
    if not row:
        print("Email not found")
        logging.warning(f"Password reset attempt - Email not found: {email}")
        return False

    user_id = row[0]
    # Prompt for a new password with validation
    while True:
        try:
            new_password = input("Enter new password: ")
            validate_password(new_password)
            # Check if the password has been used before
            check_password_history(cursor, user_id, new_password)
            break
        except ValueError as e:
            print(f"Error: {e}")
            print("Please try again.")

    # Hash the new password and update the database
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    cursor.execute(
        "UPDATE customers SET password = %s WHERE email = %s",
        (hashed_password, email)
    )
    # Store the new password in history
    store_password_history(cursor, conn, user_id, hashed_password)
    # Log the password reset action in the audit log
    cursor.execute(
        "INSERT INTO audit_log (operation, email) VALUES (%s, %s)",
        ("PASSWORD_RESET", email)
    )
    conn.commit()
    print("Password reset successfully")
    logging.info(f"Password reset for email: {email}")
    return True

def update_user(cursor, conn, email, key):
    """
    Update a user's profile (e.g., name) after validation.

    Args:
        cursor: Database cursor for executing queries.
        conn: Database connection for committing transactions.
        email (str): The email address of the user.
        key (bytes): The encryption key for encrypting the new name.

    Returns:
        bool: True if the update is successful, False otherwise.
    """
    # Redundant email validation for safety
    try:
        validate_email(email)
    except ValueError as e:
        print(f"Error: {e}")
        logging.error(f"Invalid email in update_user: {email}")
        return False

    # Check if the user exists
    cursor.execute("SELECT id FROM customers WHERE email = %s", (email,))
    row = cursor.fetchone()
    if not row:
        print("User not found.")
        return False

    print("\n=== Update Profile ===")
    # Prompt for a new name with validation
    while True:
        new_name = input("Enter new name (leave blank to keep current): ")
        if not new_name:  # Allow empty input to skip
            print("No changes made.")
            return True
        try:
            sanitize_name(new_name)
            break
        except ValueError as e:
            print(f"Error: {e}")
            print("Please try again.")

    # Encrypt the new name and update the database
    encrypted_name = encrypt_data(new_name, key)
    cursor.execute(
        "UPDATE customers SET name = %s WHERE email = %s",
        (encrypted_name, email)
    )
    # Log the update action in the audit log
    cursor.execute(
        "INSERT INTO audit_log (operation, email) VALUES (%s, %s)",
        ("UPDATE_NAME", email)
    )
    conn.commit()
    print("Profile updated successfully")
    logging.info(f"Profile updated for email: {email}")
    return True

def view_all_users(cursor, key):
    """
    View all users in the database with decrypted data (admin only).

    Args:
        cursor: Database cursor for executing queries.
        key (bytes): The encryption key for decrypting data.
    """
    cursor.execute("SELECT name, email, encrypted_data, role FROM customers")
    rows = cursor.fetchall()
    if not rows:
        print("No users found.")
        return
    print("\nAll Users:")
    for row in rows:
        encrypted_name, email, encrypted_email, role = row
        # Decrypt the name and email data
        decrypted_name = decrypt_data(encrypted_name, key)
        decrypted_email = decrypt_data(encrypted_email, key)
        print(f"Name: {decrypted_name if decrypted_name else 'N/A'}, Email: {email}, Decrypted Email: {decrypted_email}, Role: {role}")

def export_users(cursor, conn, key):
    """
    Export all users to a CSV file with decrypted data (admin only).

    Args:
        cursor: Database cursor for executing queries.
        conn: Database connection for committing transactions.
        key (bytes): The encryption key for decrypting data.
    """
    cursor.execute("SELECT name, email, encrypted_data, role FROM customers")
    rows = cursor.fetchall()
    if not rows:
        print("No users to export.")
        return

    # Create a timestamped CSV file for export
    filename = f"users_export_{int(time())}.csv"
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Name', 'Email', 'Decrypted Email', 'Role'])
        for row in rows:
            encrypted_name, email, encrypted_email, role = row
            # Decrypt the name and email data
            decrypted_name = decrypt_data(encrypted_name, key) if encrypted_name else 'N/A'
            decrypted_email = decrypt_data(encrypted_email, key) if encrypted_email else 'N/A'
            writer.writerow([decrypted_name, email, decrypted_email, role])

    # Log the export action in the audit log
    cursor.execute(
        "INSERT INTO audit_log (operation, email) VALUES (%s, %s)",
        ("EXPORT_USERS", current_session["email"])
    )
    conn.commit()
    print(f"Users exported successfully to {filename}")
    logging.info(f"Users exported by {current_session['email']} to {filename}")

def delete_user(cursor, conn, email):
    """
    Delete a user from the database (admin only, cannot delete admins).

    Args:
        cursor: Database cursor for executing queries.
        conn: Database connection for committing transactions.
        email (str): The email address of the user to delete.

    Returns:
        bool: True if the deletion is successful, False otherwise.
    """
    # Validate the email format
    try:
        validate_email(email)
    except ValueError as e:
        print(f"Error: {e}")
        logging.error(f"Invalid email in delete_user: {email}")
        return False

    # Check if the user exists and their role
    cursor.execute("SELECT id, role FROM customers WHERE email = %s", (email,))
    row = cursor.fetchone()
    if not row:
        print("User not found.")
        return False
    if row[1] == 'admin':
        print("Cannot delete an admin user.")
        return False

    # Delete the user from the database
    cursor.execute("DELETE FROM customers WHERE email = %s", (email,))
    # Log the delete action in the audit log
    cursor.execute(
        "INSERT INTO audit_log (operation, email) VALUES (%s, %s)",
        ("DELETE", email)
    )
    conn.commit()
    print(f"User {email} deleted successfully")
    logging.info(f"User deleted: {email}")
    return True

def analyze_trends(cursor):
    """
    Analyze trends in the audit_log table, focusing on password reset frequency over time (admin only).

    Args:
        cursor: Database cursor for executing queries.
    """
    # Query to count password resets per day
    query = """
    SELECT DATE_TRUNC('day', timestamp) as day, COUNT(*) as reset_count
    FROM audit_log
    WHERE operation = 'PASSWORD_RESET'
    GROUP BY DATE_TRUNC('day', timestamp)
    ORDER BY day;
    """
    cursor.execute(query)
    rows = cursor.fetchall()
    if not rows:
        print("No password reset events found.")
        return
    print("\nPassword Reset Trends (Daily):")
    for row in rows:
        day, count = row
        print(f"Date: {day.date()}, Password Resets: {count}")

def check_session():
    """
    Check if the current session is active; timeout after SESSION_TIMEOUT.

    Returns:
        bool: True if the session is active, False otherwise.
    """
    if not current_session["email"]:
        return False
    current_time = time()
    if current_time - current_session["last_activity"] > SESSION_TIMEOUT:
        print("Session timed out. Please log in again.")
        logging.info(f"Session timed out for email: {current_session['email']}")
        # Clear session state on timeout
        current_session["email"] = None
        current_session["role"] = None
        current_session["last_activity"] = None
        return False
    # Update last activity timestamp
    current_session["last_activity"] = current_time
    return True

try:
    # Load encryption key from environment variable
    key = bytes.fromhex(os.getenv("ENCRYPTION_KEY"))

    # Connect to PostgreSQL database
    conn = psycopg2.connect(
        dbname="postgres",
        user="postgres",
        password="mysecretpassword",
        host="localhost",
        port="5432"
    )
    cursor = conn.cursor()

    # Main menu loop
    print("=== Secure Customer Database System ===")
    while True:
        # Dynamically build menu options based on session state
        menu_options = [
            ("Login", lambda: True),
            ("Reset Password", lambda: True),
            ("Register New User", lambda: True),
            ("Update Profile", lambda: current_session["email"] and check_session()),
            ("Logout", lambda: current_session["email"] and check_session()),
            ("Exit", lambda: True)
        ]

        print("\nOptions:")
        valid_choices = []
        for idx, (option, condition) in enumerate(menu_options, 1):
            if condition():
                print(f"{len(valid_choices) + 1}. {option}")
                valid_choices.append((idx, option))

        # Validate user input for menu choice
        while True:
            choice = input(f"Enter your choice (1-{len(valid_choices)}): ").strip()
            if not choice:  # Handle empty input
                print("Choice cannot be empty. Please try again.")
                continue
            try:
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(valid_choices):
                    selected_idx = valid_choices[choice_idx][0]
                    break
                else:
                    print("Invalid choice. Please try again.")
            except ValueError:
                print("Invalid choice. Please try again.")

        if selected_idx == 1:  # Login
            print("\n=== User Login ===")
            # Prompt for email with validation
            while True:
                email = input("Enter email: ").strip()
                try:
                    validate_email(email)
                    break
                except ValueError as e:
                    print(f"Error: {e}")
                    print("Please try again.")
            password = input("Enter password: ")

            success, role = login(cursor, email, password)
            if success:
                # Display user data after successful login
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

        elif selected_idx == 2:  # Reset Password
            print("\n=== Password Reset ===")
            # Prompt for email with validation
            while True:
                email = input("Enter email: ").strip()
                try:
                    validate_email(email)
                    break
                except ValueError as e:
                    print(f"Error: {e}")
                    print("Please try again.")
            reset_password(cursor, conn, email)

        elif selected_idx == 3:  # Register New User
            print("\n=== Register New User ===")
            # Prompt for name with validation
            while True:
                name = input("Enter name: ").strip()
                try:
                    sanitize_name(name)
                    break
                except ValueError as e:
                    print(f"Error: {e}")
                    print("Please try again.")
            # Prompt for email with validation
            while True:
                email = input("Enter email: ").strip()
                try:
                    validate_email(email)
                    break
                except ValueError as e:
                    print(f"Error: {e}")
                    print("Please try again.")
            # Prompt for password with validation
            while True:
                password = input("Enter password: ").strip()
                try:
                    validate_password(password)
                    break
                except ValueError as e:
                    print(f"Error: {e}")
                    print("Please try again.")
            # Set role with a default of 'user'
            role = input("Enter role (user/admin, default is user): ").lower().strip() or 'user'
            if role not in ['user', 'admin']:
                print("Invalid role. Defaulting to 'user'.")
                role = 'user'

            # Encrypt sensitive data and hash the password
            encrypted_name = encrypt_data(name, key)
            encrypted_email = encrypt_data(email, key)
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            try:
                # Insert the new user into the database
                cursor.execute(
                    "INSERT INTO customers (name, email, encrypted_data, password, role) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                    (encrypted_name, email, encrypted_email, hashed_password, role)
                )
                user_id = cursor.fetchone()[0]
                # Store the initial password in history
                store_password_history(cursor, conn, user_id, hashed_password)
                # Log the insert action in the audit log
                cursor.execute(
                    "INSERT INTO audit_log (operation, email) VALUES (%s, %s)",
                    ("INSERT", email)
                )
                conn.commit()
                print("User registered successfully")
            except psycopg2.errors.UniqueViolation:
                print(f"Email {email} already exists")
                conn.rollback()

        elif selected_idx == 4:  # Update Profile
            if current_session["email"] and check_session():
                update_user(cursor, conn, current_session["email"], key)

        elif selected_idx == 5:  # Logout
            if current_session["email"] and check_session():
                logout()

        elif selected_idx == 6:  # Exit
            print("Exiting...")
            break

        # Admin menu after login
        if current_session["email"] and check_session():
            if current_session["role"] == 'admin':
                while True:
                    print("\nAdmin Options:")
                    print("1. View All Users")
                    print("2. Delete User")
                    print("3. Export Users")
                    print("4. Analyze Trends")
                    print("5. Back to Main Menu")
                    # Validate admin menu choice
                    while True:
                        admin_choice = input("Enter your choice (1-5): ").strip()
                        if not admin_choice:
                            print("Choice cannot be empty. Please try again.")
                            continue
                        try:
                            admin_choice_idx = int(admin_choice)
                            if 1 <= admin_choice_idx <= 5:
                                break
                            else:
                                print("Invalid choice. Please try again.")
                        except ValueError:
                            print("Invalid choice. Please try again.")
                    if not check_session():
                        break
                    if admin_choice == '1':
                        view_all_users(cursor, key)
                    elif admin_choice == '2':
                        print("\n=== Delete User ===")
                        while True:
                            email_to_delete = input("Enter email of user to delete: ").strip()
                            if delete_user(cursor, conn, email_to_delete):
                                break
                    elif admin_choice == '3':
                        export_users(cursor, conn, key)
                    elif admin_choice == '4':
                        analyze_trends(cursor)
                    elif admin_choice == '5':
                        break

except Exception as e:
    print(f"Error: {e}")
finally:
    # Clean up database connection
    cursor.close()
    conn.close()