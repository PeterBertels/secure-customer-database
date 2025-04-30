# Secure Customer Database System
A database system using PostgreSQL to store customer data securely with AES-256 encryption.

## Features
- Stores customer data in a PostgreSQL database with tables for customers, password history, and audit logs.
- Encrypts sensitive data (e.g., name, email) using AES-256 encryption in EAX mode (see `encrypt_data.py`).
- Hashes passwords securely using `bcrypt` and enforces strong password requirements (minimum 8 characters, uppercase, lowercase, digit, and special character).
- Implements password history to prevent reuse of the last 3 passwords, with automatic pruning of older entries.
- Supports user sessions with login, logout, and automatic session timeout after 5 minutes of inactivity.
- Implements two-factor authentication (2FA) with email-based code verification during login (simulated via console).
- Provides input validation loops for menu choices, emails, names, and passwords to ensure robust user interaction.
- Validates and sanitizes inputs across all operations (e.g., registration, login, update, delete):
  - Emails must match a valid format.
  - Names allow only letters, spaces, and hyphens.
- Prevents duplicate email entries with unique constraints in the database.
- Implements rate limiting for login attempts (5 attempts per minute per email).
- Logs security events (e.g., login attempts, password resets, session timeouts, 2FA attempts, user actions) to `security.log`.
- Maintains an audit log of user actions (e.g., insert, update, delete, export) in the database.
- Offers admin functionalities:
  - View all users with decrypted data.
  - Delete non-admin users.
  - Export user data to a CSV file.