# Secure Customer Database System
A database system using PostgreSQL to store customer data securely with AES-256 encryption.

## Features
- Stores customer data in a PostgreSQL database.
- Encrypts sensitive data (e.g., email) using AES-256 encryption in EAX mode.
- Validates email input to ensure proper format.
- Hashes passwords securely using `bcrypt`.
