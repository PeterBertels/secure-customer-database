import psycopg2
from Crypto.Cipher import AES
import os
import re
import bcrypt

def validate_email(email):
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(pattern, email):
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

    # Insert into database
    cursor.execute(
        "INSERT INTO customers (name, email, encrypted_data, password) VALUES (%s, %s, %s, %s)",
        ("John Doe", email, encrypted_email, hashed_password)
    )
    conn.commit()

    # Retrieve and decrypt
    cursor.execute("SELECT name, email, encrypted_data, password FROM customers")
    rows = cursor.fetchall()
    for row in rows:
        name, email, encrypted, hashed = row
        decrypted_email = decrypt_data(encrypted, key)
        print(f"Name: {name}, Email: {email}, Decrypted Email: {decrypted_email}")
        # Verify password
        if hashed:
            hashed_bytes = bytes(hashed)  # Convert memoryview to bytes
            if bcrypt.checkpw(password.encode('utf-8'), hashed_bytes):
                print("Password verified successfully")
        else:
            print("No password set for this record")

except Exception as e:
    print(f"Error: {e}")
finally:
    cursor.close()
    conn.close()