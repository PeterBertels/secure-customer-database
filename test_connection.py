import psycopg2
from Crypto.Cipher import AES
import os

def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return nonce + ciphertext + tag

def decrypt_data(encrypted_data, key):
    nonce = encrypted_data[:16]
    tag = encrypted_data[-16:]
    ciphertext = encrypted_data[16:-16]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

try:
    # Temporary key for testing (replace with secure storage later)
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
    encrypted_email = encrypt_data(email, key)

    # Insert into database
    cursor.execute(
        "INSERT INTO customers (name, email, encrypted_data) VALUES (%s, %s, %s)",
        ("John Doe", email, encrypted_email)
    )
    conn.commit()

    # Retrieve and decrypt
    cursor.execute("SELECT name, email, encrypted_data FROM customers")
    rows = cursor.fetchall()
    for row in rows:
        name, email, encrypted = row
        decrypted_email = decrypt_data(encrypted, key)
        print(f"Name: {name}, Email: {email}, Decrypted Email: {decrypted_email}")

except Exception as e:
    print(f"Error: {e}")
finally:
    cursor.close()
    conn.close()
