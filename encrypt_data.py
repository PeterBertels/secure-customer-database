from Crypto.Cipher import AES
import os

def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return nonce + ciphertext + tag

def decrypt_data(encrypted_data, key):
    nonce = encrypted_data[:16]  # EAX nonce is 16 bytes
    tag = encrypted_data[-16:]  # Tag is 16 bytes
    ciphertext = encrypted_data[16:-16]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# Example usage
if __name__ == "__main__":
    key = os.urandom(32)  # 256-bit key
    data = "sensitive@email.com"
    encrypted = encrypt_data(data, key)
    decrypted = decrypt_data(encrypted, key)
    print(f"Original: {data}")
    print(f"Encrypted: {encrypted.hex()}")
    print(f"Decrypted: {decrypted}")
