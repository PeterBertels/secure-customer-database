"""
Encryption and Decryption Module

This module provides functions for encrypting and decrypting data using AES-256 in EAX mode.
It ensures the confidentiality and integrity of sensitive data (e.g., names, emails) stored in the database.

Dependencies:
- pycryptodome: For AES encryption and decryption.
"""

from Crypto.Cipher import AES
import os

def encrypt_data(data, key):
    """
    Encrypt data using AES-256 in EAX mode.

    Args:
        data (str): The data to encrypt.
        key (bytes): The encryption key (32 bytes for AES-256).

    Returns:
        bytes: The encrypted data, including nonce, tag, and ciphertext.
    """
    if not data:
        return None
    # Create a new AES cipher in EAX mode with a random nonce
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    # Encrypt the data and get the authentication tag
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    # Combine nonce, tag, and ciphertext for storage
    return nonce + tag + ciphertext

def decrypt_data(data, key):
    """
    Decrypt data encrypted with AES-256 in EAX mode.

    Args:
        data (bytes): The encrypted data, including nonce, tag, and ciphertext.
        key (bytes): The decryption key (32 bytes for AES-256).

    Returns:
        str: The decrypted data, or None if decryption fails.
    """
    if not data:
        return None
    try:
        # Extract nonce, tag, and ciphertext from the encrypted data
        nonce = data[:16]  # EAX mode nonce is typically 16 bytes
        tag = data[16:32]  # Tag is 16 bytes
        ciphertext = data[32:]
        # Create a new AES cipher in EAX mode with the extracted nonce
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        # Decrypt the data and verify the authentication tag
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except (ValueError, KeyError) as e:
        print(f"Decryption error: {e}")
        return None