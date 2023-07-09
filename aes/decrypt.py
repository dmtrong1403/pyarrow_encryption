import os
import csv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import sys

def decrypt_data(data, key, associated_data):
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def main(input_encrypted_csv, output_csv, password):
    # Read the encrypted file
    with open(input_encrypted_csv, 'rb') as f:
        encrypted_data = f.read()

    # Extract the salt and encrypted data
    salt = encrypted_data[:16]
    encrypted_csv_data = encrypted_data[16:]

    # Generate AES key
    key = generate_aes_key(password, salt)

    # Decrypt the encrypted CSV data
    decrypted_data = decrypt_data(encrypted_csv_data, key, salt)

    # Deserialize the decrypted data into CSV rows
    csv_rows = [row.split(',') for row in decrypted_data.decode().split('\n')]

    # Write the decrypted data to the output file
    with open(output_csv, 'w', newline='') as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        writer.writerows(csv_rows)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python decrypt_csv.py <input_encrypted_csv> <output_csv> <password>")
    else:
        main(sys.argv[1], sys.argv[2], sys.argv[3])