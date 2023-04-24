import os
import csv
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import sys

def encrypt_data(data, key, associated_data):
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, associated_data)
    return (nonce + ciphertext)

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def md5_hash(file_content):
    md5 = hashlib.md5()
    md5.update(file_content.encode())
    return md5.hexdigest()

def main(input_csv, output, password):
    # Read CSV file
    with open(input_csv, 'r') as f:
        reader = csv.reader(f)
        csv_data = [row for row in reader]

    # Serialize CSV data
    serialized_data = "\n".join([",".join(row) for row in csv_data]).encode()

    # Generate AES key
    salt = os.urandom(16)
    key = generate_aes_key(password, salt)

    # Encrypt the serialized CSV data
    encrypted_data = encrypt_data(serialized_data, key, salt)

    # Write the encrypted data to the output file
    with open(f'{output}.csv', 'wb') as f:
        f.write(salt + encrypted_data)
    with open(f'{output}.md5', 'w') as f:
        # f.write(md5_hash("\n".join([",".join(row) for row in csv_data]).replace('"', '')))
        serialized_data = "\n".join([",".join(row) for row in csv_data]).replace('"', '')
        md5 = md5_hash(serialized_data)
        f.write(md5)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python encrypt.py <input_csv> <output> <password>")
    else:
        main(sys.argv[1], sys.argv[2], sys.argv[3])
