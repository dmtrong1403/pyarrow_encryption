import os
import csv
import pandas as pd
import numpy as np
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def generate_key_pair(public_key_file='public_key.pem', private_key_file='private_key.pem'):
    # check if the key files already exist
    if os.path.exists(public_key_file) and os.path.exists(private_key_file):
        print('Key pair already exists.')
        return

    # generate the private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # write the private key to file
    with open(private_key_file, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # generate the public key from the private key
    public_key = private_key.public_key()

    # write the public key to file
    with open(public_key_file, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print('Key pair generated successfully.')


def encrypt_csv(filename, public_key_file='public_key.pem'):
    # read the public key from file and create a key object from it
    with open(public_key_file, 'rb') as f:
        public_key_pem = f.read()
    key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

    # read the original CSV file into a pandas dataframe
    original_df = pd.read_csv(filename)

    # convert numeric values to strings
    original_df = original_df.applymap(lambda x: str(x) if str(x).isnumeric() else x)

    # encrypt the values in the dataframe
    encrypted_df = original_df.applymap(lambda x: key.encrypt(
        x.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ).hex())

    # write the encrypted dataframe to a new CSV file
    encrypted_df.to_csv('encrypted_' + filename, index=False, quoting=csv.QUOTE_NONNUMERIC)

    print('Encryption successful.')


def decrypt_csv(filename):
    # read the private key from file and create a key object from it
    with open('private_key.pem', 'rb') as f:
        private_key_pem = f.read()
    key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )

    # read the encrypted CSV file into a pandas dataframe
    encrypted_df = pd.read_csv(filename)

    # decrypt the values in the dataframe
    decrypted_df = encrypted_df.applymap(lambda x: key.decrypt(
        bytes.fromhex(x),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ).decode().strip())

    # write the decrypted dataframe to a new CSV file
    decrypted_df.to_csv('decrypted_' + filename, index=False, quoting=csv.QUOTE_NONNUMERIC)

    print('Decryption successful.')

    # compute the checksum of the original file
    original_checksum = hashlib.md5(open('example.csv', 'rb').read()).hexdigest()

    # compute the checksum of the decrypted file
    decrypted_checksum = hashlib.md5(open('decrypted_' + filename, 'rb').read()).hexdigest()

    # compare the checksums
    if original_checksum == decrypted_checksum:
        print('Decrypted file matches original file.')
    else:
        print('Decrypted file does not match original file.')

def replicate_rows(csv_file, n=1000, output_file='replicated.csv'):
    # Read the CSV file into a pandas dataframe
    df = pd.read_csv(csv_file)

    # Replicate the rows
    replicated_df = pd.concat([df]*n, ignore_index=True)

    # Write the replicated rows to a new CSV file
    replicated_df.to_csv(output_file, index=False)

    print(f'Replicated {len(df)} rows {n} times to create {len(replicated_df)} rows in {output_file}.')

if __name__ == '__main__':
    # generate_key_pair()
    # filename = "example.csv"
    # encrypt_csv(filename)
    # decrypt_csv('encrypted_' + filename)
    replicate_rows('example.csv', n=1000, output_file='replicated.csv')
