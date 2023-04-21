import csv
import pandas as pd
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def encrypt_csv(filename):
    # generate a new RSA key pair
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # create a cipher object for encryption
    public_key = key.public_key()

    # read the CSV file into a pandas dataframe
    df = pd.read_csv(filename)

    # encrypt the values in the dataframe
    encrypted_df = df.applymap(lambda x: public_key.encrypt(
        str(x).strip().encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ).hex())

    # write the encrypted dataframe to a new CSV file
    encrypted_df.to_csv('encrypted_' + filename, index=False)

    # serialize the private key to a PEM-encoded string
    private_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # write the private key to a file
    with open('private_key.pem', 'wb') as f:
        f.write(private_key_pem)

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

if __name__ == '__main__':
    filename = "example.csv"
    encrypt_csv(filename)
    decrypt_csv('encrypted_' + filename)
