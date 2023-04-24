import hashlib
import sys
import csv

def md5_hash(file_content):
    md5 = hashlib.md5()
    md5.update(file_content.encode())
    return md5.hexdigest()

def main(input_csv):
    # Read CSV file
    with open(input_csv, 'r', newline='') as f:
        reader = csv.reader(f)
        csv_data = [row for row in reader]

    # Serialize CSV data without double quotes
    serialized_data = "\n".join([",".join(row) for row in csv_data]).replace('"', '')

    # Calculate MD5 hash
    return md5_hash(serialized_data)

if __name__ == "__main__":
    original_checksum = main('example.csv')
    decrypted_checksum = main('decrypted.csv')

    # compare the checksums
    if original_checksum == decrypted_checksum:
        print('Decrypted file matches original file.')
    else:
        print('Decrypted file does not match original file.')
