import csv
import os
import sys
import base64
import getpass
import tempfile
import random
import string
import pyperclip
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

PASSWORD_FILE = "password_store.csv"
KEY_FILE = "keyfile.key"

# Generate or load encryption key based on master password
def get_key_from_password(password: str) -> bytes:
    salt = b"\x00" * 16  # Static salt for simplicity; use random in production
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encrypt file contents
def encrypt_file(filename, key):
    if not os.path.exists(filename):
        return
    with open(filename, "rb") as f:
        data = f.read()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    with open(filename, "wb") as f:
        f.write(encrypted)

# Decrypt file contents
def decrypt_file(filename, key):
    if not os.path.exists(filename):
        return
    with open(filename, "rb") as f:
        data = f.read()
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(data)
        with open(filename, "wb") as f:
            f.write(decrypted)
    except:
        print("Incorrect password or corrupted file.")
        sys.exit(1)

# Load all entries
def load_entries():
    entries = []
    if not os.path.exists(PASSWORD_FILE):
        return entries
    with open(PASSWORD_FILE, newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            entries.append(row)
    return entries

# Save all entries
def save_entries(entries):
    with open(PASSWORD_FILE, "w", newline="") as csvfile:
        fieldnames = ["Title", "EncryptedPassword", "URL", "Notes"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for entry in entries:
            writer.writerow(entry)

# Encrypt password string
def encrypt_password(password, key):
    fernet = Fernet(key)
    return fernet.encrypt(password.encode()).decode()

# Decrypt password string
def decrypt_password(enc_password, key):
    fernet = Fernet(key)
    return fernet.decrypt(enc_password.encode()).decode()

# Add new password
def add_entry(key):
    title = input("Title: ")
    password = getpass.getpass("Password: ")
    url = input("URL/Application: ")
    notes = input("Notes: ")
    encrypted = encrypt_password(password, key)
    entries = load_entries()
    entries.append({"Title": title, "EncryptedPassword": encrypted, "URL": url, "Notes": notes})
    save_entries(entries)
    print("Entry added.")

# Search for a password
def search_entry(key):
    title = input("Search Title: ")
    entries = load_entries()
    found = False
    for entry in entries:
        if entry["Title"].lower() == title.lower():
            print(f"Found: URL={entry['URL']}, Notes={entry['Notes']}")
            action = input("Show password? (y/n): ")
            if action.lower() == 'y':
                password = decrypt_password(entry['EncryptedPassword'], key)
                print(f"Password: {password}")
                copy = input("Copy to clipboard? (y/n): ")
                if copy.lower() == 'y':
                    pyperclip.copy(password)
                    print("Copied to clipboard.")
            found = True
    if not found:
        print("No entry found.")

# Update an existing password
def update_entry(key):
    title = input("Title to update: ")
    entries = load_entries()
    for entry in entries:
        if entry["Title"].lower() == title.lower():
            new_password = getpass.getpass("New Password: ")
            entry["EncryptedPassword"] = encrypt_password(new_password, key)
            save_entries(entries)
            print("Password updated.")
            return
    print("Entry not found.")

# Delete an entry
def delete_entry():
    title = input("Title to delete: ")
    entries = load_entries()
    entries = [e for e in entries if e["Title"].lower() != title.lower()]
    save_entries(entries)
    print("Entry deleted (if it existed).")

# Random Password Generator
def generate_password():
    length = int(input("Length of password: "))
    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(chars) for _ in range(length))
    print(f"Generated password: {password}")
    copy = input("Copy to clipboard? (y/n): ")
    if copy.lower() == 'y':
        pyperclip.copy(password)
        print("Copied to clipboard.")

# MAIN PROGRAM
def main():
    print("--- Password Manager ---")
    password = getpass.getpass("Enter master password: ")
    key = get_key_from_password(password)

    if os.path.exists(PASSWORD_FILE):
        decrypt_file(PASSWORD_FILE, key)
    else:
        open(PASSWORD_FILE, "w").close()

    try:
        while True:
            print("\nOptions: [1] Add [2] Search [3] Update [4] Delete [5] Generate Password [6] Exit")
            choice = input("Choose: ")
            if choice == "1":
                add_entry(key)
            elif choice == "2":
                search_entry(key)
            elif choice == "3":
                update_entry(key)
            elif choice == "4":
                delete_entry()
            elif choice == "5":
                generate_password()
            elif choice == "6":
                break
            else:
                print("Invalid option.")
    finally:
        encrypt_file(PASSWORD_FILE, key)
        print("Data encrypted. Exiting.")

if __name__ == "__main__":
    main()
