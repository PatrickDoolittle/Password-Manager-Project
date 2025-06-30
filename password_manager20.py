#!/usr/bin/env python3
"""
Student Name: Patrick Doolittle
Date: 2025-06-30

Secure password manager using PBKDF2 and AES-GCM.


Passwords are stored in pipe-delimited files with the following format.
The hashes of main passwords in users.txt and encrypted service passwords in user_passwords.txt:
  users.txt:          username|salt|verifier
  user_passwords.txt: service|username|encrypted_data
"""

import os
import getpass # Secure password input
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

class PasswordManager:
    def __init__(self):
        self.users_file = "users.txt"
        self.current_user = None
        self.enc_key = None
        self.iterations = 310000  # PBKDF2 slow hashing iterations
    
    def derive_keys(self, password, salt):
        derived = PBKDF2(password, salt, dkLen=64, count=self.iterations, hmac_hash_module=SHA256)
        return derived[:32], derived[32:] # Half of key for verification, half for encryption
    
    def encrypt(self, plaintext, key):
        # AES-GCM encryption with 12-byte nonce
        nonce = os.urandom(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
        return nonce + tag + ciphertext # Stored as nonce, tag, ciphertext concatenated
    
    def decrypt(self, data, key):
        # AES-GCM decryption
        nonce = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode()
        except ValueError:
            raise ValueError("Decryption failed - data corrupted or wrong key")
    
    def register(self):
        # Register new user and generate PBKDF2 key material
        username = input("Choose username: ")
        password = getpass.getpass("Choose password: ")
        confirm = getpass.getpass("Confirm password: ")
        
        if password != confirm:
            print("Passwords don't match!")
            return
        
        # Check if user exists
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r') as f:
                for line in f:
                    if line.startswith(username + "|"):
                        print("User already exists!")
                        return
        
        # Generate 16-byte salt for precomputation resistance
        salt = os.urandom(16)
        
        # Derive keys
        enc_key, verifier = self.derive_keys(password, salt)
        
        # Store username, salt, and verifier in a pipe-delimited text file, encoded in hex
        with open(self.users_file, 'a') as f:
            f.write(f"{username}|{salt.hex()}|{verifier.hex()}\n")
        # Create an empty file for this user's passwords
        open(f"{username}_passwords.txt", 'w').close()
        print("Registration successful!")
    
    def login(self):
        # Login existing user, re-derive keys, and verify password
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        
        if not os.path.exists(self.users_file):
            print("No users registered!")
            return False
        
        # Find user in users.txt, verify password, and re-derive keys
        with open(self.users_file, 'r') as f:
            for line in f:
                parts = line.strip().split("|")
                if len(parts) == 3:
                    stored_user, salt_hex, stored_verifier = parts
                    if stored_user == username:
                        # Derive keys from entered password
                        salt = bytes.fromhex(salt_hex)
                        enc_key, verifier = self.derive_keys(password, salt)
                        
                        # Check if verifier matches
                        if verifier.hex() == stored_verifier:
                            self.current_user = username
                            self.enc_key = enc_key
                            print(f"Welcome, {username}!")
                            return True
                        else:
                            print("Invalid password!")
                            return False
        
        print("User not found!")
        return False
    
    def add_password(self):
        # Encrypt a new password using AES-GCM
        service = input("Service/Website: ")
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        
        encrypted = self.encrypt(password, self.enc_key)
        
        # Save: service|username|encrypted_data
        with open(f"{self.current_user}_passwords.txt", 'a') as f:
            f.write(f"{service}|{username}|{encrypted.hex()}\n")
        
        print("Password saved!")
    
    def view_passwords(self):
        # Display list of services with saved passwords
        file = f"{self.current_user}_passwords.txt"
        if not os.path.exists(file):
            print("No passwords saved yet!")
            return
        
        print("\nSaved passwords:")
        with open(file, 'r') as f:
            for i, line in enumerate(f, 1):
                parts = line.strip().split('|')
                if len(parts) >= 2:
                    print(f"{i}. {parts[0]} - {parts[1]}")
    
    def get_password(self):
        # Decrypt and display a service's password

        self.view_passwords()
        
        try:
            choice = int(input("\nEnter number to view: "))
        except ValueError:
            print("Invalid number!")
            return
        
        # Read and decrypt
        with open(f"{self.current_user}_passwords.txt", 'r') as f:
            lines = f.readlines()
            if 0 < choice <= len(lines):
                parts = lines[choice-1].strip().split('|')
                if len(parts) == 3:
                    service, username, encrypted_hex = parts
                    
                    try:
                        # Decrypt password
                        encrypted = bytes.fromhex(encrypted_hex)
                        decrypted = self.decrypt(encrypted, self.enc_key)
                        
                        print(f"\nService: {service}")
                        print(f"Username: {username}")
                        print(f"Password: {decrypted}")
                    except ValueError as e:
                        print(f"Error: {e}")
                else:
                    print("Invalid password entry!")
            else:
                print("Invalid choice!")
    
    def delete_password(self):
        # Delete a saved password entry
        self.view_passwords()
        
        try:
            choice = int(input("\nEnter number to delete: "))
        except ValueError:
            print("Invalid number!")
            return
        
        with open(f"{self.current_user}_passwords.txt", 'r') as f:
            lines = f.readlines()
        
        if 0 < choice <= len(lines):
            # Confirm deletion
            parts = lines[choice-1].strip().split('|')
            if len(parts) >= 2:
                confirm = input(f"Delete password for {parts[0]}? (y/n): ")
                if confirm.lower() == 'y':
                    # Rewrite file without the deleted line
                    with open(f"{self.current_user}_passwords.txt", 'w') as f:
                        for i, line in enumerate(lines):
                            if i != choice-1:
                                f.write(line)
                    print("Password deleted!")
        else:
            print("Invalid choice!")
    
    def run(self):
        # Main program loop
        print("=== Secure Password Manager ===")
        print(f"Using PBKDF2 with {self.iterations} slow hashing iterations")
        print("Encryption: AES-256-GCM\n")
        
        while True:
            if not self.current_user:
                print("\n1. Login")
                print("2. Register")
                print("3. Exit")
                
                choice = input("Choose: ")
                
                if choice == '1':
                    self.login()
                elif choice == '2':
                    self.register()
                elif choice == '3':
                    print("Goodbye!")
                    break
            else:
                print(f"\n=== {self.current_user}'s Vault ===")
                print("1. Add password")
                print("2. View password")
                print("3. List passwords")
                print("4. Delete password")
                print("5. Logout")
                
                choice = input("Choose: ")
                
                if choice == '1':
                    self.add_password()
                elif choice == '2':
                    self.get_password()
                elif choice == '3':
                    self.view_passwords()
                elif choice == '4':
                    self.delete_password()
                elif choice == '5':
                    self.current_user = None
                    self.enc_key = None
                    print("Logged out!")

if __name__ == "__main__":
    pm = PasswordManager()
    pm.run()