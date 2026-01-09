import random
import string
from cryptography.fernet import Fernet
import os

# ---------------- KEY MANAGEMENT ----------------
def load_or_create_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        print("Encryption key generated and saved.")
    else:
        key = open("secret.key", "rb").read()
    return key

key = load_or_create_key()
cipher = Fernet(key)

# ---------------- PASSWORD GENERATOR ----------------
def pass_gen(length):
    safe_symbols = "!@#$%^&*()_+-="
    characters = (
        string.ascii_lowercase +
        string.ascii_uppercase +
        string.digits +
        safe_symbols
    )
    return ''.join(random.choice(characters) for _ in range(length))

# ---------------- PASSWORD STRENGTH ----------------
def check_strength(password):
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    score = sum([has_upper, has_lower, has_digit, has_symbol])

    if length >= 12 and score == 4:
        return "Strong"
    elif length >= 8 and score >= 3:
        return "Medium"
    else:
        return "Weak"

# ---------------- ENCRYPT / DECRYPT ----------------
def encrypt_password(password):
    return cipher.encrypt(password.encode())

def decrypt_password(encrypted_password):
    return cipher.decrypt(encrypted_password).decode()

# ---------------- SAVE PASSWORD ----------------
def save_pass(website, username, password):
    encrypted = encrypt_password(password)
    with open("passwords_secure.txt", "ab") as file:
        file.write(b"Website: " + website.encode() + b"\n")
        file.write(b"Username: " + username.encode() + b"\n")
        file.write(b"Password: " + encrypted + b"\n")
        file.write(b"-" * 30 + b"\n")

# ---------------- VIEW PASSWORDS ----------------
def view_passwords():
    with open("passwords_secure.txt", "rb") as file:
        for line in file:
            if line.startswith(b"Password: "):
                encrypted = line.replace(b"Password: ", b"").strip()
                decrypted = decrypt_password(encrypted)
                print("Password:", decrypted)
            else:
                print(line.decode().strip())

# ---------------- MAIN ----------------
print("Welcome to Password Generator")

length = int(input("Enter password length: "))
if length < 6:
    print("Password length too short!")
    exit()

password = pass_gen(length)
print("\nGenerated Password:", password)

strength = check_strength(password)
print("Password Strength:", strength)

save_choice = input("\nDo you want to save this password? (y/n): ")

if save_choice.lower() == "y":
    website = input("Enter website name: ")
    username = input("Enter username/email: ")
    save_pass(website, username, password)
    print("Password saved securely!")
else:
    print("Password not saved.")
