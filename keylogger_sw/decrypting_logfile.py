from cryptography.fernet import Fernet

with open("secret.key", "rb") as key_file:
    key = key_file.read()

cipher = Fernet(key)

with open("keystrokes_encrypted.log", "rb") as f:
    for line in f:
        decrypted = cipher.decrypt(line.strip())
        print(decrypted.decode())