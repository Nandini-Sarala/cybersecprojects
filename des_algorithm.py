from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import base64

# Padding function (DES requires 8-byte blocks)
def pad(text):
    while len(text) % 8 != 0:
        text += ' '
    return text

def encrypt_des_ecb(text, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = pad(text)
    encrypted = cipher.encrypt(padded_text.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_des_ecb(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(ciphertext))
    return decrypted.decode().strip()

# Example usage
key = get_random_bytes(8)  # DES requires 8-byte key
plaintext = "Hello!"
ciphertext = encrypt_des_ecb(plaintext, key)
decrypted = decrypt_des_ecb(ciphertext, key)

print("🔐 Encrypted:", ciphertext)
print("🔓 Decrypted:", decrypted)