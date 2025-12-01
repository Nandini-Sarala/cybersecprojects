from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def encrypt_aes(text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(text.ljust(16).encode())
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def decrypt_aes(ciphertext, key):
    raw = base64.b64decode(ciphertext)
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ct).decode().strip()

# Example usage
key = get_random_bytes(16)  # AES-128
plaintext = "Hello!"
ciphertext = encrypt_aes(plaintext, key)
decrypted = decrypt_aes(ciphertext, key)

print("🔐 Encrypted:", ciphertext)
print("🔓 Decrypted:", decrypted)