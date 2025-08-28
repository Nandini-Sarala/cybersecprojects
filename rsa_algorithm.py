from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def generate_keys():
    key = RSA.generate(2048)
    return key.publickey(), key

def encrypt_rsa(text, pub_key):
    cipher = PKCS1_OAEP.new(pub_key)
    return base64.b64encode(cipher.encrypt(text.encode())).decode()

def decrypt_rsa(ciphertext, priv_key):
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(base64.b64decode(ciphertext)).decode()


# Sample usage
public_key, private_key = generate_keys()
plaintext = "Hello!"
ciphertext = encrypt_rsa(plaintext, public_key)
decrypted = decrypt_rsa(ciphertext, private_key)

print("🔐 Encrypted:", ciphertext)
print("🔓 Decrypted:", decrypted)