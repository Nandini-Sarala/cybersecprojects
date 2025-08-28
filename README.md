🛡️ Multi-Algorithm Text Encryption Tool

🔍 Overview
This project is a Python-based encryption suite that allows users to securely encrypt and decrypt text using three major cryptographic algorithms:
- AES (Advanced Encryption Standard)
- DES (Data Encryption Standard)
- RSA (Rivest–Shamir–Adleman)

It demonstrates both "symmetric" and "asymmetric" encryption techniques and highlights the differences in key management, block sizes, and security practices.

 📚 What I Learned

 🔐 Encryption Fundamentals
- "Symmetric encryption" (AES, DES) uses the same key for encryption and decryption.
- "Asymmetric encryption" (RSA) uses a public/private key pair for secure communication.

 🧠 Modes of Operation
- "ECB (Electronic Codebook)": Simple but insecure due to pattern leakage.
- "CBC (Cipher Block Chaining)": More secure by chaining blocks and using an IV.

 🧼 Padding Importance
- Block ciphers require input to match block size (AES: 16 bytes, DES: 8 bytes).
- Padding ensures compatibility and hides plaintext length.
- Secure padding schemes like PKCS#7 and PKCS1_OAEP prevent attacks.

 🔒 Key Management
- AES and DES require securely generated and stored keys.
- RSA generates a key pair, allowing public sharing without compromising security.

---

 🧪 How to Run

 ✅ Prerequisites
- Python 3.x
- Install dependencies:
  ```bash
  pip install pycryptodome
  ```

 📁 File Structure
```
encryption_tool/
├── aes_module.py
├── des_module.py
├── rsa_module.py
└── main.py
```

 🧾 Sample Usage
Each module includes:
- `encrypt_<algorithm>(text, key)`
- `decrypt_<algorithm>(ciphertext, key)`

Example:
```python
from aes_module import encrypt_aes, decrypt_aes
key = get_random_bytes(16)
ciphertext = encrypt_aes("Hello!", key)
print(decrypt_aes(ciphertext, key))
```

 🧩 Algorithms Summary

| Algorithm | Type      | Key Size     | Block Size | Mode Used | Security Level |
|-----------|-----------|--------------|------------|-----------|----------------|
| AES       | Symmetric | 128 bits     | 16 bytes   | CBC       | Strong         |
| DES       | Symmetric | 56 bits      | 8 bytes    | ECB       | Weak (legacy)  |
| RSA       | Asymmetric| 2048 bits    | N/A        | OAEP      | Strong         |


 🚀 Future Enhancements
- Add GUI with Tkinter or Flask
- Implement hybrid encryption (RSA + AES)
- Use PKCS#7 padding for AES/DES
- Encrypt files instead of just text




