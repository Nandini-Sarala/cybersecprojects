# Quick Reference - Text Encryptor Project

## 🚀 Quick Start (Copy & Paste)

### Terminal 1: Start Web Server
```powershell
cd "e:\cybersecprojects\text_encryption\web_encrypt"
python -m http.server 8000
```
Then open: **http://localhost:8000**

### Terminal 2: Start Flask Server (Optional)
```powershell
cd "e:\cybersecprojects\text_encryption\server"
pip install -r requirements.txt
python app.py
```
Server runs at: **http://localhost:5000**

### Terminal 3: Run Tests
```powershell
cd "e:\cybersecprojects\text_encryption"
python test_integration.py
```

---

## 🎯 What You Can Do Now

### ✅ AES Encryption
- Enter plaintext → passphrase → Click "Encrypt"
- Output: Base64 blob (salt || iv || ciphertext)
- Decrypt: Click "Decrypt" with same passphrase

### ✅ DES Encryption
- Select TripleDES from dropdown
- Works same as AES
- Uses CryptoJS library

### ✅ RSA Encryption (Client-Only)
1. Select "RSA" algorithm
2. Enter passphrase
3. Click "Generate RSA keypair"
4. Public key displayed (share with others)
5. Encrypted private key saved (export & backup)
6. Share public key → recipient encrypts → you decrypt

### ✅ RSA with Server Integration
1. Generate RSA keypair (passphrase-protected)
2. Set server URL: `http://localhost:5000`
3. Click "Send public key to server"
4. Encrypt a message
5. Click "Send encrypted to server"
6. Server decrypts and shows plaintext

### ✅ Passphrase Tools
- **Generator**: Creates strong random passphrases
- **Strength Meter**: Real-time feedback (Weak → Strong)
- **Copy**: One-click clipboard copy
- **Length Control**: 8-128 character passphrases

### ✅ Key Management
- **Export**: Download encrypted private key as `.key` file
- **Import**: Restore private key from file

---

## 📊 Test Results

```
✓ ALL TESTS PASSED
  ✓ Server status check
  ✓ RSA keypair generation (2048-bit)
  ✓ Public key transmission
  ✓ Encryption (client-side RSA-OAEP)
  ✓ Decryption (server-side)
  ✓ Round-trip: "Hello, Server!" ↔ "Hello, Server!"
```

---

## 🔐 Security Summary

| Feature | Implementation |
|---------|-----------------|
| Symmetric (AES) | PBKDF2-SHA256 (250k iterations) → AES-GCM |
| Asymmetric (RSA) | RSA-OAEP 2048-bit, MGF1-SHA256 |
| Private Key | Encrypted with PBKDF2 + AES-GCM |
| Key Storage | Client-side (browser) or export to file |

---

## 📁 Key Files

| File | Purpose |
|------|---------|
| `web_encrypt/index.html` | UI with all controls |
| `web_encrypt/app.js` | Encryption logic + strength meter |
| `server/app.py` | Flask endpoints for RSA decryption |
| `test_integration.py` | Automated test suite |
| `README.md` | Full project documentation |
| `IMPLEMENTATION_SUMMARY.md` | Technical details |

---

## 🐛 Troubleshooting

| Problem | Fix |
|---------|-----|
| Web page won't load | Check `python -m http.server 8000` is running |
| "Cannot connect to server" | Check Flask server: `python server/app.py` |
| "ModuleNotFoundError: No module named 'flask'" | Run: `pip install -r server/requirements.txt` |
| Server decryption fails | Ensure private key is set via `/set_private_key` |
| CORS errors | Restart Flask server (Flask-CORS should be installed) |

---

## 💡 Example Workflows

### Workflow 1: Symmetric Encryption (AES)
```
1. Select AES
2. Type: "Secret Message"
3. Type passphrase or click "Generate passphrase"
4. Watch strength meter
5. Click "Encrypt"
6. Result: Base64 ciphertext
7. Click "Decrypt" to verify
```

### Workflow 2: RSA Client-Only
```
1. Select RSA
2. Enter passphrase
3. Click "Generate RSA keypair"
4. Export private key → save encrypted_private_key_*.key
5. Share public key with recipient
6. Recipient: paste public key, enter message, encrypt
7. You: import private key, paste ciphertext, decrypt
```

### Workflow 3: RSA with Server
```
1. Select RSA, generate keypair with passphrase
2. Set server URL: http://localhost:5000
3. Click "Send public key to server"
4. Type: "Hello, Server!"
5. Click "Encrypt"
6. Click "Send encrypted to server"
7. Output shows: "Hello, Server!" (decrypted by server)
```

---

## 🎓 Educational Notes

This project demonstrates:
- ✅ Web Crypto API (client-side encryption)
- ✅ PBKDF2 key derivation
- ✅ AES-GCM authenticated encryption
- ✅ RSA-OAEP asymmetric encryption
- ✅ Flask REST API design
- ✅ Client-server key exchange
- ✅ Real-time UI feedback
- ✅ File import/export

---

## ⚠️ Important Notes

**This is a LEARNING/DEMO tool. NOT for production use without:**
- Security audit
- HTTPS (not HTTP)
- Authentication/authorization
- Rate limiting
- Secure key storage
- Access logging

---

## 📞 Support

For issues or questions:
1. Check `README.md` for full documentation
2. Read `IMPLEMENTATION_SUMMARY.md` for technical details
3. Review `server/README.md` for server-specific info
4. Run `python test_integration.py` to verify setup

---

## 🎉 Completed Features

- [x] Passphrase strength meter (real-time)
- [x] Passphrase generator (configurable length)
- [x] Passphrase copy to clipboard
- [x] Export encrypted private key
- [x] Import encrypted private key
- [x] Python Flask server
- [x] Public key transmission (client → server)
- [x] RSA encryption/decryption (client + server)
- [x] CORS support
- [x] Integration tests (automated)
- [x] Comprehensive documentation
- [x] Quick reference guide (this file)

---

**Project Status**: ✅ Complete & Tested  
**Last Updated**: November 28, 2025  
**Test Results**: All endpoints responding, encryption verified end-to-end
