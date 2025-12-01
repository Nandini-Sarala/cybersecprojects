# Text Encryptor - Complete Project

A client-side AES/DES/RSA encryption toolkit with passphrase strength meter, key management, and optional server integration for RSA decryption.

## Features

### Client-Side Web UI
- **AES-GCM encryption**: PBKDF2-derived keys from passphrase
- **TripleDES (via CryptoJS)**: Passphrase-based encryption
- **RSA-OAEP (2048-bit)**: Asymmetric encryption with passphrase-protected private keys
- **Passphrase strength meter**: Real-time feedback on passphrase complexity
- **Passphrase generator**: Create strong random passphrases with configurable length
- **Export/Import**: Save and restore encrypted private keys as files
- **Server integration**: Send RSA public keys and encrypted messages to a Python Flask server

### Python Flask Server Demo
- Store and manage RSA public keys
- Decrypt RSA-encrypted messages server-side
- CORS-enabled for browser-based requests
- Suitable for demonstrating secure key exchange workflows

## Project Structure

```
text_encryption/
├── web_encrypt/
│   ├── index.html          # UI (AES/DES/RSA algorithm selector, passphrase tools)
│   ├── app.js              # Client-side crypto logic
│   ├── README.md           # Web UI documentation
│   └── requirements.txt     # (optional) if using Python for local testing
├── server/
│   ├── app.py              # Flask server (RSA key storage & decryption)
│   ├── requirements.txt     # Flask, Flask-CORS, cryptography
│   └── README.md           # Server documentation
├── test_integration.py      # Integration test suite
└── README.md               # This file
```

## Quick Start

### 1. Start the Web Server (for UI access)

```powershell
cd web_encrypt
python -m http.server 8000
# Then open http://localhost:8000 in your browser
```

### 2. Start the Flask Server (optional, for server integration)

```powershell
cd server
pip install -r requirements.txt
python app.py
# Server will run at http://localhost:5000
```

### 3. Run Integration Tests

```powershell
python test_integration.py
```

This validates:
- Flask server endpoints
- RSA key generation
- Public key transmission
- Encryption/decryption round-trip

## Usage Examples

### AES Encryption (Client-Side)

1. Open http://localhost:8000
2. Select "AES-GCM" from the Algorithm dropdown
3. Enter your plaintext
4. Enter (or generate) a passphrase
5. Click "Encrypt"
6. To decrypt: click "Decrypt" with the same passphrase

**Output format**: `base64(salt || iv || ciphertext)`

### RSA with Server Integration

1. **Generate RSA keypair**:
   - Select "RSA" algorithm
   - Enter a passphrase to protect the private key
   - Click "Generate RSA keypair"
   - Public key and encrypted private key are displayed

2. **Send public key to server**:
   - Enter server URL: `http://localhost:5000`
   - Click "Send public key to server"

3. **Encrypt and send message**:
   - Enter plaintext
   - Click "Encrypt" (RSA)
   - Click "Send encrypted to server"
   - Server decrypts and returns plaintext

4. **Save/restore your private key**:
   - Click "Export encrypted private key" to download as `.key` file
   - Click "Import encrypted private key" to restore from file

### Passphrase Management

- **Strength meter**: Watch real-time updates as you type (Weak → Fair → Good → Strong)
- **Generate passphrase**: Click "Generate passphrase" for a random 24-character password
- **Adjust length**: Set the length input (8-128 characters) before generating
- **Copy passphrase**: Click "Copy passphrase" to save to clipboard

## Security Notes

⚠️ **This is a learning/demo tool.** For production use:

- Review cryptographic implementations (this demo uses Web Crypto API and cryptography library)
- Authenticate and encrypt server communication (use HTTPS, not HTTP)
- Implement access controls and rate limiting on server endpoints
- Store private keys securely (HSM, KMS, encrypted at-rest)
- Use authenticated key exchange (TLS, client certificates)
- Never transmit unencrypted private keys over the network

**Key Management:**
- Passphrase is critical: anyone with passphrase + encrypted private key can decrypt
- For RSA: private key is encrypted with AES-GCM using PBKDF2-derived key
- If passphrase is lost, encrypted private key cannot be recovered
- Always export and backup encrypted private keys

## Technical Details

### Encryption Formats

**AES-GCM (PBKDF2 key derivation)**:
```
base64(salt || iv || ciphertext)
- salt: 16 bytes (random)
- iv: 12 bytes (random)
- ciphertext: encrypted plaintext
- Key derivation: PBKDF2-SHA256, 250,000 iterations
```

**RSA-OAEP**:
```
base64(ciphertext)
- Key size: 2048-bit
- Padding: OAEP with MGF1-SHA256
```

**Encrypted Private Key (RSA)**:
```
base64(salt || iv || ciphertext)
- Stores PKCS#8 private key encrypted with AES-GCM
- Key derived from user passphrase using PBKDF2-SHA256
```

### Server API

**POST /receive_pubkey**
- Store a client's RSA public key
- Request: `{ "public_key": "PEM-formatted public key" }`
- Response: `{ "message": "Public key received and stored" }`

**POST /set_private_key**
- Set the server's private key for decryption
- Request: `{ "private_key": "PEM-formatted private key" }`
- Response: `{ "message": "Private key set" }`

**POST /decrypt_message**
- Decrypt an RSA-encrypted message
- Request: `{ "encrypted_message": "base64 ciphertext" }`
- Response: `{ "decrypted_message": "plaintext" }`

**GET /status**
- Check server status and key availability
- Response: `{ "status": "Server running", "public_key_stored": bool, "private_key_stored": bool }`

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Cannot connect to web server | Ensure `python -m http.server 8000` is running in web_encrypt folder |
| "ModuleNotFoundError: No module named 'flask'" | Run `pip install -r server/requirements.txt` |
| Cannot decrypt message sent to server | Ensure Flask server is running and private key is set (via /set_private_key endpoint) |
| Server reports "No public key available" | Send your public key first using "Send public key to server" button |
| CORS errors in browser | Ensure Flask-CORS is installed and server is running with CORS enabled |

## Files Reference

- `web_encrypt/index.html` - User interface with algorithm selector, passphrase tools
- `web_encrypt/app.js` - AES/DES/RSA crypto implementation, strength meter, export/import
- `server/app.py` - Flask endpoints for key storage and decryption
- `test_integration.py` - Automated test suite

## Dependencies

**Web UI**: None (uses Web Crypto API, browser-native)

**Server**:
- Flask 2.3+
- Flask-CORS 4.0+
- cryptography 41+

**Testing**:
- requests
- cryptography

Install server dependencies:
```bash
pip install -r server/requirements.txt
```

## Examples & Workflow

### Client-Only Workflow (No Server)

```
1. Generate RSA keypair → public key + encrypted private key
2. Save encrypted private key to file (Export)
3. Share public key with recipient
4. Recipient encrypts message with public key
5. You decrypt with encrypted private key + passphrase (Import & Decrypt)
```

### With Server (Key Escrow / Recovery)

```
1. Generate RSA keypair on client
2. Send public key to server (Server stores it)
3. Set private key on server (For decryption)
4. Client encrypts message with public key
5. Client sends ciphertext to server
6. Server decrypts and returns plaintext
```

## Browser Compatibility

- Chrome 37+
- Edge 79+
- Firefox 34+
- Safari 11+

All modern browsers with Web Crypto API support.

## Next Steps for Production

1. Move to HTTPS (not HTTP)
2. Add authentication (API keys, OAuth)
3. Implement rate limiting
4. Add audit logging
5. Use encrypted/secure key storage
6. Review and test with security audit
7. Deploy to production server (not development server)

## License

This is a learning/demo project. Use and modify as needed for educational purposes.
