Text Encryptor (client-side)

This demo provides a small, browser-based toolkit to encrypt and decrypt short text using three modes:

- AES (AES‑GCM): passphrase → PBKDF2 → AES‑GCM (recommended for symmetric use)
- DES (TripleDES via CryptoJS): passphrase-based TripleDES (compatibility/demo)
- RSA (RSA-OAEP): asymmetric encrypt with public key; private key is protected by a passphrase (the private key PKCS#8 is symmetrically encrypted and packaged)

Files
- `index.html` — UI (plain text, passphrase, algorithm selector, RSA key tools)
- `app.js` — client-side logic for AES, DES and RSA flows (Web Crypto API + CryptoJS)
- `README.md` — this file

Quick usage
1. Open `e:\cybersecprojects\text_encryption\web_encrypt\index.html` in a modern browser (Chrome, Edge, Firefox). For best behavior open via HTTP (see "Run locally").
2. Choose algorithm from the "Algorithm" dropdown: AES, DES, or RSA.
3. Enter the plaintext in the "Plain text" box.
4. **Passphrase management:**
   - Enter a passphrase in the "Passphrase" field.
   - Watch the **strength meter** update in real-time (Weak / Fair / Good / Strong).
   - Click **"Generate passphrase"** to create a strong random passphrase (customize length with the input field).
   - Click **"Copy passphrase"** to copy the generated or current passphrase to clipboard.
5. Click "Encrypt":
	 - AES: output is base64(salt||iv||ciphertext). Salt = 16 bytes, IV = 12 bytes.
	 - DES: output is CryptoJS TripleDES cipher string (base64-like). CryptoJS derives the key from the passphrase.
	 - RSA: you must first generate (or paste) a public key. Click "Generate RSA keypair" to create a keypair—the public key (PEM) will appear, and the encrypted private key (packaged base64) will appear in the "Encrypted private key" box. Use the public key to encrypt; use the encrypted private key + passphrase to decrypt.
   - **Export/Import private keys:** Use the "Export encrypted private key" button to download your encrypted private key as a `.key` file. Use "Import encrypted private key" to restore a previously saved key.

Decryption notes
- AES: paste the base64 packaged output into the output area (or keep it there) and click Decrypt with the same passphrase.
- DES: place the TripleDES ciphertext in the output area and click Decrypt with the same passphrase.
- RSA: to decrypt, the encrypted private key (the packaged base64 created during RSA generation) must be present in the "Encrypted private key" box and the correct passphrase entered; Decrypt will unlock the private key and decrypt the RSA ciphertext.

Formats & packaging
- AES protected blobs: base64 encoding of (salt || iv || ciphertext)
	- salt: 16 bytes (PBKDF2 salt)
	- iv: 12 bytes (AES‑GCM IV)
	- ciphertext: remaining bytes
- DES (CryptoJS TripleDES): CryptoJS ciphertext string (base64-like) returned by CryptoJS.TripleDES.encrypt
- RSA:
	- Public key: PEM (SPKI) displayed as `-----BEGIN PUBLIC KEY-----` ... `-----END PUBLIC KEY-----`.
	- Encrypted private key: base64 packaged blob (salt||iv||ciphertext) produced by encrypting PKCS#8 private key using AES-GCM with a key derived from your passphrase.
	- RSA ciphertext produced by RSA-OAEP is base64 of the raw RSA output.

Run locally (recommended)
Open a local HTTP server from the `web_encrypt` folder so the page runs without file:// restrictions. From PowerShell in `e:\cybersecprojects\text_encryption\web_encrypt`: 

```powershell
cd "e:\cybersecprojects\text_encryption\web_encrypt"
python -m http.server 8000
# then open http://localhost:8000 in your browser
```

Security notes
- This is a learning/demo tool. Do not consider it production-ready for high-value secrets without reviewing key management, algorithm choice and secure deployment.
- The passphrase is critical: anyone with the passphrase + the packaged output can decrypt. Use long, unique passphrases (password manager / diceware recommended). Use the **passphrase generator** for strong random passphrases.
- For RSA the private key is encrypted with a symmetric key derived from your passphrase. If you lose the passphrase you cannot recover the private key.
- For production, prefer well-reviewed libraries and server-side protections for key storage and use proper authenticated key exchange when sharing encrypted messages.

## Server Integration (Optional)

The project includes a **Python Flask server demo** that can decrypt RSA-encrypted messages server-side. This demonstrates a realistic workflow where a client encrypts data with a server's public key, and the server decrypts it.

### Starting the server

1. **Install server dependencies:**
   ```powershell
   cd "..\server"
   pip install -r requirements.txt
   ```

2. **Run the server:**
   ```powershell
   python app.py
   ```
   The server starts at `http://localhost:5000`.

3. **Generate RSA keypair in the web UI** (if not already done).

4. **Send your public key to the server:**
   - In the web UI, enter the server URL: `http://localhost:5000`
   - Click **"Send public key to server"**

5. **Encrypt a message and send it to the server:**
   - Enter text in the "Plain text" box
   - Click **Encrypt** (RSA algorithm should be selected)
   - Click **"Send encrypted to server"**
   - The server will decrypt it and return the plaintext

### Server API Endpoints

- `POST /receive_pubkey` — Store a client's public key
- `POST /set_private_key` — Set the server's private key (for decryption)
- `POST /decrypt_message` — Decrypt an RSA-encrypted message
- `GET /status` — Check server status and key availability

See `server/README.md` for full endpoint documentation and examples.

Previous steps (completed)
- ✅ Add a passphrase-strength meter and a passphrase generator.
- ✅ Add an "export/import" button for encrypted private key files.
- ✅ Integrate with a small server demo (Python Flask) to show sending an RSA public key to a recipient and decrypting server-side.
