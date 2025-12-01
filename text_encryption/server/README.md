# RSA Server Demo

A Flask server that demonstrates RSA encryption/decryption with support for storing public keys and decrypting client-side encrypted messages.

## Setup

1. **Install dependencies:**
   ```bash
   cd server
   pip install -r requirements.txt
   ```

2. **Run the server:**
   ```bash
   python app.py
   ```
   The server will start at `http://localhost:5000`.

## Endpoints

### POST /receive_pubkey
Receive and store a client's RSA public key.

**Request:**
```json
{
  "public_key": "-----BEGIN PUBLIC KEY-----\n....\n-----END PUBLIC KEY-----"
}
```

**Response:**
```json
{
  "message": "Public key received and stored"
}
```

### POST /set_private_key
Set the server-side private key (needed for decryption). For demo purposes only.

**Request:**
```json
{
  "private_key": "-----BEGIN PRIVATE KEY-----\n....\n-----END PRIVATE KEY-----"
}
```

**Response:**
```json
{
  "message": "Private key set"
}
```

### POST /decrypt_message
Decrypt an RSA-encrypted message.

**Request:**
```json
{
  "encrypted_message": "base64_encoded_ciphertext"
}
```

**Response:**
```json
{
  "decrypted_message": "Hello, World!"
}
```

### GET /status
Check server status and key availability.

**Response:**
```json
{
  "status": "Server running",
  "public_key_stored": true,
  "private_key_stored": true
}
```

## Workflow Example (Browser)

1. **Open the web UI** at `http://localhost:8000` (or wherever the web_encrypt folder is served).
2. **Switch to RSA** algorithm.
3. **Enter a passphrase** and click **Generate RSA keypair**.
4. **Set the server URL** to `http://localhost:5000`.
5. **Click "Send public key to server"** to upload your public key.
6. **Export your encrypted private key** (save it safely).
7. **Create a new keypair or restore one**, then:
   - Enter text to encrypt.
   - Click **Encrypt** to generate an RSA-encrypted message.
   - Click **"Send encrypted to server"** to decrypt it server-side.
   - The plaintext will appear in the output area.

## Security Notes

- This is a **demo/learning tool**. Do not use in production without proper security review.
- The private key is exposed here for demo simplicity. In production:
  - Store private keys securely (HSM, KMS, etc.).
  - Use authentication and TLS/HTTPS.
  - Implement rate limiting and access controls.
- CORS is enabled for demo convenience; restrict in production.

## Testing with curl

```bash
# Check server status
curl http://localhost:5000/status

# Send a public key (replace with actual key)
curl -X POST http://localhost:5000/receive_pubkey \
  -H "Content-Type: application/json" \
  -d '{"public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"}'

# Set a private key
curl -X POST http://localhost:5000/set_private_key \
  -H "Content-Type: application/json" \
  -d '{"private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"}'

# Decrypt a message
curl -X POST http://localhost:5000/decrypt_message \
  -H "Content-Type: application/json" \
  -d '{"encrypted_message": "base64_encoded_ciphertext"}'
```
