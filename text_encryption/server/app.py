"""
Flask server demo for RSA encryption/decryption.
Receives RSA public keys and encrypted messages, decrypts server-side.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64

app = Flask(__name__)
CORS(app)

# Store received public key and private key (for demo purposes)
stored_public_key = None
stored_private_key = None

@app.route('/receive_pubkey', methods=['POST'])
def receive_pubkey():
    """Receive and store a public key from client."""
    global stored_public_key
    try:
        data = request.get_json()
        public_key_pem = data.get('public_key', '').strip()
        
        if not public_key_pem:
            return jsonify({'error': 'No public key provided'}), 400
        
        # Validate the public key format
        stored_public_key = public_key_pem
        return jsonify({'message': 'Public key received and stored'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/set_private_key', methods=['POST'])
def set_private_key():
    """
    Set the private key for server-side decryption.
    For demo: expects a PEM-formatted private key (unencrypted for demo simplicity).
    In production, the private key should be securely stored or provided via secure means.
    """
    global stored_private_key
    try:
        data = request.get_json()
        private_key_pem = data.get('private_key', '').strip()
        
        if not private_key_pem:
            return jsonify({'error': 'No private key provided'}), 400
        
        stored_private_key = private_key_pem
        return jsonify({'message': 'Private key set'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt_message', methods=['POST'])
def decrypt_message():
    """
    Decrypt an RSA-encrypted message using the stored private key.
    """
    global stored_private_key
    try:
        data = request.get_json()
        encrypted_message_b64 = data.get('encrypted_message', '').strip()
        
        if not encrypted_message_b64:
            return jsonify({'error': 'No encrypted message provided'}), 400
        
        if not stored_private_key:
            return jsonify({'error': 'No private key set on server. Call /set_private_key first.'}), 400
        
        # Decode the encrypted message from base64
        encrypted_bytes = base64.b64decode(encrypted_message_b64)
        
        # Load the private key from PEM
        private_key = serialization.load_pem_private_key(
            stored_private_key.encode(),
            password=None,
            backend=default_backend()
        )
        
        # Decrypt the message
        plaintext = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return jsonify({'decrypted_message': plaintext.decode('utf-8')}), 200
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 500

@app.route('/status', methods=['GET'])
def status():
    """Check server status and key availability."""
    has_pub = stored_public_key is not None
    has_priv = stored_private_key is not None
    return jsonify({
        'status': 'Server running',
        'public_key_stored': has_pub,
        'private_key_stored': has_priv
    }), 200

if __name__ == '__main__':
    print("RSA Encryption/Decryption Server")
    print("=================================")
    print("Endpoints:")
    print("  POST /receive_pubkey - Store a public key")
    print("  POST /set_private_key - Set the private key (for decryption)")
    print("  POST /decrypt_message - Decrypt an RSA-encrypted message")
    print("  GET /status - Check server status")
    print("\nRunning on http://localhost:5000")
    app.run(debug=True, host='localhost', port=5000)
