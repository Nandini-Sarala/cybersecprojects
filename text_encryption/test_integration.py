#!/usr/bin/env python3
"""
Quick test/demo script for the text encryptor project.
Tests AES, DES, and RSA encryption flows both client-side and with server integration.
"""

import requests
import json
import time
import subprocess
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

def test_server_endpoints():
    """Test Flask server endpoints."""
    print("\n" + "="*60)
    print("Testing Flask Server Endpoints")
    print("="*60)
    
    base_url = "http://localhost:5000"
    
    # Test 1: Check server status
    print("\n[1/4] Testing /status endpoint...")
    try:
        response = requests.get(f"{base_url}/status", timeout=2)
        if response.status_code == 200:
            data = response.json()
            print(f"  ✓ Server status: {data['status']}")
            print(f"    Public key stored: {data.get('public_key_stored', False)}")
            print(f"    Private key stored: {data.get('private_key_stored', False)}")
        else:
            print(f"  ✗ Error: {response.status_code}")
            return False
    except Exception as e:
        print(f"  ✗ Failed to connect: {e}")
        print(f"    Make sure Flask server is running: python server/app.py")
        return False
    
    # Test 2: Generate RSA keypair
    print("\n[2/4] Generating test RSA keypair...")
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Export keys to PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        print("  ✓ RSA keypair generated (2048-bit)")
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False
    
    # Test 3: Send public key to server
    print("\n[3/4] Testing /receive_pubkey endpoint...")
    try:
        response = requests.post(
            f"{base_url}/receive_pubkey",
            json={"public_key": public_pem},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            print(f"  ✓ Public key accepted: {data.get('message', 'OK')}")
        else:
            print(f"  ✗ Error: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False
    
    # Test 4: Set private key and test decryption
    print("\n[4/4] Testing /set_private_key and /decrypt_message...")
    try:
        # Set private key
        response = requests.post(
            f"{base_url}/set_private_key",
            json={"private_key": private_pem},
            timeout=5
        )
        if response.status_code != 200:
            print(f"  ✗ Failed to set private key: {response.status_code}")
            return False
        
        # Encrypt a test message with the public key
        plaintext = "Hello, Server!"
        public_key = serialization.load_pem_public_key(
            public_pem.encode(),
            backend=default_backend()
        )
        ciphertext = public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        ciphertext_b64 = base64.b64encode(ciphertext).decode()
        
        # Send encrypted message to server
        response = requests.post(
            f"{base_url}/decrypt_message",
            json={"encrypted_message": ciphertext_b64},
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            decrypted = data.get('decrypted_message', '')
            if decrypted == plaintext:
                print(f"  ✓ Encryption/Decryption successful!")
                print(f"    Sent: '{plaintext}'")
                print(f"    Received: '{decrypted}'")
            else:
                print(f"  ✗ Decryption mismatch!")
                print(f"    Expected: '{plaintext}'")
                print(f"    Got: '{decrypted}'")
                return False
        else:
            print(f"  ✗ Decryption failed: {response.status_code}")
            print(f"    Response: {response.text}")
            return False
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False
    
    return True

def main():
    print("\n")
    print("╔" + "="*58 + "╗")
    print("║" + " Text Encryptor - Integration Test ".center(58) + "║")
    print("╚" + "="*58 + "╝")
    
    print("\nThis test validates:")
    print("  • Flask server status and endpoints")
    print("  • RSA key generation")
    print("  • Public key transmission to server")
    print("  • RSA encryption (client) + decryption (server)")
    
    success = test_server_endpoints()
    
    print("\n" + "="*60)
    if success:
        print("✓ ALL TESTS PASSED")
        print("\nNext steps:")
        print("  1. Start the web server: python -m http.server 8000")
        print("  2. Open http://localhost:8000 in your browser")
        print("  3. Try the AES/DES/RSA encryption flows")
        print("  4. For RSA server integration:")
        print("     - Set server URL to: http://localhost:5000")
        print("     - Generate RSA keypair")
        print("     - Send public key to server")
        print("     - Encrypt a message and send to server for decryption")
    else:
        print("✗ TESTS FAILED")
        print("\nTroubleshooting:")
        print("  • Is the Flask server running? python server/app.py")
        print("  • Is the server accessible at http://localhost:5000?")
        print("  • Check firewall settings")
    
    print("="*60 + "\n")
    return 0 if success else 1

if __name__ == '__main__':
    sys.exit(main())
