// app.js - Client-side AES/DES/RSA encryptor with strength meter & generator
async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const passKey = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salt, iterations: 250000, hash: 'SHA-256' }, passKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt','decrypt']);
}
function concatBuffers(...buffers) {
  let total = 0; for (const b of buffers) total += b.byteLength;
  const out = new Uint8Array(total); let offset = 0;
  for (const b of buffers) { out.set(new Uint8Array(b), offset); offset += b.byteLength; }
  return out.buffer;
}
function abToBase64(buf) {
  const bytes = new Uint8Array(buf); let binary = ''; const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  return btoa(binary);
}
function base64ToAb(base64) {
  const binary = atob(base64); const len = binary.length; const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
async function encryptText(plaintext, password) {
  const enc = new TextEncoder(); const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12)); const key = await deriveKey(password, salt.buffer);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, enc.encode(plaintext));
  const packaged = concatBuffers(salt.buffer, iv.buffer, ciphertext);
  return abToBase64(packaged);
}
async function decryptText(packagedBase64, password) {
  const dec = new TextDecoder(); const packaged = base64ToAb(packagedBase64);
  const packagedBytes = new Uint8Array(packaged); const salt = packagedBytes.slice(0, 16).buffer;
  const iv = packagedBytes.slice(16, 28).buffer; const ct = packagedBytes.slice(28).buffer;
  const key = await deriveKey(password, salt); const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct);
  return dec.decode(plainBuf);
}
function encryptDES(plaintext, passphrase) { return CryptoJS.TripleDES.encrypt(plaintext, passphrase).toString(); }
function decryptDES(ciphertext, passphrase) { return CryptoJS.TripleDES.decrypt(ciphertext, passphrase).toString(CryptoJS.enc.Utf8); }
function pemFromBinary(bin, label) {
  const b64 = abToBase64(bin); const chunkSize = 64; let pem = '';
  for (let i = 0; i < b64.length; i += chunkSize) pem += b64.slice(i, i + chunkSize) + '\n';
  return '-----BEGIN ' + label + '-----\n' + pem + '-----END ' + label + '-----\n';
}
function pemToArrayBuffer(pem) {
  const lines = pem.split('\n');
  const filtered = lines.filter(l => !l.includes('BEGIN') && !l.includes('END') && l.trim() !== '');
  return base64ToAb(filtered.join(''));
}
async function generateRSAKeypairAndProtect(passphrase) {
  const keyPair = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' }, true, ['encrypt','decrypt']);
  const pubBuf = await crypto.subtle.exportKey('spki', keyPair.publicKey); const privBuf = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
  const salt = crypto.getRandomValues(new Uint8Array(16)); const iv = crypto.getRandomValues(new Uint8Array(12));
  const sym = await deriveKey(passphrase, salt.buffer);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, sym, privBuf);
  const packaged = concatBuffers(salt.buffer, iv.buffer, encrypted);
  return { publicPem: pemFromBinary(pubBuf, 'PUBLIC KEY'), encryptedPrivateBase64: abToBase64(packaged) };
}
async function importPublicKeyFromPem(pem) {
  const ab = pemToArrayBuffer(pem);
  return crypto.subtle.importKey('spki', ab, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
}
async function importPrivateKeyFromProtected(packagedBase64, passphrase) {
  const packaged = base64ToAb(packagedBase64); const bytes = new Uint8Array(packaged);
  const salt = bytes.slice(0,16).buffer; const iv = bytes.slice(16,28).buffer; const ct = bytes.slice(28).buffer;
  const sym = await deriveKey(passphrase, salt);
  const privBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, sym, ct);
  return crypto.subtle.importKey('pkcs8', privBuf, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
}
async function encryptWithPublicKeyPem(plaintext, pubPem) {
  const key = await importPublicKeyFromPem(pubPem); const enc = new TextEncoder();
  const ct = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, enc.encode(plaintext));
  return abToBase64(ct);
}
async function decryptWithProtectedPrivate(packagedBase64Cipher, protectedPrivBase64, passphrase) {
  const priv = await importPrivateKeyFromProtected(protectedPrivBase64, passphrase);
  const ctBuff = base64ToAb(packagedBase64Cipher);
  const plainBuf = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, priv, ctBuff);
  return new TextDecoder().decode(plainBuf);
}
const plaintextEl = document.getElementById('plaintext'); const passwordEl = document.getElementById('password');
const encryptBtn = document.getElementById('encryptBtn'); const decryptBtn = document.getElementById('decryptBtn');
const copyBtn = document.getElementById('copyBtn'); const outputEl = document.getElementById('output');
const algoEl = document.getElementById('algo'); const rsaSection = document.getElementById('rsaSection');
const genRSA = document.getElementById('genRSA'); const pubkeyEl = document.getElementById('pubkey');
const encPrivateEl = document.getElementById('encPrivate'); const passStrengthMeter = document.getElementById('passStrength');
const passStrengthText = document.getElementById('passStrengthText'); const genLengthEl = document.getElementById('genLength');
const genPassBtn = document.getElementById('genPass'); const copyPassBtn = document.getElementById('copyPass');
const exportEncPrivateBtn = document.getElementById('exportEncPrivate'); const importEncPrivateBtn = document.getElementById('importEncPrivate');
const importEncPrivateFile = document.getElementById('importEncPrivateFile'); const serverUrlEl = document.getElementById('serverUrl');
const sendPubToServerBtn = document.getElementById('sendPubToServer'); const sendEncToServerBtn = document.getElementById('sendEncToServer');
function calculatePassphraseStrength(pass) {
  let strength = 0; if (!pass) return 0;
  strength += Math.min(30, pass.length * 2);
  if (/[a-z]/.test(pass)) strength += 15; if (/[A-Z]/.test(pass)) strength += 15;
  if (/[0-9]/.test(pass)) strength += 20; if (/[^a-zA-Z0-9]/.test(pass)) strength += 20;
  return Math.min(100, strength);
}
function updatePassStrengthDisplay() {
  const pass = passwordEl.value; const score = calculatePassphraseStrength(pass);
  passStrengthMeter.value = score; let label = 'Strength: ';
  if (score < 20) label += 'Weak'; else if (score < 50) label += 'Fair';
  else if (score < 75) label += 'Good'; else label += 'Strong';
  passStrengthText.textContent = label;
}
passwordEl.addEventListener('input', updatePassStrengthDisplay);
function generatePassphrase() {
  const len = parseInt(genLengthEl.value) || 24;
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#\$%^&*()_+-=[]{}|;:,.<>?';
  let pass = ''; for (let i = 0; i < len; i++) pass += chars.charAt(Math.floor(Math.random() * chars.length));
  return pass;
}
genPassBtn.addEventListener('click', () => { const newPass = generatePassphrase(); passwordEl.value = newPass; updatePassStrengthDisplay(); });
copyPassBtn.addEventListener('click', () => {
  if (!passwordEl.value) return alert('No passphrase to copy');
  navigator.clipboard.writeText(passwordEl.value).then(() => alert('Passphrase copied')).catch(err => alert('Copy failed: ' + err.message));
});
exportEncPrivateBtn.addEventListener('click', () => {
  const encPriv = encPrivateEl.value.trim();
  if (!encPriv) return alert('No encrypted private key to export');
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = 'encrypted_private_key_' + timestamp + '.key';
  const blob = new Blob([encPriv], { type: 'text/plain' }); const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
});
importEncPrivateBtn.addEventListener('click', () => importEncPrivateFile.click());
importEncPrivateFile.addEventListener('change', (e) => {
  const file = e.target.files[0]; if (!file) return;
  const reader = new FileReader();
  reader.onload = (evt) => { encPrivateEl.value = evt.target.result.trim(); alert('Encrypted private key imported'); };
  reader.onerror = () => alert('Failed to read file'); reader.readAsText(file);
});
sendPubToServerBtn.addEventListener('click', async () => {
  const serverUrl = serverUrlEl.value.trim(); if (!serverUrl) return alert('Enter server URL');
  const pub = pubkeyEl.value.trim(); if (!pub) return alert('No public key to send');
  sendPubToServerBtn.disabled = true;
  try {
    const response = await fetch(serverUrl + '/receive_pubkey', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ public_key: pub }) });
    const data = await response.json();
    if (response.ok) alert('Public key sent: ' + (data.message || 'OK'));
    else alert('Server error: ' + (data.error || response.statusText));
  } catch (err) { alert('Failed: ' + err.message); }
  finally { sendPubToServerBtn.disabled = false; }
});
sendEncToServerBtn.addEventListener('click', async () => {
  const serverUrl = serverUrlEl.value.trim(); if (!serverUrl) return alert('Enter server URL');
  const enc = outputEl.textContent.trim(); if (!enc || enc === '(no output yet)') return alert('No encrypted output to send');
  sendEncToServerBtn.disabled = true;
  try {
    const response = await fetch(serverUrl + '/decrypt_message', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ encrypted_message: enc }) });
    const data = await response.json();
    if (response.ok) { outputEl.textContent = data.decrypted_message || 'Decrypted'; alert('Message decrypted by server'); }
    else alert('Server error: ' + (data.error || response.statusText));
  } catch (err) { alert('Failed: ' + err.message); }
  finally { sendEncToServerBtn.disabled = false; }
});
encryptBtn.addEventListener('click', async () => {
  const text = plaintextEl.value; const pass = passwordEl.value; const algo = algoEl.value;
  if (!text) return alert('Enter text to encrypt'); if (!pass) return alert('Enter a passphrase');
  encryptBtn.disabled = true; outputEl.textContent = 'Encrypting...';
  try {
    if (algo === 'AES') outputEl.textContent = await encryptText(text, pass);
    else if (algo === 'DES') outputEl.textContent = encryptDES(text, pass);
    else if (algo === 'RSA') {
      const pub = pubkeyEl.value.trim();
      if (!pub) throw new Error('No public key available');
      outputEl.textContent = await encryptWithPublicKeyPem(text, pub);
    }
  } catch (err) { outputEl.textContent = 'Encryption error: ' + err.message; }
  finally { encryptBtn.disabled = false; }
});
decryptBtn.addEventListener('click', async () => {
  const packaged = outputEl.textContent.trim(); const pass = passwordEl.value; const algo = algoEl.value;
  if (!packaged || packaged === '(no output yet)') return alert('No encrypted text to decrypt');
  if (!pass) return alert('Enter the passphrase');
  decryptBtn.disabled = true; outputEl.textContent = 'Decrypting...';
  try {
    if (algo === 'AES') outputEl.textContent = await decryptText(packaged, pass);
    else if (algo === 'DES') outputEl.textContent = decryptDES(packaged, pass);
    else if (algo === 'RSA') {
      const encPriv = encPrivateEl.value.trim();
      if (!encPriv) throw new Error('No encrypted private key found');
      outputEl.textContent = await decryptWithProtectedPrivate(packaged, encPriv, pass);
    }
  } catch (err) { outputEl.textContent = 'Decryption error: ' + err.message; }
  finally { decryptBtn.disabled = false; }
});
copyBtn.addEventListener('click', async () => {
  const text = outputEl.textContent;
  if (!text || text === '(no output yet)') return alert('Nothing to copy');
  try { await navigator.clipboard.writeText(text); alert('Copied to clipboard'); }
  catch (err) { alert('Copy failed: ' + err.message); }
});
algoEl.addEventListener('change', () => { rsaSection.style.display = algoEl.value === 'RSA' ? 'block' : 'none'; });
genRSA.addEventListener('click', async () => {
  const pass = passwordEl.value;
  if (!pass) return alert('Enter a passphrase to protect the private key');
  genRSA.disabled = true; genRSA.textContent = 'Generating...';
  try {
    const { publicPem, encryptedPrivateBase64 } = await generateRSAKeypairAndProtect(pass);
    pubkeyEl.value = publicPem; encPrivateEl.value = encryptedPrivateBase64;
    alert('RSA keypair generated and encrypted');
  } catch (err) { alert('RSA generation error: ' + err.message); }
  finally { genRSA.disabled = false; genRSA.textContent = 'Generate RSA keypair (encrypt private with passphrase)'; }
});
