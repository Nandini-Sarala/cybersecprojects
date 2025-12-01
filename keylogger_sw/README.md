# keylogger_sw

WARNING: This directory contains keylogger code intended for educational and research purposes only. Do NOT run these programs on systems you do not own or have explicit authorization to test. Unauthorized use of keyloggers is illegal and unethical.

This folder contains simple Python keylogger examples and small utilities used for local testing in a controlled lab environment. The implementations are intentionally minimal for educational clarity and are NOT production-ready.

Contents
- `keylogger.py` — minimal keylogger that writes raw keystroke text to `keystrokes.log` using `pynput`.
- `keyloggerwithencryption.py` — same as above but encrypts each keystroke with a symmetric key (Fernet) and writes base64-like encrypted lines to `keystrokes_encrypted.log`.
- `generate_saving_aeskey.py` — generates a Fernet key and saves it as `secret.key` (used by the encrypted logger and the decryptor).
- `decrypting_logfile.py` — reads `keystrokes_encrypted.log` and decrypts each line using the key in `secret.key`, printing plaintext to stdout.
- `secret.key` — example key file (already present in this repo). Treat this file as sensitive — anyone with it can decrypt logs produced by the encrypted keylogger.

Prerequisites
- Python 3.8+ (3.10 or newer recommended)
- pip

Dependencies
The code in this folder uses:
- `pynput` (for capturing keyboard events)
- `cryptography` (Fernet symmetric encryption)

You can install dependencies into a virtual environment (recommended):

Windows PowerShell example

```powershell
cd "E:\cybersecprojects\keylogger_sw"
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
& ".\.venv\Scripts\Activate.ps1"
python -m pip install --upgrade pip
pip install pynput cryptography
# or, if you maintain a requirements.txt, run:
# pip install -r requirements.txt
```

Usage (safe lab only)

1) Generate a key (once) — this creates `secret.key` used by the encrypted keylogger and the decryptor:

```powershell
python generate_saving_aeskey.py
```

2) Run the encrypted keylogger (in a lab VM / test account only)

```powershell
python keyloggerwithencryption.py
```

This will append encrypted lines to `keystrokes_encrypted.log` in the same folder. Each line is a Fernet-encrypted chunk (binary written in base64-friendly form).

3) Inspect / decrypt collected logs (offline, in a safe environment)

```powershell
python decrypting_logfile.py
```

It will read `secret.key` and `keystrokes_encrypted.log` and print the recovered keystrokes to the console.

Notes and safe-handling guidance
- ALWAYS run these scripts only on systems you control and for which you have explicit, written permission.
- Treat `secret.key` as a secret: anyone who obtains it can decrypt the logs.
- The code is intentionally simplistic: it appends every keystroke and does not filter sensitive data (passwords, tokens, etc.). Use responsibly.
- Consider additional safeguards for research: isolated VM, network disabled, limited runtime, and secure deletion of logs and keys after testing.

Development / contribution
- If you add features or dependencies, consider adding a `requirements.txt` to this folder. Example:

```
pynput
cryptography

```

License & Ethics
- This repository is provided for educational purposes only. The author(s) are not responsible for misuse. By using these tools you agree to follow all applicable laws and to obtain proper authorization before testing.

Questions?
- If you want, I can: add a `requirements.txt`, add a safer demo harness that records only synthetic events, or implement a test runner that demonstrates encryption/decryption without capturing real keyboard input. Tell me which you prefer.
