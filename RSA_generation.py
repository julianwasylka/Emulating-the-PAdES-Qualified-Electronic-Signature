from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import sys
import time
import threading
import os

KEY_SIZE = 4096
CIPHER_MODE = AES.MODE_EAX
IV = get_random_bytes(16) # initial vector, to randomize

stop_progress_bar = threading.Event()

def progress_bar_animation(total_length=50):
    sys.stdout.write("Generating RSA keys: [")
    sys.stdout.flush()
    
    current_progress = 0
    while not stop_progress_bar.is_set():
        if current_progress < total_length:
            sys.stdout.write("#")
            sys.stdout.flush()
            current_progress += 1
        time.sleep(0.6) 
    
    while current_progress < total_length:
        sys.stdout.write("#")
        sys.stdout.flush()
        current_progress += 1
    
    sys.stdout.write("]\n")
    sys.stdout.flush()

def create_rsa_keys():
    pin = input("Enter PIN: ").encode()
    aes_key = SHA256.new(pin).digest()

    progress_thread = threading.Thread(target=progress_bar_animation)
    progress_thread.start()

    try:
        rsa_key = RSA.generate(bits=KEY_SIZE)

        private_key = rsa_key.export_key(format='PEM')
        public_key = rsa_key.publickey().export_key(format='PEM')

        cipher = AES.new(aes_key, CIPHER_MODE)
        encrypted_private_key = cipher.encrypt(private_key)
    finally:
        stop_progress_bar.set()
        progress_thread.join()

    with open("projekt/keys/rsa_private.bin", "wb") as f:
        f.write(encrypted_private_key)

    with open("projekt/keys/rsa_public.pem", "wb") as f:
        f.write(public_key)

    print("Keys saved to files in the keys folder.")

if __name__ == "__main__":
    create_rsa_keys()