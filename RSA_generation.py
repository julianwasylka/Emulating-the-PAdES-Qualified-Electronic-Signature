from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

KEY_SIZE = 4096
CIPHER_MODE = AES.MODE_EAX
IV = get_random_bytes(16) # initial vector, to randomize

def create_rsa_keys():
    pin = input("Enter PIN: ").encode()
    aes_key = SHA256.new(pin).digest()

    rsa_key = RSA.generate(bits=KEY_SIZE)

    private_key = rsa_key.export_key(format='PEM')
    public_key = rsa_key.publickey().export_key(format='PEM')

    cipher = AES.new(aes_key, CIPHER_MODE)
    encrypted_private_key = cipher.encrypt(private_key)

    with open("keys/rsa_private.bin", "wb") as f:
        f.write(encrypted_private_key)

    with open("keys/rsa_public.pem", "wb") as f:
        f.write(public_key)

    print("Keys saved to files in the keys folder.")

if __name__ == "__main__":
    create_rsa_keys()