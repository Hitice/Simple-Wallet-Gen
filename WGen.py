import os
import hashlib
import binascii

def generate_private_key():
    # Generate 32 random bytes for the private key
    private_key = os.urandom(32)
    return private_key

def private_key_to_wif(private_key):
    # Convert the private key to WIF
    extended_key = b'\x80' + private_key
    hashed_key = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()
    wif = extended_key + hashed_key[:4]
    return binascii.b2a_base58(wif)

def main():
    private_key = generate_private_key()
    wif = private_key_to_wif(private_key)
    
    print("Private Key (Hex):", private_key.hex())
    print("Private Key (WIF):", wif.decode())

if __name__ == "__main__":
    main()
