import os
import hashlib
import base58
from Crypto.Hash import RIPEMD160
import ecdsa

def generate_private_key():
    """Generates a 32-byte private key."""
    return os.urandom(32)

def private_key_to_wif(private_key):
    """Converts the private key to Wallet Import Format (WIF)."""
    # Adds the prefix 0x80 to indicate this is a private key
    extended_key = b'\x80' + private_key
    
    # Perform two rounds of SHA-256 hashing
    hashed_key = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()
    
    # Add the first 4 bytes of the hashed result as a checksum
    wif = extended_key + hashed_key[:4]
    
    # Encode the private key in WIF format using base58
    return base58.b58encode(wif).decode('utf-8')

def private_key_to_public_key(private_key):
    """Converts the private key into a public key using ECDSA (SECP256k1 curve)."""
    # Use ecdsa library to derive the public key from the private key
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    # Add 0x04 prefix to indicate uncompressed public key
    public_key = b'\x04' + vk.to_string()
    return public_key

def public_key_to_address(public_key):
    """Converts the public key to a Bitcoin address."""
    # Perform SHA-256 hashing on the public key
    sha256_pk = hashlib.sha256(public_key).digest()
    
    # Perform RIPEMD-160 hashing on the result of the SHA-256 hash
    ripemd160 = RIPEMD160.new()
    ripemd160.update(sha256_pk)
    hashed_pk = ripemd160.digest()
    
    # Add 0x00 prefix to indicate a P2PKH address (Pay-to-PubKey-Hash)
    extended_ripemd160 = b'\x00' + hashed_pk
    
    # Perform two rounds of SHA-256 hashing to generate the checksum
    checksum = hashlib.sha256(hashlib.sha256(extended_ripemd160).digest()).digest()[:4]
    
    # Append the checksum to the end of the hashed public key
    address = base58.b58encode(extended_ripemd160 + checksum).decode('utf-8')
    return address

def main():
    # Generate the private key
    private_key = generate_private_key()
    
    # Convert the private key to WIF format
    wif = private_key_to_wif(private_key)
    
    # Derive the public key from the private key
    public_key = private_key_to_public_key(private_key)
    
    # Convert the public key into a Bitcoin address
    address = public_key_to_address(public_key)
    
    # Display the private key and Bitcoin address to the user
    print("### WARNING! ###")
    print("Your private key and Bitcoin address have been generated.")
    print("NEVER share your private key with anyone.")
    print("Store both pieces of information securely, preferably offline.")
    print("\nPrivate Key (WIF):", wif)
    print("Bitcoin Address:", address)

if __name__ == "__main__":
    main()
