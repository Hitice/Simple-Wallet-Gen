import os
import hashlib
import base58
from Crypto.Hash import RIPEMD160

def generate_private_key():
    """Gera uma chave privada de 32 bytes."""
    return os.urandom(32)

def private_key_to_wif(private_key):
    """Converte a chave privada para o formato Wallet Import Format (WIF)."""
    extended_key = b'\x80' + private_key
    hashed_key = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()
    wif = extended_key + hashed_key[:4]
    return base58.b58encode(wif).decode('utf-8')

def private_key_to_public_key(private_key):
    """Converte a chave privada para uma chave pública."""
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    public_key = b'\x04' + vk.to_string()  # Prefixo 0x04 para chave pública não comprimida
    return public_key

def public_key_to_address(public_key):
    """Converte uma chave pública em um endereço de Bitcoin."""
    sha256_pk = hashlib.sha256(public_key).digest()
    ripemd160 = RIPEMD160.new()
    ripemd160.update(sha256_pk)
    hashed_pk = ripemd160.digest()
    extended_ripemd160 = b'\x00' + hashed_pk  # Prefixo 0x00 para endereços P2PKH

    # Realiza dois hashes SHA-256 para gerar o checksum
    checksum = hashlib.sha256(hashlib.sha256(extended_ripemd160).digest()).digest()[:4]
    
    # Adiciona o checksum ao final e codifica em base58
    address = base58.b58encode(extended_ripemd160 + checksum).decode('utf-8')
    return address

def main():
    # Gera a chave privada
    private_key = generate_private_key()
    
    # Converte para WIF
    wif = private_key_to_wif(private_key)
    
    # Gera a chave pública a partir da chave privada
    public_key = private_key_to_public_key(private_key)
    
    # Converte a chave pública para um endereço de Bitcoin
    address = public_key_to_address(public_key)
    
    # Exibe o resultado ao usuário
    print("### ATENÇÃO! ###")
    print("A chave privada e o endereço da carteira foram gerados.")
    print("NUNCA compartilhe sua chave privada com ninguém.")
    print("Armazene ambos os dados em um local seguro e de preferência offline.")
    print("\nChave privada (WIF):", wif)
    print("Endereço de Bitcoin:", address)

if __name__ == "__main__":
    main()
