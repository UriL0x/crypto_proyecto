# src/crypto_utils.py

'''Este archivo contiene utilidades criptográficas para generar claves'''

import os
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# CLAVE MAESTRA
def gen_master_key():
    return os.urandom(32)  # AES-256

# CIFRADO / DESCIFRADO AES-GCM
def aesgcm_encrypt(key: bytes, plaintext: bytes):
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def aesgcm_decrypt(key: bytes, blob: bytes):
    if len(blob) < 12 + 16:
        raise ValueError("Blob cifrado inválido")

    nonce = blob[:12]
    ct = blob[12:]
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, None)

# ESCROW (clave maestra cifrada con passphrase)
def derive_key(passphrase: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    return kdf.derive(passphrase.encode())


def create_escrow(master_key: bytes, passphrase: str) -> bytes:
    salt = os.urandom(16)
    derived = derive_key(passphrase, salt)
    encrypted = aesgcm_encrypt(derived, master_key)
    return salt + encrypted


def recover_master_key(blob: bytes, passphrase: str):
    salt = blob[:16]
    encrypted = blob[16:]
    derived = derive_key(passphrase, salt)
    return aesgcm_decrypt(derived, encrypted)


# SANDBOX: seguridad de rutas
def ensure_in_sandbox(path: Path, sandbox_root: Path):
    path_resolved = path.resolve()
    sandbox_resolved = sandbox_root.resolve()
    if not str(path_resolved).startswith(str(sandbox_resolved)):
        raise PermissionError(f"Intento de acceso fuera de sandbox: {path_resolved}")


def read_bytes_safe(path: Path, sandbox_root: Path):
    ensure_in_sandbox(path, sandbox_root)
    return path.read_bytes()


def write_bytes_safe(path: Path, data: bytes, sandbox_root: Path):
    ensure_in_sandbox(path, sandbox_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
