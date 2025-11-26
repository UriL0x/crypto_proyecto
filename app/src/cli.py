# src/cli.py

'''Este archivo implementa una interfaz de línea de comandos (CLI) para cifrar y descifrar archivos
usando una clave maestra almacenada de forma segura en un "escrow" cifrado'''

import argparse
import sys
from pathlib import Path
import getpass
import os

from crypto_utils import (
    aesgcm_encrypt, aesgcm_decrypt,
    gen_master_key,
    create_escrow, recover_master_key,
    ensure_in_sandbox, read_bytes_safe, write_bytes_safe
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SANDBOX = PROJECT_ROOT / "sandbox"
ESCROW_DIR = PROJECT_ROOT / "escrow"
ESCROW_FILE = ESCROW_DIR / "recovery.enc"

def cmd_init(args):
    SANDBOX.mkdir(parents=True, exist_ok=True)
    ESCROW_DIR.mkdir(parents=True, exist_ok=True)

    pass1 = getpass.getpass("Passphrase de recuperación: ")
    pass2 = getpass.getpass("Confirmar passphrase: ")

    if pass1 != pass2:
        print("ERROR: Las passphrases no coinciden.")
        sys.exit(1)

    master = gen_master_key()
    blob = create_escrow(master, pass1)
    ESCROW_FILE.write_bytes(blob)

    print(f"[OK] Escrow creado en: {ESCROW_FILE}")

def load_master_key():
    if not ESCROW_FILE.exists():
        print("ERROR: No existe recovery.enc. Ejecute 'init' primero.")
        sys.exit(1)

    passphrase = getpass.getpass("Passphrase de recuperación: ")
    blob = ESCROW_FILE.read_bytes()
    try:
        master = recover_master_key(blob, passphrase)
    except Exception:
        print("ERROR: Passphrase incorrecta o escrow corrupto.")
        sys.exit(2)

    return master

def cmd_encrypt(in_file, out_file):
    infile = SANDBOX / "input" / in_file
    outfile = SANDBOX / "output" / out_file

    ensure_in_sandbox(infile, SANDBOX)
    ensure_in_sandbox(outfile, SANDBOX)

    if not infile.exists():
        print("ERROR: Archivo de entrada no existe.")
        sys.exit(1)

    master = load_master_key()

    plaintext = read_bytes_safe(infile, SANDBOX)
    encrypted = aesgcm_encrypt(master, plaintext)

    write_bytes_safe(outfile, encrypted, SANDBOX)

    print(f"[OK] Archivo cifrado: {outfile}")

def cmd_decrypt(args):
    infile = SANDBOX / "output" / args.infile
    outfile = SANDBOX / "input" / args.outfile

    ensure_in_sandbox(infile, SANDBOX)
    ensure_in_sandbox(outfile, SANDBOX)

    if not infile.exists():
        print("ERROR: Archivo cifrado no existe.")
        input("Presione Enter para continuar...")
        sys.exit(1)

    master = load_master_key()

    encrypted = read_bytes_safe(infile, SANDBOX)

    try:
        plaintext = aesgcm_decrypt(master, encrypted)
    except Exception:
        print("ERROR: No se pudo descifrar. Archivo corrupto.")
        input("Presione Enter para continuar...")
        sys.exit(2)

    write_bytes_safe(outfile, plaintext, SANDBOX)

    print(f"[OK] Archivo descifrado: {outfile}")
    input("Presione Enter para continuar...")

def cmd_test(args):
    print("== TEST CIFRADO/DESCIFRADO ==")

    tmp_in = SANDBOX / "test_input.txt"
    tmp_enc = SANDBOX / "test.enc"
    tmp_dec = SANDBOX / "test_dec.txt"

    tmp_in.write_text("PRUEBA123")

    cmd_encrypt("test_input.txt", "test.enc")
    cmd_decrypt(argparse.Namespace(infile="test.enc", outfile="test_dec.txt"))

    if tmp_dec.read_text() == "PRUEBA123":
        print("[OK] TEST COMPLETADO CORRECTAMENTE")
        input("Presione Enter para continuar...")
    else:
        print("[ERROR] TEST FALLÓ")
        input("Presione Enter para continuar...")

def main():
    run = True
    while run:
        print("// CIFRADO DE ARCHIVOS - CLI //")
        print("-------------------------------")
        print("Seleccione una opción:")
        print("[a] Iniciar (crear escrow)")
        print("[b] Cifrar archivo")
        print("[c] Descifrar archivo")
        print("[d] Testear cifrado/descifrado")
        option = input(">> Opción => ").strip().lower()
        
        if option == 'a':
            cmd_init(None)
        elif option == 'b':
            infile = input(">> Nombre del archivo a cifrar: ").strip()
            outfile = input(">> Nombre de salida del archivo cifrado: ").strip()
            cmd_encrypt(infile, outfile)
        elif option == 'c':
            infile = input(">> Nombre del archivo a descifrar: ").strip()
            outfile = input(">> Nombre de salida del archivo descifrado: ").strip()
            args = argparse.Namespace(infile=infile, outfile=outfile)
            cmd_decrypt(args)
        elif option == 'd':
            cmd_test(None)
        elif option == 'cls':
            os.system('cls' if os.name == 'nt' else 'clear')
        elif option == 'exit':
            run = False
        else:
            print("Opción no válida.")

if __name__ == "__main__":
    main()
