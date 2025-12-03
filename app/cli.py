import argparse
import sys
from pathlib import Path
import getpass
import os
import logging
from datetime import datetime
from tests.test import (
    test_basic_encrypt_decrypt,
    test_avalanche_effect,
    test_entropy_analysis,
    test_performance_benchmark,
    test_multiple_data_sizes,
    test_bit_balance
)
from src.crypto_utils import (
    aesgcm_encrypt, aesgcm_decrypt,
    gen_master_key,
    create_escrow, recover_master_key,
    ensure_in_sandbox, read_bytes_safe, write_bytes_safe
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SANDBOX = PROJECT_ROOT / "sandbox"
ESCROW_DIR = PROJECT_ROOT / "escrow"
ESCROW_FILE = ESCROW_DIR / "recovery.enc"
LOG_FILE = PROJECT_ROOT / "execution.log"

# Configurar logging
def setup_logging():
    """Configura el sistema de logging."""
    logger = logging.getLogger('cifra')
    logger.setLevel(logging.DEBUG)
    
    # Crear archivo de log si no existe
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    # Handler para archivo
    file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    
    # Formato
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    
    return logger

logger = setup_logging()

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
    input("Presione Enter para continuar...")
    os.system('cls' if os.name == 'nt' else 'clear')

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
    os.system('cls' if os.name == 'nt' else 'clear')

def cmd_test(args):
    """Ejecuta todos los tests criptográficos."""
    print("[INFO] Ejecutando suite completa de tests...")
    print("=" * 50)
    
    tests = [
        ("test_basic_encrypt_decrypt", test_basic_encrypt_decrypt),
        ("test_avalanche_effect", test_avalanche_effect),
        ("test_entropy_analysis", test_entropy_analysis),
        ("test_performance_benchmark", test_performance_benchmark),
        ("test_multiple_data_sizes", test_multiple_data_sizes),
        ("test_bit_balance", test_bit_balance),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            print(f"[RUN] {test_name}...", end=" ", flush=True)
            test_func()
            print("✓ PASADO")
            passed += 1
        except Exception as e:
            print(f"✗ FALLO: {e}")
            failed += 1
    
    print("=" * 50)
    print(f"[RESULT] Pasados: {passed}, Fallos: {failed}")
    
    if failed == 0:
        print("[OK] Todos los tests pasaron.")
    else:
        print(f"[ERROR] {failed} test(s) fallaron.")
        sys.exit(1)

def menu_interactive():
    """Menú interactivo para operaciones de cifrado."""
    run = True
    while run:
        print("\n// CIFRADO DE ARCHIVOS - CLI //")
        print("-------------------------------")
        print("Seleccione una opción:")
        print("[a] Iniciar (crear escrow)")
        print("[b] Cifrar archivo")
        print("[c] Descifrar archivo")
        print("[d] Correr todos los tests")
        print("[cls] Limpiar pantalla")
        print("[exit] Salir")
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
            print("Saliendo...")
            run = False
        else:
            print("Opción no válida. Intente de nuevo.")

def build_parser():
    """Construye el parser de argumentos."""
    parser = argparse.ArgumentParser(
        prog='cifra-cli',
        description='CLI para cifrado seguro de archivos con escrow'
    )
    
    parser.add_argument(
        '--tests',
        action='store_true',
        help='Ejecutar suite completa de tests criptográficos'
    )
    
    parser.add_argument(
        '--menu',
        action='store_true',
        help='Abrir menú interactivo'
    )
    
    return parser

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    
    # Si se pasa --tests, ejecutar todos los tests
    if args.tests:
        cmd_test(None)
        return
    
    # Si se pasa --menu o sin argumentos, abrir menú interactivo
    if args.menu or (not args.tests and not argv):
        menu_interactive()
        return
    
    # Si no hay argumentos válidos, mostrar ayuda
    parser.print_help()

if __name__ == "__main__":
    main()
