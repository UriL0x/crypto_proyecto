# src/tests/test_basic.py

'''Pruebas básicas de cifrado y descifrado usando la CLI.'''

import subprocess
from pathlib import Path
import sys
import os


ROOT = Path(__file__).resolve().parents[2]
SANDBOX = ROOT / "sandbox"
ESCROW = ROOT / "escrow"


def test_encrypt_decrypt(monkeypatch):
    # Passphrase automática para tests
    monkeypatch.setattr("getpass.getpass", lambda x="": "testpass")

    subprocess.run([sys.executable, "-m", "src.cli", "init"])

    f_in = SANDBOX / "test.txt"
    f_in.write_text("hola mundo")

    subprocess.run([sys.executable, "-m", "src.cli", "encrypt",
                    str(f_in), str(SANDBOX / "test.enc")])

    subprocess.run([sys.executable, "-m", "src.cli", "decrypt",
                    str(SANDBOX / "test.enc"), str(SANDBOX / "test.dec")])

    assert (SANDBOX / "test.dec").read_text() == "hola mundo"
