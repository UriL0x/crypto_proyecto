import subprocess, sys, os, time
from pathlib import Path
import math
from collections import Counter
from src.crypto_utils import aesgcm_decrypt, aesgcm_encrypt, gen_master_key

try:
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')  # backend no interactivo
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Warning: matplotlib no instalado. Los gráficos no se generarán.")

ROOT = Path(__file__).resolve().parents[2]
SANDBOX = ROOT / "sandbox"
ESCROW = ROOT / "escrow"
OUTPUT_DIR = Path(__file__).resolve().parent / "results"
OUTPUT_DIR.mkdir(exist_ok=True)

TEST_KEY = gen_master_key()

def cifrar_descifrar(data: bytes) -> bytes:
    blob = aesgcm_encrypt(TEST_KEY, data)
    result = aesgcm_decrypt(TEST_KEY, blob)
    return result

def hamming_distance(b1: bytes, b2: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(b1, b2))

def entropy(data: bytes) -> float:
    cnt = Counter(data)
    total = len(data)
    if len(cnt) == 0:
        return 0
    return -sum((c/total) * math.log2(c/total) for c in cnt.values())

def bit_histogram(data: bytes):
    bits = "".join(f"{byte:08b}" for byte in data)
    return bits.count("0"), bits.count("1")


# ============= TESTS CON MÚLTIPLES DATOS =============

def test_basic_encrypt_decrypt():
    """Test básico: round-trip encrypt/decrypt."""
    original = b"Mensaje de prueba"
    resultado = cifrar_descifrar(original)
    assert original == resultado
    print("✓ Test básico: PASADO")


def test_multiple_data_sizes():
    """Test encrypt/decrypt con múltiples tamaños de datos."""
    sizes = [16, 64, 256, 1024, 4096, 16384]
    results = []

    for size in sizes:
        data = os.urandom(size)
        t0 = time.time()
        encrypted = aesgcm_encrypt(TEST_KEY, data)
        t1 = time.time()
        decrypted = aesgcm_decrypt(TEST_KEY, encrypted)
        t2 = time.time()

        enc_time = t1 - t0
        dec_time = t2 - t1

        assert data == decrypted, f"Fallo en tamaño {size}"
        results.append({
            "size": size,
            "enc_time": enc_time,
            "dec_time": dec_time,
            "total_time": enc_time + dec_time
        })
        print(f"  Tamaño {size:6d} bytes: enc={enc_time*1000:.2f}ms, dec={dec_time*1000:.2f}ms")

    # Guardar gráfico de tiempos
    if HAS_MATPLOTLIB:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
        
        sizes_plot = [r["size"] for r in results]
        enc_times = [r["enc_time"] * 1000 for r in results]
        dec_times = [r["dec_time"] * 1000 for r in results]
        
        ax1.plot(sizes_plot, enc_times, marker='o', label='Encrypt', linewidth=2)
        ax1.plot(sizes_plot, dec_times, marker='s', label='Decrypt', linewidth=2)
        ax1.set_xlabel('Tamaño de datos (bytes)')
        ax1.set_ylabel('Tiempo (ms)')
        ax1.set_title('Tiempo de Cifrado/Descifrado por Tamaño')
        ax1.legend()
        ax1.grid(True)
        ax1.set_xscale('log')
        
        ax2.bar([str(s//1024)+'KB' if s >= 1024 else str(s)+'B' for s in sizes_plot], 
                [r["total_time"] for r in results], color='steelblue')
        ax2.set_ylabel('Tiempo Total (segundos)')
        ax2.set_title('Tiempo Total por Tamaño')
        ax2.grid(True, axis='y')
        
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / "test_multiple_data_sizes.png", dpi=150)
        plt.close()
        print(f"  → Gráfico guardado: {OUTPUT_DIR / 'test_multiple_data_sizes.png'}")

    print("✓ Test múltiples tamaños: PASADO\n")


def test_avalanche_effect():
    """Test efecto avalancha: cambio de 1 bit causa cambios significativos en ciphertext."""
    key = gen_master_key()
    data_sizes = [32, 64, 128, 256]
    avalanche_ratios = []

    for size in data_sizes:
        data1 = os.urandom(size)
        # Cambiar 1 bit en el primer byte
        data2 = bytes([data1[0] ^ 0b00000001]) + data1[1:]
        
        blob1 = aesgcm_encrypt(key, data1)
        blob2 = aesgcm_encrypt(key, data2)

        # Comparar ciphertexts (sin nonce/tag)
        ct1 = blob1[12:]
        ct2 = blob2[12:]

        dif = hamming_distance(ct1, ct2)
        total = len(ct1) * 8
        ratio = dif / total if total > 0 else 0

        avalanche_ratios.append(ratio)
        print(f"  Tamaño {size:3d} bytes: avalanche ratio = {ratio:.3f} (esperado ~0.5)")
        assert 0.35 < ratio < 0.65, f"Avalanche ratio fuera de rango: {ratio}"

    # Gráfico
    if HAS_MATPLOTLIB:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.bar([str(s) for s in data_sizes], avalanche_ratios, color='coral')
        ax.axhline(y=0.5, color='green', linestyle='--', label='Ideal (0.5)')
        ax.set_ylabel('Avalanche Ratio')
        ax.set_xlabel('Tamaño de datos (bytes)')
        ax.set_title('Efecto Avalancha: Ratio de Cambio de Bits')
        ax.set_ylim([0, 1])
        ax.legend()
        ax.grid(True, axis='y')
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / "test_avalanche_effect.png", dpi=150)
        plt.close()
        print(f"  → Gráfico guardado: {OUTPUT_DIR / 'test_avalanche_effect.png'}")

    print("✓ Test efecto avalancha: PASADO\n")


def test_entropy_analysis():
    """Test entropía de datos cifrados para múltiples tamaños."""
    data_sizes = [256, 512, 1024, 2048, 4096, 8192]
    entropies = []
    sample_data = []

    for size in data_sizes:
        data = os.urandom(size)
        encrypted = cifrar_descifrar(data)
        H = entropy(encrypted)
        entropies.append(H)
        sample_data.append(encrypted)
        print(f"  Tamaño {size:5d} bytes: Entropía = {H:.4f} (esperado ~8.0)")
        assert H > 7, f"Entropía baja: {H}"

    # Gráfico
    if HAS_MATPLOTLIB:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
        
        ax1.plot(data_sizes, entropies, marker='o', linewidth=2, markersize=8, color='darkgreen')
        ax1.axhline(y=8.0, color='red', linestyle='--', label='Máximo (8.0)')
        ax1.set_xlabel('Tamaño de datos (bytes)')
        ax1.set_ylabel('Entropía (bits)')
        ax1.set_title('Entropía de Datos Cifrados')
        ax1.legend()
        ax1.grid(True)
        
        # Histograma de distribución de bytes en la muestra más grande
        largest_encrypted = sample_data[-1]
        byte_counts = Counter(largest_encrypted)
        ax2.bar(range(256), [byte_counts.get(i, 0) for i in range(256)], color='steelblue', alpha=0.7)
        ax2.set_xlabel('Valor de Byte (0-255)')
        ax2.set_ylabel('Frecuencia')
        ax2.set_title(f'Distribución de Bytes (muestra de {data_sizes[-1]} bytes)')
        ax2.grid(True, axis='y')
        
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / "test_entropy_analysis.png", dpi=150)
        plt.close()
        print(f"  → Gráfico guardado: {OUTPUT_DIR / 'test_entropy_analysis.png'}")

    print("✓ Test análisis de entropía: PASADO\n")


def test_bit_balance():
    """Test equilibrio de bits 0 y 1 en ciphertext."""
    data_sizes = [256, 512, 1024, 2048, 4096]
    bit_balances = []

    for size in data_sizes:
        data = os.urandom(size)
        encrypted = cifrar_descifrar(data)
        zeros, ones = bit_histogram(encrypted)
        total = zeros + ones
        p0 = zeros / total
        p1 = ones / total
        balance = abs(p0 - 0.5)
        bit_balances.append(balance)
        print(f"  Tamaño {size:5d} bytes: P(0)={p0:.4f}, P(1)={p1:.4f}, balance={balance:.4f}")
        assert abs(p0 - 0.5) < 0.05, f"Desequilibrio de bits: P(0)={p0}"
        assert abs(p1 - 0.5) < 0.05, f"Desequilibrio de bits: P(1)={p1}"

    # Gráfico
    if HAS_MATPLOTLIB:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.plot(data_sizes, bit_balances, marker='o', linewidth=2, markersize=8, color='purple')
        ax.axhline(y=0.05, color='red', linestyle='--', label='Límite de tolerancia (0.05)')
        ax.fill_between(data_sizes, 0, 0.05, alpha=0.2, color='green', label='Zona aceptable')
        ax.set_xlabel('Tamaño de datos (bytes)')
        ax.set_ylabel('Desequilibrio de Bits')
        ax.set_title('Equilibrio de Bits 0 y 1 en Ciphertext')
        ax.legend()
        ax.grid(True)
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / "test_bit_balance.png", dpi=150)
        plt.close()
        print(f"  → Gráfico guardado: {OUTPUT_DIR / 'test_bit_balance.png'}")

    print("✓ Test equilibrio de bits: PASADO\n")


def test_performance_benchmark():
    """Benchmark de rendimiento: throughput (MB/s) para diferentes tamaños."""
    data_sizes = [1024, 4096, 16384, 65536, 262144, 1048576]
    throughputs_enc = []
    throughputs_dec = []

    for size in data_sizes:
        data = os.urandom(size)
        
        # Encrypt
        t0 = time.time()
        encrypted = aesgcm_encrypt(TEST_KEY, data)
        t1 = time.time()
        enc_time = t1 - t0
        
        # Decrypt
        t0 = time.time()
        decrypted = aesgcm_decrypt(TEST_KEY, encrypted)
        t1 = time.time()
        dec_time = t1 - t0
        
        throughput_enc = (size / (1024 * 1024)) / enc_time if enc_time > 0 else 0
        throughput_dec = (size / (1024 * 1024)) / dec_time if dec_time > 0 else 0
        
        throughputs_enc.append(throughput_enc)
        throughputs_dec.append(throughput_dec)
        
        print(f"  Tamaño {size:8d} bytes: Encrypt={throughput_enc:.2f} MB/s, Decrypt={throughput_dec:.2f} MB/s")

    # Gráfico
    if HAS_MATPLOTLIB:
        fig, ax = plt.subplots(figsize=(12, 6))
        ax.plot([s // 1024 for s in data_sizes], throughputs_enc, marker='o', label='Encrypt', linewidth=2, markersize=8)
        ax.plot([s // 1024 for s in data_sizes], throughputs_dec, marker='s', label='Decrypt', linewidth=2, markersize=8)
        ax.set_xlabel('Tamaño de datos (KB)')
        ax.set_ylabel('Throughput (MB/s)')
        ax.set_title('Rendimiento de Cifrado/Descifrado')
        ax.legend()
        ax.grid(True)
        ax.set_xscale('log')
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / "test_performance_benchmark.png", dpi=150)
        plt.close()
        print(f"  → Gráfico guardado: {OUTPUT_DIR / 'test_performance_benchmark.png'}")

    print("✓ Test benchmark de rendimiento: PASADO\n")
