"""
WdC Lab 3 - RSA
"""

import random
import time
import math
import sys
import matplotlib.pyplot as plt
from sympy import isprime, nextprime


 
# 1. KODOWANIE TEKSTU (alfabet 26-znakowy)
 
ALPHABET_SIZE = 26
BLOCK_SIZE = 10
KEY_BITS = 768

def char_to_num(c):
    return ord(c.lower()) - ord('a')

def num_to_char(n):
    return chr(n + ord('a'))

def block_to_number(block):
    result = 0
    for i, c in enumerate(block):
        result += char_to_num(c) * (ALPHABET_SIZE ** i)
    return result

def number_to_block(number, length):
    chars = []
    for _ in range(length):
        chars.append(num_to_char(number % ALPHABET_SIZE))
        number //= ALPHABET_SIZE
    return ''.join(chars)

def read_and_prepare(text, block_size=BLOCK_SIZE):
    clean = ''.join(c for c in text.lower() if 'a' <= c <= 'z')
    if not clean:
        raise ValueError("Tekst nie zawiera liter a-z")

    blocks = []
    lengths = []
    for i in range(0, len(clean), block_size):
        block = clean[i:i + block_size]
        lengths.append(len(block))
        # Uzupełnienie ostatniego bloku
        block = block.ljust(block_size, 'a')
        blocks.append(block)
    return blocks, lengths


 
# 2. GENEROWANIE KLUCZY RSA (768 bitów)
 
def generate_prime(bits):
    while True:
        # Losujemy liczbę z zakresu [2^(bits-1), 2^bits - 1]
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1))  # ustawiamy MSB
        candidate |= 1                  # ustawiamy LSB (nieparzyste)
        if isprime(candidate):
            return candidate

def generate_rsa_keys(key_bits=KEY_BITS):
    p_bits = key_bits // 2 - 64  
    q_bits = key_bits // 2 + 64   

    # Krok 1: dwie różne liczby pierwsze
    while True:
        p = generate_prime(p_bits)
        q = generate_prime(q_bits)
        if p != q:
            break

    # Krok 2
    n = p * q

    # Krok 3
    phi = (p - 1) * (q - 1)

    # Krok 4
    e = 65537
    if e >= phi or math.gcd(e, phi) != 1:
        raise ValueError(f"Wybrane e={e} nie spełnia warunków RSA dla tego klucza.")

    # Krok 5
    d = pow(e, -1, phi)

    return n, e, d, p, q


 
# 3. SZYFROWANIE I DESZYFROWANIE
 

def encrypt_block(m, e, n):
    return pow(m, e, n)


def encrypt_message(blocks, e, n, block_size=BLOCK_SIZE):
    encrypted = []
    for block in blocks:
        m = block_to_number(block)
        if m >= n:
            raise ValueError(
                f"Błąd: wartość bloku m={m} >= n={n}. "
                "Zwiększ długość klucza lub zmniejsz rozmiar bloku."
            )
        c = encrypt_block(m, e, n)
        encrypted.append(c)
    return encrypted

def decrypt_block(c, d, n):
    return pow(c, d, n)

def decrypt_message(encrypted, d, n, lengths, block_size=BLOCK_SIZE):
    decrypted_blocks = []
    for c, length in zip(encrypted, lengths):
        m = decrypt_block(c, d, n)
        block = number_to_block(m, block_size)

        # Przycinanie do oryginalnej długości bloku
        decrypted_blocks.append(block[:length])
    return ''.join(decrypted_blocks)


 
# 4. WERYFIKACJA BLOK PO BLOKU
 
def verify(original_blocks, lengths, encrypted, d, n, block_size=BLOCK_SIZE):
    all_ok = True
    print("\n  Weryfikacja blok po bloku  ")
    for i, (block, c, length) in enumerate(zip(original_blocks, encrypted, lengths)):
        m_dec = decrypt_block(c, d, n)
        block_dec = number_to_block(m_dec, block_size)[:length]
        original = block[:length]
        ok = (original == block_dec)
        if not ok:
            all_ok = False
        status = "OK" if ok else "BŁĄD"
        print(f"  Blok {i+1:2d}: '{original}' -> szyfrogram={c} -> '{block_dec}' [{status}]")
    return all_ok



 
# 5. FAKTORYZACJA (test czasowy)
 

def trial_division(n):
    """
    Faktoryzacja przez próbne dzielenie.
    Zwraca (p, q, iteracje) lub (None, None, iteracje) jeśli nie znaleziono.
    """
    iterations = 0
    if n % 2 == 0:
        return 2, n // 2, 1
    i = 3
    while i * i <= n:
        iterations += 1
        if n % i == 0:
            return i, n // i, iterations
        i += 2
    return None, None, iterations

def trial_division_timed(n, max_seconds=360.0):
    """
    Faktoryzacja przez próbne dzielenie z limitem czasu.
    Zwraca (p, q, iteracje, przekroczono_czas).
    """
    iterations = 0
    deadline = time.perf_counter() + max_seconds
    if n % 2 == 0:
        return 2, n // 2, 1, False
    i = 3
    while i * i <= n:
        iterations += 1
        if n % i == 0:
            return i, n // i, iterations, False
        i += 2
        if iterations % 500_000 == 0 and time.perf_counter() > deadline:
            return None, None, iterations, True
    return None, None, iterations, False

def factorization_timing_test():
    """
    Dla każdego rozmiaru: generujemy n = p*q i mierzymy czas trial division.
    """
    bit_sizes = [32, 40, 48, 56, 64, 72, 80, 88]
    results = []

    print("\n" + "="*65)
    print("FAKTORYZACJA RSA - Test czasowy (trial division, limit czasu)")
    print("="*65)
    print(f"{'Bity':>6} | {'Czas [s]':>12} | {'Iteracje':>14} | {'Sukces':>7}")
    print("-"*65)

    for bits in bit_sizes:
        half = bits // 2
        p = generate_prime(half)
        q = generate_prime(half)
        while p == q:
            q = generate_prime(half)
        n_test = p * q

        start = time.perf_counter()
        found_p, found_q, iters, timeout = trial_division_timed(n_test, max_seconds=360.0)
        elapsed = time.perf_counter() - start

        success = (found_p is not None)
        timeout_str = " (TIMEOUT)" if timeout else ""
        results.append((bits, elapsed, iters, success))
        print(f"{bits:>6} | {elapsed:>12.6f} | {iters:>14,} | {'TAK' if success else 'NIE':>7}{timeout_str}")

    return results


 
# 6. DOPASOWANIE KRZYWYCH 
 

def fit_curves(results):
    """
    Próbuje dopasować funkcję potęgową i wykładniczą do wyników.
    Używa prostej regresji liniowej na zlogarytmowanych danych.
    """
    import math

    xs = [r[0] for r in results if r[3]]  # bity
    ys = [r[1] for r in results if r[3]]  # czas

    if len(xs) < 3:
        print("\nZbyt mało danych do dopasowania krzywych.")
        return

    n = len(xs)

    #   Funkcja potęgowa: t = a * x^b
    # ln(t) = ln(a) + b*ln(x)
    lx = [math.log(x) for x in xs]
    ly = [math.log(y) if y > 0 else -30 for y in ys]

    # Regresja liniowa: ly = b*lx + ln(a)
    sum_lx = sum(lx)
    sum_ly = sum(ly)
    sum_lxly = sum(a * b for a, b in zip(lx, ly))
    sum_lx2 = sum(a**2 for a in lx)

    b_pow = (n * sum_lxly - sum_lx * sum_ly) / (n * sum_lx2 - sum_lx**2)
    a_pow = math.exp((sum_ly - b_pow * sum_lx) / n)

    # R^2 dla potęgowej
    ly_mean = sum_ly / n
    ss_tot = sum((y - ly_mean)**2 for y in ly)
    ly_pred = [b_pow * lx_i + math.log(a_pow) for lx_i in lx]
    ss_res = sum((y - yp)**2 for y, yp in zip(ly, ly_pred))
    r2_pow = 1 - ss_res / ss_tot if ss_tot != 0 else 0

    #   Funkcja wykładnicza: t = a * e^(b*x)
    # ln(t) = ln(a) + b*x
    sum_x = sum(xs)
    sum_logy = sum(ly)
    sum_xly = sum(a * b for a, b in zip(xs, ly))
    sum_x2 = sum(x**2 for x in xs)

    b_exp = (n * sum_xly - sum_x * sum_logy) / (n * sum_x2 - sum_x**2)
    a_exp = math.exp((sum_logy - b_exp * sum_x) / n)

    # R^2 dla wykładniczej
    ly_pred_exp = [b_exp * x + math.log(a_exp) for x in xs]
    ss_res_exp = sum((y - yp)**2 for y, yp in zip(ly, ly_pred_exp))
    r2_exp = 1 - ss_res_exp / ss_tot if ss_tot != 0 else 0

    print("\n  Dopasowanie krzywych  ")
    print(f"  Potęgowa:    t = {a_pow:.4e} * x^{b_pow:.3f}   R2 = {r2_pow:.4f}")
    print(f"  Wykładnicza: t = {a_exp:.4e} * e^({b_exp:.4f}*x)  R2 = {r2_exp:.4f}")

    winner = "potęgowa" if r2_pow > r2_exp else "wykładnicza"

# 7. WYKRES FAKTORYZACJI
def plot_factorization(results, out_png="factorization_result.png"):
    """Rysuje wykres: rozmiar klucza (bity) -> czas faktoryzacji."""
    bits = [r[0] for r in results]
    times = [r[1] for r in results]
    success = [r[3] for r in results]

    plt.figure(figsize=(8, 5))
    plt.plot(bits, times, marker='o', label='czas faktoryzacji')

    # zaznacz TIMEOUT-y
    for b, t, ok in zip(bits, times, success):
        if not ok:
            plt.scatter(b, t, color='red', zorder=5)

    plt.xlabel('Rozmiar klucza (bity)')
    plt.ylabel('Czas faktoryzacji (s)')
    plt.title('Czas faktoryzacji RSA (trial division)')
    plt.yscale('log')
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_png)
    print(f"\nWykres zapisany do: {out_png}")



# 8. MAIN
def main():
    print("=" * 65)
    print("WdC Lab 3 - Implementacja RSA (alfabet 26-znakowy)")
    print("=" * 65)

    # --- Wczytanie wiadomości ---
    input_file = "message.txt"
    with open(input_file, "r", encoding="utf-8") as f:
        message = f.read()
    print(f"\nWczytano wiadomość z pliku '{input_file}'")
    print(f"Oryginalna wiadomość: '{message}'")

    blocks, lengths = read_and_prepare(message, block_size=BLOCK_SIZE)
    print(f"Po oczyszczeniu i podziale na bloki ({len(blocks)} bloków):")
    for i, (b, l) in enumerate(zip(blocks, lengths)):
        m_val = block_to_number(b)
        print(f"  Blok {i+1}: '{b[:l]}' (padding: '{b}') -> liczba = {m_val}")

    #   Generowanie kluczy  
    print("\nGenerowanie kluczy RSA (2048 bitów)")
    t0 = time.perf_counter()
    n, e, d, p, q = generate_rsa_keys(key_bits=KEY_BITS)
    t_keygen = time.perf_counter() - t0
    print(f"  Czas generowania: {t_keygen:.3f} s")
    print(f"  Długość n: {n.bit_length()} bitów")
    print(f"  Długość p: {p.bit_length()} bitów, długość q: {q.bit_length()} bitów (różnica: {abs(p.bit_length() - q.bit_length())} bitów)")
    print(f"  Długość e: {e.bit_length()} bitów")
    print(f"  e = {e}")
    print(f"  d = {d}")

    #   Szyfrowanie  
    print("\nSzyfrowanie blok po bloku")
    encrypted = encrypt_message(blocks, e, n)
    for i, (b, c, l) in enumerate(zip(blocks, encrypted, lengths)):
        print(f"  Blok {i+1}: m={block_to_number(b)} -> c={c}")

    #   Deszyfrowanie  
    print("\nDeszyfrowanie blok po bloku")
    decrypted_text = decrypt_message(encrypted, d, n, lengths)
    print(f"  Odszyfrowana wiadomość: '{decrypted_text}'")

    #   Weryfikacja  
    all_ok = verify(blocks, lengths, encrypted, d, n)
    print(f"\n  Wynik weryfikacji: {'WSZYSTKIE BLOKI ZGODNE' if all_ok else 'WYKRYTO ROZBIEŻNOŚCI'}")

    #   Test faktoryzacji
    results = factorization_timing_test()

    #   Dopasowanie krzywych  
    fit_curves(results)

    #   Wykres  
    plot_factorization(results)

    print("\n" + "="*65)
    print("Koniec programu.")
    print("="*65)


if __name__ == "__main__":
    main()