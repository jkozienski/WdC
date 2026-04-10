import math
import random
from Crypto.Util.number import getPrime, isPrime


# 1. WCZYTANIE WIADOMOSCI Z PLIKU
def read_message(file_path):
    # otwieramy plik i zwracamy jego zawartosc jako string
    f = open(file_path, "r", encoding="utf-8")
    text = f.read()
    f.close()
    return text


# 2. ZAMIANA TEKSTU NA BITY I Z POWROTEM
def text_to_bits(text):
    # zamieniamy kazdy znak tekstu na 8 bitow
    bits = []
    for byte in text.encode("utf-8"):
        for i in range(7, -1, -1):         # od najwazniejszego bitu (MSB) do LSB
            bit = (byte >> i) & 1          # wyciagamy i-ty bit
            bits.append(bit)
    return bits


def bits_to_text(bits):
    # zamieniamy liste bitow z powrotem na tekst
    byte_array = bytearray()
    for i in range(0, len(bits), 8):
        value = 0
        for j in range(8):                 # skladamy 8 bitow w jedna liczbe
            value = value * 2 + bits[i + j]
        byte_array.append(value)
    return byte_array.decode("utf-8")


# 3. GENERATOR BLUM-BLUM-SHUB (BBS)
def generate_blum_prime(bits):
    # generuje liczbe pierwsza kongruentna 3 mod 4 o danej dlugosci bitowej
    candidate = getPrime(bits)             # losowa liczba pierwsza o zadanej dlugosci
    while candidate % 4 != 3:             # szukamy az spelni warunek BBS
        candidate = getPrime(bits)
    return candidate


def bbs_generator(p, q, seed, num_bits):
    # generator pseudolosowych bitow Blum-Blum-Shub
    n = p * q                          

    X = (seed * seed) % n              # X(0) = seed^2 mod n

    bits = []
    for i in range(num_bits):
        X = (X * X) % n               # X(i) = X(i-1)^2 mod n
        bit = X % 2                    # bierzemy ostatni bit 
        bits.append(bit)

    return bits

# 4A. TEST PROPORCJI WYSTAPIEN (Frequency / Monobit Test)
def nist_frequency_test(bits):
    # Test 1 - Frequency (Monobit) Test
    # Sprawdzamy czy liczba jedynek i zer jest w przyblizeniu rowna.
    # Kazde 1 traktujemy jako +1, kazde 0 jako -1 i sumujemy.
    # Dla prawdziwie losowego ciagu suma powinna byc bliska 0.
    #
    # p-value >= 0.01  ->  test ZALICZONY (ciag wyglada losowo)
    # p-value <  0.01  ->  test NIEZALICZONY

    n = len(bits)

    # sumujemy: +1 dla jedynek, -1 dla zer
    S = 0
    for b in bits:
        if b == 1:
            S = S + 1
        else:
            S = S - 1

    # statystyka testowa
    s_obs = abs(S) / math.sqrt(n)

    p_value = math.erfc(s_obs / math.sqrt(2))

    passed = p_value >= 0.01

    print("  [Test proporcji wystapien]")
    print("  Suma S =", S, "  (idealnie: 0)")
    print("  s_obs  =", round(s_obs, 6))
    print("  p-value=", round(p_value, 6), " (prog: 0.01)")
    if passed:
        print("  Wynik: ZALICZONY")
    else:
        print("  Wynik: NIEZALICZONY")

    return passed


# 4B. TEST SERII WYSTAPIEN (Runs Test)
def nist_runs_test(bits):
    #Test 2 - Runs Test
    # Sprawdzamy czy liczba serii jest typowa dla losowego ciagu.
    # Seria to nieprzerwany ciag tych samych bitow np 0000 albo 111.
    # Za duzo lub za malo serii sugeruje, ze ciag nie jest losowy.
    #
    # p-value >= 0.01  ->  test ZALICZONY
    # p-value <  0.01  ->  test NIEZALICZONY

    n = len(bits)

    # liczymy proporcje jedynek (pi)
    ones = 0
    for b in bits:
        ones = ones + b
    pi = ones / n

    print("  [Test serii wystapien]")
    print("  Proporcja jedynek pi =", round(pi, 6), "  (idealnie: 0.5)")

    # warunek wstepny: pi musi byc wystarczajaco bliskie 0.5
    # jesli nie, test jest automatycznie niezaliczony
    if abs(pi - 0.5) >= (2 / math.sqrt(n)):
        print("  Warunek wstepny niespelniony - pi zbyt dalekie od 0.5")
        print("  Wynik: NIEZALICZONY")
        return False

    # liczymy liczbe serii V_n
    # za kazdym razem gdy bit sie zmienia, zaczyna sie nowa seria
    V_n = 1
    for i in range(1, n):
        if bits[i] != bits[i - 1]:
            V_n = V_n + 1

    # statystyka testowa
    numerator = abs(V_n - 2 * n * pi * (1 - pi))
    denominator = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    p_value = math.erfc(numerator / denominator)

    passed = p_value >= 0.01

    print("  Liczba serii V_n =", V_n)
    print("  p-value =", round(p_value, 6), " (prog: 0.01)")
    if passed:
        print("  Wynik: ZALICZONY")
    else:
        print("  Wynik: NIEZALICZONY")

    return passed


# 5. SZYFROWANIE (XOR - One-Time Pad)
def encrypt(message_bits, key_bits):
    # szyfrowanie: XOR kazdego bitu wiadomosci z odpowiadajacym bitem klucza
    # przyklad: 1 XOR 0 = 1,  0 XOR 1 = 1,  1 XOR 1 = 0
    ciphertext = []
    for i in range(len(message_bits)):
        ciphertext.append(message_bits[i] ^ key_bits[i])
    return ciphertext


# 6. ODSZYFROWANIE
def decrypt(ciphertext_bits, key_bits):
    # odszyfrowanie tak jak szyfrowanie
    return encrypt(ciphertext_bits, key_bits)


# 7. WERYFIKACJA ZGODNOSCI
def verify(original_bits, decrypted_bits):
    # porownujemy bit po bicie oryginalna i odszyfrowana wiadomosc
    if len(original_bits) != len(decrypted_bits):
        return False
    for i in range(len(original_bits)):
        if original_bits[i] != decrypted_bits[i]:
            return False
    return True


# Main
FILE = "wiadomosc.txt"
message_text = read_message(FILE)
 
print("  SZYFR DOSKONALY (OTP) + generator Blum-Blum-Shub")
print("=" * 50)
print("\n[1] Wiadomosc (" + str(len(message_text)) + " znakow):")
print("   ", message_text)

#    2 zamiana na bity  
message_bits = text_to_bits(message_text)
length = len(message_bits)

print("\n[2] Wiadomosc jako bity (", length, "bitow):")
print("   ", "".join(str(b) for b in message_bits))

#    3 generowanie klucza przez BBS  
# generujemy dwie liczby pierwsze kongruentne 3 mod 4 
p = generate_blum_prime(128)
q = generate_blum_prime(128)

n = p * q
seed = random.randint(1, n - 1)       # losowy seed miedzy 1 a n-1
while seed % p == 0 or seed % q == 0: # seed nie moze byc podzielny przez p ani q
    seed = random.randint(1, n - 1)

print("\n[3] Generator BBS:")
print("    p =", p, " (pierwsza, p % 4 =", p % 4, ")")
print("    q =", q, " (pierwsza, q % 4 =", q % 4, ")")
print("    seed =", seed)

key = bbs_generator(p, q, seed, length)

print("    Wygenerowano", len(key), "bitow klucza.")
print("   ", "".join(str(b) for b in key))

#    4 testy statystyczne NIST  
print("\n[4] Testy statystyczne NIST (na wygenerowanym kluczu):")
nist_frequency_test(key)
print()
nist_runs_test(key)

#    5 szyfrowanie  
ciphertext = encrypt(message_bits, key)

print("\n[5] Szyfrogram (wszystkie", len(ciphertext), "bity):")
print("   ", "".join(str(b) for b in ciphertext))

#    6 odszyfrowanie  
decrypted_bits = decrypt(ciphertext, key)
decrypted_text = bits_to_text(decrypted_bits)

print("\n[6] Odszyfrowana wiadomosc:")
print("   ", decrypted_text)

#    7 weryfikacja  
match = verify(message_bits, decrypted_bits)

print("\n[7] Weryfikacja zgodnosci:")
if match:
    print("    OK - wiadomosci sa identyczne!")
else:
    print("    BLAD - wiadomosci roznia sie!")

print("=" * 60)