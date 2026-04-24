"""
Implementacja SHA-256 krok po kroku.

Uwagi do sprawozdania:
- Padding sluzy aby dlugosc wiadomosci byla wielokrotnoscia 512 bitow
  (SHA-256 przetwarza dane w blokach po 512 bitow). Dopisanie '1' a potem
  zer oraz dlugosci oryginalnej wiadomosci na koncu (64 bity) sprawia,
  ze dwie rozne wiadomosci nie moga po paddingu wygladac tak samo.
- Rozszerzenie 16 slow do 64 slow w message schedule ma rozpropagowac
  kazdy bit wejscia na wiele pozycji przed kompresja (efekt lawinowy).
- Stale H0..H7 oraz K[0..63] to pierwsze 32 bity czesci ulamkowych
  pierwiastkow (kwadratowych / szesciennych) kolejnych liczb pierwszych.
  Uzywa sie ich zamiast "wymyslonych" liczb, zeby bylo widac, ze nie
  zostawiono w nich zadnego ukrytego tylnego wejscia (nothing-up-my-sleeve).
"""

# ----- stale algorytmu -----

# H0..H7: pierwsze 32 bity czesci ulamkowej pierwiastkow kwadratowych
# pierwszych 8 liczb pierwszych (2, 3, 5, 7, 11, 13, 17, 19)
H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

# K[0..63]: pierwspyt
# pierwszych 64 liczb pierwszych (2..311) - tzw. stale rundowe
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

MASK32 = 0xFFFFFFFF  # maska do obciecia wyniku do 32 bitow (arytmetyka mod 2^32)


# ----- operacje bitowe na slowach 32-bitowych -----

def rotr(x: int, n: int) -> int:
    """Rotacja w prawo o n bitow (w ramach 32 bitow)."""
    x &= MASK32
    return ((x >> n) | (x << (32 - n))) & MASK32


def shr(x: int, n: int) -> int:
    """Przesuniecie w prawo o n bitow (z wpisywaniem zer)."""
    return (x & MASK32) >> n


# ----- kroki algorytmu -----

def preprocess(message: bytes) -> bytes:
    """
    Krok 1 - padding.
    Dopisujemy bit '1', potem zera, a na koncu 64-bitowa (big-endian)
    dlugosc oryginalnej wiadomosci w bitach. Calosc ma miec dlugosc
    bedaca wielokrotnoscia 512 bitow (64 bajtow).
    """
    original_bit_len = len(message) * 8

    # bit '1' + 7 zer = bajt 0x80
    padded = message + b'\x80'

    # dopelnienie zerami, zeby po dodaniu 8 bajtow dlugosci dac wielokrotnosc 64 bajtow
    while (len(padded) % 64) != 56:
        padded += b'\x00'

    # 64-bitowa dlugosc oryginalnej wiadomosci w bitach, big-endian
    padded += original_bit_len.to_bytes(8, byteorder='big')
    return padded


def build_message_schedule(block: bytes) -> list:
    """
    Krok 5 - tworzenie tablicy w[0..63] dla jednego 512-bitowego bloku.
    Pierwsze 16 slow to surowe dane z bloku, kolejne liczone ze wzoru.
    """
    w = [0] * 64
    # 16 slow po 32 bity = 64 bajty bloku
    for i in range(16):
        w[i] = int.from_bytes(block[i * 4:(i + 1) * 4], byteorder='big')

    for i in range(16, 64):
        s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ shr(w[i - 15], 3)
        s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ shr(w[i - 2], 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK32
    return w


def compress(h: list, w: list) -> list:
    """
    Krok 6 - petla kompresji dla jednego bloku.
    Mutujemy zmienne a..h, na koniec dodajemy je do aktualnych wartosci h0..h7.
    """
    a, b, c, d, e, f, g, hh = h

    for i in range(64):
        S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ (~e & MASK32 & g)
        temp1 = (hh + S1 + ch + K[i] + w[i]) & MASK32

        S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & MASK32

        hh = g
        g = f
        f = e
        e = (d + temp1) & MASK32
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & MASK32

    return [
        (h[0] + a) & MASK32,
        (h[1] + b) & MASK32,
        (h[2] + c) & MASK32,
        (h[3] + d) & MASK32,
        (h[4] + e) & MASK32,
        (h[5] + f) & MASK32,
        (h[6] + g) & MASK32,
        (h[7] + hh) & MASK32,
    ]


def sha256(message) -> str:
    """Pelne SHA-256: zwraca hash w postaci hex-stringa (64 znaki = 256 bitow)."""
    if isinstance(message, str):
        message = message.encode('utf-8')

    padded = preprocess(message)
    h = list(H_INIT)

    # kazdy blok ma 512 bitow = 64 bajty
    for offset in range(0, len(padded), 64):
        block = padded[offset:offset + 64]
        w = build_message_schedule(block)
        h = compress(h, w)

    return ''.join(f'{value:08x}' for value in h)


# ----- narzedzia dodatkowe (dystans Hamminga) -----

def hamming_distance_hex(hex_a: str, hex_b: str) -> int:
    """Dystans Hamminga miedzy dwoma hashami zapisanymi jako hex - liczony na bitach."""
    a = int(hex_a, 16)
    b = int(hex_b, 16)
    return (a ^ b).bit_count()


# ----- demonstracja -----

if __name__ == "__main__":
    import hashlib

    # 1) Weryfikacja na "hello world"
    text = "hello world"
    mine = sha256(text)
    ref = hashlib.sha256(text.encode()).hexdigest()

    print(f'Wiadomosc: "{text}"')
    print(f'Moje SHA-256:  {mine}')
    print(f'hashlib:       {ref}')
    print(f'Zgodne: {mine == ref}')
    print()

    # 2) Efekt lawinowy - pary wiadomosci rozniace sie drobnie,
    #    patrzymy ile bitow hasha sie zmienia (dystans Hamminga).
    pairs = [
        ("hello world",       "hello world!"),
        ("hello world",       "Hello world"),
        ("abc",               "abd"),
        ("The quick brown fox jumps over the lazy dog",
         "The quick brown fox jumps over the lazy dog."),
        ("test123",           "test124"),
        ("password",          "Password"),
        ("aaaaaaaa",          "aaaaaaab"),
        ("0000000000000000",  "0000000000000001"),
        ("Ala ma kota",       "Ala ma kotA"),
        ("Lorem ipsum",       "lorem ipsum"),
        ("2025-01-01",        "2025-01-02"),
        ("user@example.com",  "user@example.co"),
        ("WdC lab 4",         "WdC Lab 4"),
        ("kryptografia",      "Kryptografia"),
        ("SHA-256",           "SHA-255"),
        ("Jarek Marek",       "Jarek Darek"),
        ("Politechnika",      "politechnika"),
        ("0",                 "1"),
        ("",                  " "),
        ("A",                 "B"),
        ("klucz-tajny-001",   "klucz-tajny-002"),
        ("x" * 100,           "x" * 99 + "y"),
        ("test",              "Test"),
        ("abc123",            "abc124"),
        ("dane wejsciowe",    "Dane wejsciowe"),
    ]

    print("Test efektu lawinowego (dystans Hamminga miedzy hashami):")
    print(f'{"m1":<45} {"m2":<45} {"Hamming":>8} / 256')
    print("-" * 110)
    distances = []
    for m1, m2 in pairs:
        h1 = sha256(m1)
        h2 = sha256(m2)
        d = hamming_distance_hex(h1, h2)
        distances.append(d)
        print(f'{m1!r:<45} {m2!r:<45} {d:>8}')

    avg = sum(distances) / len(distances)
    print("-" * 110)
    print(f"Srednia: {avg:.2f} / 256 (oczekiwane ~128 dla dobrego hasha)")
