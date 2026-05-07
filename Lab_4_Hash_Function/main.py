
# H0..H7
# 8 liczb pierwszych (2, 3, 5, 7, 11, 13, 17, 19)
H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

# K[0..63]
# pierwszych 64 liczb pierwszych (2..311) 
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

MASK32 = 0xFFFFFFFF  # maska do obciecia wyniku do 32 bitow 


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
    original_bit_len = len(message) * 8

    padded = message + b'\x80'

    while (len(padded) % 64) != 56:
        padded += b'\x00'

    # 64-bitowa dlugosc oryginalnej wiadomosci w bitach, big-endian
    padded += original_bit_len.to_bytes(8, byteorder='big')
    return padded


def build_message_schedule(block: bytes) -> list:
    """
    Tworzenie tablicy w[0..63] dla jednego 512-bitowego bloku.
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
    Petla kompresji dla jednego bloku.
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


# dystans Hamminga

def hamming_distance_hex(hex_a: str, hex_b: str) -> int:
    """Dystans Hamminga miedzy dwoma hashami zapisanymi jako hex - liczony na bitach."""
    a = int(hex_a, 16)
    b = int(hex_b, 16)
    return (a ^ b).bit_count()



if __name__ == "__main__":
    import hashlib

    # 1) Weryfikacja algorytmu
    text = "hello world"
    mine = sha256(text)
    ref = hashlib.sha256(text.encode()).hexdigest()

    print(f'Wiadomosc: "{text}"')
    print(f'Moje SHA-256:  {mine}')
    print(f'hashlib:       {ref}')
    print(f'Zgodne: {mine == ref}')
    print()

    # 2) Pary wiadomosci rozniace sie niewiele
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

    # 3) Czy mozna skrocic tekst "dowolnej" dlugosci?
    import os

    print()
    print("Test dlugosci wejscia:")
    print(f'{"zadane bity":>12} {"realne bajty":>14} {"dl. skrotu [bit]":>18}   skrot')
    print("-" * 110)

    bit_lengths = [1, 32, 128, 512, 1024]
    for bits in bit_lengths:
        # zaokraglamy w gore do pelnych bajtow (impl. bajtowa)
        n_bytes = max(1, (bits + 7) // 8)
        data = os.urandom(n_bytes)  # losowe dane danej dlugosci
        digest = sha256(data)
        digest_bits = len(digest) * 4  # 1 znak hex = 4 bity
        ok = "OK" if digest_bits == 256 else "BLAD"
        print(f'{bits:>12} {n_bytes:>14} {digest_bits:>18}   {digest}  [{ok}]')

    print("-" * 110)


    # 4) Porownanie czasu: wlasna implementacja vs hashlib
    import time

    print()
    print("Porownanie czasu generowania pojedynczego skrotu:")
    print(f'{"rozmiar wejscia":<20} {"moja [ms]":>14} {"hashlib [ms]":>16} {"stosunek":>12}')
    print("-" * 70)

    sizes = [
        ("11 B (hello world)", b"hello world", 2000),
        ("64 B (1 blok)",      b"a" * 64,      2000),
        ("1 KB",               b"a" * 1024,    500),
        ("10 KB",              b"a" * 10240,   100),
        ("100 KB",             b"a" * 102400,  20),
    ]

    for label, data, repeats in sizes:
        t0 = time.perf_counter()
        for _ in range(repeats):
            sha256(data)
        my_ms = (time.perf_counter() - t0) / repeats * 1000

        t0 = time.perf_counter()
        for _ in range(repeats):
            hashlib.sha256(data).hexdigest()
        lib_ms = (time.perf_counter() - t0) / repeats * 1000

        ratio = my_ms / lib_ms if lib_ms > 0 else float('inf')
        print(f'{label:<20} {my_ms:>14.4f} {lib_ms:>16.4f} {ratio:>11.0f}x')

    print("-" * 70)
