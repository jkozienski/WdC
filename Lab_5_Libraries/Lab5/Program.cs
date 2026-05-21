using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

// Bouncy Castle FIPS 1.0.2
// Wymagane namespace (jedyny assembly: bc-fips-1.0.2.dll)
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.Utilities; // BasicEntropySourceProvider
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;


// Benchmark: Bouncy Castle FIPS 1.0.2 vs .NET Crypto API
//
// ECIES (BC FIPS): ECDH realizowany przez .NET ECDiffieHellman
// (dotnet-native), reszta (AES, HMAC) przez BC FIPS. Powodem
// jest brak publicznego, stabilnego C# API dla FipsEC w tej
// wersji biblioteki.


class Program
{
    const int Iterations = 10;
    const int RsaKeySize = 2048;
    const int AesKeySize = 32;
    const int MacSize    = 32;
    const int PubKeySize = 65; // uncompressed P-256

    static byte[] data = Array.Empty<byte>();

    static readonly FipsSecureRandom FipsRng = BuildFipsRng();

    static FipsSecureRandom BuildFipsRng()
    {
        var ent     = new BasicEntropySourceProvider(new SecureRandom(), true);
        var builder = CryptoServicesRegistrar
            .CreateService(FipsDrbg.Sha512HMac)
            .FromEntropySource(ent);
        builder.SetSecurityStrength(256);
        builder.SetEntropyBitsRequired(256);
        return builder.Build(
            System.Text.Encoding.ASCII.GetBytes("BenchmarkNonce"), true);
    }

    static void Main()
    {
        CryptoServicesRegistrar.SetSecureRandom(FipsRng);

        const string inputFile = "input.txt";
        if (!File.Exists(inputFile))
            File.WriteAllText(inputFile, new string('A', 1024));
        data = File.ReadAllBytes(inputFile);

        Console.WriteLine("============================================================");
        Console.WriteLine("  BENCHMARK: Bouncy Castle FIPS 1.0.2 vs .NET Crypto API");
        Console.WriteLine($"  Dane wejsciowe: {data.Length} bajtow");
        Console.WriteLine($"  Iteracje: {Iterations}");
        Console.WriteLine("============================================================\n");

        Console.WriteLine("[ BOUNCY CASTLE FIPS 1.0.2 ]\n");
        Measure("AES-256-CBC",    BcFipsAesCbc);
        Measure("3DES-CBC",       BcFips3Des);
        Measure("RSA-2048 OAEP",  BcFipsRsa);
        Measure("ECIES (P-256)",  BcFipsEcies);
        Measure("SHA-256",        BcFipsSha256);
        Measure("SHA-3-256",      BcFipsSha3);
        Measure("RSA-PSS podpis", BcFipsRsaSign);

        Console.WriteLine("\n[ .NET CRYPTO API ]\n");
        Measure("AES-256-CBC",    DotNetAesCbc);
        Measure("3DES-CBC",       DotNet3Des);
        Measure("RSA-2048 OAEP",  DotNetRsa);
        Measure("ECIES (P-256)",  DotNetEcies);
        Measure("SHA-256",        DotNetSha256);
        Measure("MD5",            DotNetMd5);
        Measure("RSA-PSS podpis", DotNetRsaSign);

        Console.WriteLine("\n============================================================");
        Console.WriteLine("  Benchmark zakonczony.");
        Console.WriteLine("============================================================");
    }

    static void Measure(string name, Action action)
    {
        try { action(); } catch { }
        var sw = new Stopwatch();
        long total = 0;
        for (int i = 0; i < Iterations; i++)
        {
            sw.Restart(); action(); sw.Stop();
            total += sw.ElapsedTicks;
        }
        double ns = total * (1_000_000_000.0 / Stopwatch.Frequency) / Iterations;
        string f = ns switch
        {
            < 1_000         => $"{ns:F1} ns",
            < 1_000_000     => $"{ns / 1_000:F3} µs",
            < 1_000_000_000 => $"{ns / 1_000_000:F3} ms",
            _               => $"{ns / 1_000_000_000:F3} s"
        };
        Console.WriteLine($"  {name,-20} avg: {f,12}");
    }

    
    // BC FIPS 1.0.2

    // --- AES-256-CBC ---
    static void BcFipsAesCbc()
    {
        FipsAes.Key key = CryptoServicesRegistrar
            .CreateGenerator(FipsAes.KeyGen256, FipsRng)
            .GenerateKey();

        byte[] iv = new byte[16];
        FipsRng.NextBytes(iv);

        byte[] ct = BcFipsAesCbcRun(data, key, iv, encrypt: true);
        BcFipsAesCbcRun(ct, key, iv, encrypt: false);
    }

    // --- 3DES-CBC ---
    static void BcFips3Des()
    {
        // budujemy klucz bezposrednio z losowych bajtow
        byte[] keyBytes = new byte[24];
        FipsRng.NextBytes(keyBytes);
        FipsTripleDes.Key key = new FipsTripleDes.Key(keyBytes);

        byte[] iv = new byte[8];
        FipsRng.NextBytes(iv);

        IBlockCipherService svc = CryptoServicesRegistrar.CreateService(key);

        var encBuf = new MemoryOutputStream();
        using (Stream s = svc
            .CreateBlockEncryptorBuilder(FipsTripleDes.Cbc.WithIV(iv))
            .BuildPaddedCipher(encBuf, new Org.BouncyCastle.Crypto.Paddings.Pkcs7Padding())
            .Stream)
            s.Write(data, 0, data.Length);
        byte[] ct = encBuf.ToArray();

        using Stream dec = svc
            .CreateBlockDecryptorBuilder(FipsTripleDes.Cbc.WithIV(iv))
            .BuildPaddedCipher(
                new MemoryInputStream(ct),
                new Org.BouncyCastle.Crypto.Paddings.Pkcs7Padding())
            .Stream;
        Streams.Drain(dec);
    }

    // --- RSA-2048 OAEP-SHA256 ---
    static void BcFipsRsa()
    {
        var kpGen = CryptoServicesRegistrar.CreateGenerator(
            new FipsRsa.KeyGenerationParameters(
                new Org.BouncyCastle.Math.BigInteger("65537"), RsaKeySize),
            FipsRng);
        AsymmetricKeyPair<AsymmetricRsaPublicKey, AsymmetricRsaPrivateKey> kp =
            kpGen.GenerateKeyPair();

        int maxBlock = RsaKeySize / 8 - 2 * 32 - 2; // 190 bajtow
        byte[] input = data.Length > maxBlock ? data[..maxBlock] : data;

        var spec = FipsRsa.WrapOaep.WithDigest(FipsShs.Sha256);

        byte[] enc = CryptoServicesRegistrar
            .CreateService(kp.PublicKey, FipsRng)
            .CreateKeyWrapper(spec)
            .Wrap(input).Collect();

        CryptoServicesRegistrar
            .CreateService(kp.PrivateKey, FipsRng)
            .CreateKeyUnwrapper(spec)
            .Unwrap(enc, 0, enc.Length).Collect();
    }

    // --- ECIES (P-256): ECDH przez .NET, AES+HMAC przez BC FIPS ---
    static void BcFipsEcies()
    {
        // Para kluczy odbiorcy (.NET)
        using var recipientEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ECParameters recipientPrivParams = recipientEcdh.ExportParameters(true);

        // ===== SZYFROWANIE =====
        using var ephemeral     = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var recipientTemp = ECDiffieHellman.Create(
            recipientEcdh.ExportParameters(false));
        byte[] secret = ephemeral.DeriveRawSecretAgreement(recipientTemp.PublicKey);

        byte[] km      = BcFipsKdf(secret, AesKeySize + MacSize);
        byte[] aesKey  = km[..AesKeySize];
        byte[] macKey  = km[AesKeySize..];

        byte[] iv        = new byte[16]; FipsRng.NextBytes(iv);
        byte[] encrypted = BcFipsAesCbcRun(
            data, new FipsAes.Key(aesKey), iv, encrypt: true);
        byte[] ephPub    = DotNetExportPub(ephemeral);
        byte[] mac       = BcFipsHmac(macKey, ephPub, iv, encrypted);
        byte[] ciphertext = Combine(ephPub, iv, encrypted, mac);

        // ===== ODSZYFROWANIE =====
        byte[] ephPubMsg = ciphertext[..PubKeySize];
        byte[] ivMsg     = ciphertext[PubKeySize..(PubKeySize + 16)];
        byte[] macMsg    = ciphertext[(ciphertext.Length - MacSize)..];
        byte[] encMsg    = ciphertext[(PubKeySize + 16)..(ciphertext.Length - MacSize)];

        using var ephRecov = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q     = new ECPoint { X = ephPubMsg[1..33], Y = ephPubMsg[33..65] }
        });
        using var recipPriv = ECDiffieHellman.Create(recipientPrivParams);
        byte[] secret2 = recipPriv.DeriveRawSecretAgreement(ephRecov.PublicKey);

        byte[] km2     = BcFipsKdf(secret2, AesKeySize + MacSize);
        byte[] aesKey2 = km2[..AesKeySize];
        byte[] macKey2 = km2[AesKeySize..];

        if (!CryptographicOperations.FixedTimeEquals(
                BcFipsHmac(macKey2, ephPubMsg, ivMsg, encMsg), macMsg))
            throw new CryptographicException("HMAC verification failed");

        BcFipsAesCbcRun(encMsg, new FipsAes.Key(aesKey2), ivMsg, encrypt: false);
    }

    // --- SHA-256 ---
    static void BcFipsSha256()
    {
        var calc = CryptoServicesRegistrar
            .CreateService(FipsShs.Sha256).CreateCalculator();
        using (Stream s = calc.Stream) s.Write(data, 0, data.Length);
        calc.GetResult().Collect();
    }

    // --- SHA-3-256 ---
    static void BcFipsSha3()
    {
        var calc = CryptoServicesRegistrar
            .CreateService(FipsShs.Sha3_256).CreateCalculator();
        using (Stream s = calc.Stream) s.Write(data, 0, data.Length);
        calc.GetResult().Collect();
    }

    // --- RSA-PSS podpis (SHA-256, salt=32) ---
    static void BcFipsRsaSign()
    {
        var kpGen = CryptoServicesRegistrar.CreateGenerator(
            new FipsRsa.KeyGenerationParameters(
                new Org.BouncyCastle.Math.BigInteger("65537"), RsaKeySize),
            FipsRng);
        AsymmetricKeyPair<AsymmetricRsaPublicKey, AsymmetricRsaPrivateKey> kp =
            kpGen.GenerateKeyPair();

        var spec = FipsRsa.Pss.WithDigest(FipsShs.Sha256).WithSaltLength(32);

        // Podpisywanie
        ISignatureFactory<FipsRsa.PssSignatureParameters> sigFactory =
            CryptoServicesRegistrar
                .CreateService(kp.PrivateKey, FipsRng)
                .CreateSignatureFactory(spec);
        IStreamCalculator<IBlockResult> signer = sigFactory.CreateCalculator();
        using (Stream s = signer.Stream) s.Write(data, 0, data.Length);
        byte[] sig = signer.GetResult().Collect();

        // Weryfikacja
        IVerifierFactory<FipsRsa.PssSignatureParameters> verFactory =
            CryptoServicesRegistrar
                .CreateService(kp.PublicKey)
                .CreateVerifierFactory(spec);
        IStreamCalculator<IVerifier> verifier = verFactory.CreateCalculator();
        using (Stream s = verifier.Stream) s.Write(data, 0, data.Length);
        verifier.GetResult().IsVerified(sig);
    }

    
    // Metody pomocnicze BC FIPS
    

    static byte[] BcFipsAesCbcRun(byte[] input, FipsAes.Key key, byte[] iv, bool encrypt)
    {
        IBlockCipherService svc = CryptoServicesRegistrar.CreateService(key);
        var padding = new Org.BouncyCastle.Crypto.Paddings.Pkcs7Padding();
        var bOut    = new MemoryOutputStream();

        if (encrypt)
        {
            using Stream s = svc
                .CreateBlockEncryptorBuilder(FipsAes.Cbc.WithIV(iv))
                .BuildPaddedCipher(bOut, padding).Stream;
            s.Write(input, 0, input.Length);
        }
        else
        {
            using Stream s = svc
                .CreateBlockDecryptorBuilder(FipsAes.Cbc.WithIV(iv))
                .BuildPaddedCipher(new MemoryInputStream(input), padding).Stream;
            byte[] plain = Streams.ReadAll(s);
            bOut.Write(plain, 0, plain.Length);
        }
        return bOut.ToArray();
    }

static byte[] BcFipsHmac(byte[] keyBytes, byte[] a, byte[] b, byte[] c)
{
    var macKey = new FipsShs.Key(FipsShs.Sha256HMac, keyBytes);
    var calc = CryptoServicesRegistrar
        .CreateService(macKey)
        .CreateMacFactory(FipsShs.Sha256HMac.WithMacSize(256))
        .CreateCalculator();
    using (Stream s = calc.Stream)
    {
        s.Write(a, 0, a.Length);
        s.Write(b, 0, b.Length);
        s.Write(c, 0, c.Length);
    }
    return calc.GetResult().Collect();
}

    // SHA-256 counter-KDF
    static byte[] BcFipsKdf(byte[] secret, int length)
    {
        using var ms = new MemoryStream();
        for (int ctr = 1; ms.Length < length; ctr++)
        {
            var calc = CryptoServicesRegistrar
                .CreateService(FipsShs.Sha256).CreateCalculator();
            using (Stream s = calc.Stream)
            {
                s.Write(secret, 0, secret.Length);
                byte[] cb = BitConverter.GetBytes(ctr);
                s.Write(cb, 0, cb.Length);
            }
            byte[] h = calc.GetResult().Collect();
            ms.Write(h, 0, h.Length);
        }
        return ms.ToArray()[..length];
    }

    static byte[] DotNetExportPub(ECDiffieHellman ecdh)
    {
        ECParameters p = ecdh.ExportParameters(false);
        byte[] r = new byte[PubKeySize];
        r[0] = 0x04;
        p.Q.X!.CopyTo(r.AsSpan(1));
        p.Q.Y!.CopyTo(r.AsSpan(33));
        return r;
    }

    static byte[] Combine(byte[] a, byte[] b, byte[] c, byte[] d)
    {
        using var ms = new MemoryStream();
        ms.Write(a); ms.Write(b); ms.Write(c); ms.Write(d);
        return ms.ToArray();
    }

    
    // .NET CRYPTO API
    
    static void DotNetAesCbc()
    {
        using var aes = System.Security.Cryptography.Aes.Create();
        aes.KeySize = 256; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
        aes.GenerateKey(); aes.GenerateIV();
        using var enc = aes.CreateEncryptor();
        using var ms1 = new MemoryStream();
        using var cs1 = new CryptoStream(ms1, enc, CryptoStreamMode.Write);
        cs1.Write(data); cs1.FlushFinalBlock();
        byte[] ct = ms1.ToArray();
        using var dec = aes.CreateDecryptor();
        using var ms2 = new MemoryStream(ct);
        using var cs2 = new CryptoStream(ms2, dec, CryptoStreamMode.Read);
        using var ms3 = new MemoryStream(); cs2.CopyTo(ms3);
    }

    static void DotNet3Des()
    {
        using var des = TripleDES.Create();
        des.KeySize = 192; des.Mode = CipherMode.CBC; des.Padding = PaddingMode.PKCS7;
        des.GenerateKey(); des.GenerateIV();
        using var enc = des.CreateEncryptor();
        using var ms1 = new MemoryStream();
        using var cs1 = new CryptoStream(ms1, enc, CryptoStreamMode.Write);
        cs1.Write(data); cs1.FlushFinalBlock();
        byte[] ct = ms1.ToArray();
        using var dec = des.CreateDecryptor();
        using var ms2 = new MemoryStream(ct);
        using var cs2 = new CryptoStream(ms2, dec, CryptoStreamMode.Read);
        using var ms3 = new MemoryStream(); cs2.CopyTo(ms3);
    }

    static void DotNetRsa()
    {
        using var rsa = RSA.Create(RsaKeySize);
        int maxBlock  = rsa.KeySize / 8 - 2 * 32 - 2;
        byte[] input  = data.Length > maxBlock ? data[..maxBlock] : data;
        byte[] enc    = rsa.Encrypt(input, RSAEncryptionPadding.OaepSHA256);
        rsa.Decrypt(enc, RSAEncryptionPadding.OaepSHA256);
    }

    static void DotNetEcies()
    {
        using var recipientEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ECParameters recipPrivParams = recipientEcdh.ExportParameters(true);

        using var ephemeral     = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var recipientTemp = ECDiffieHellman.Create(recipientEcdh.ExportParameters(false));
        byte[] secret = ephemeral.DeriveRawSecretAgreement(recipientTemp.PublicKey);

        byte[] aesKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, AesKeySize,
            info: "aes"u8.ToArray());
        byte[] macKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, MacSize,
            info: "mac"u8.ToArray());

        byte[] iv        = RandomNumberGenerator.GetBytes(16);
        byte[] encrypted = DotNetAesCbcEnc(data, aesKey, iv);
        byte[] ephPub    = DotNetExportPub(ephemeral);
        byte[] mac       = DotNetHmac(macKey, ephPub, iv, encrypted);
        byte[] ciphertext = Combine(ephPub, iv, encrypted, mac);

        byte[] ephPubMsg = ciphertext[..PubKeySize];
        byte[] ivMsg     = ciphertext[PubKeySize..(PubKeySize + 16)];
        byte[] macMsg    = ciphertext[(ciphertext.Length - MacSize)..];
        byte[] encMsg    = ciphertext[(PubKeySize + 16)..(ciphertext.Length - MacSize)];

        using var ephRecov = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q     = new ECPoint { X = ephPubMsg[1..33], Y = ephPubMsg[33..65] }
        });
        using var recipPriv = ECDiffieHellman.Create(recipPrivParams);
        byte[] secret2 = recipPriv.DeriveRawSecretAgreement(ephRecov.PublicKey);

        byte[] aesKey2 = HKDF.DeriveKey(HashAlgorithmName.SHA256, secret2, AesKeySize,
            info: "aes"u8.ToArray());
        byte[] macKey2 = HKDF.DeriveKey(HashAlgorithmName.SHA256, secret2, MacSize,
            info: "mac"u8.ToArray());

        if (!CryptographicOperations.FixedTimeEquals(
                DotNetHmac(macKey2, ephPubMsg, ivMsg, encMsg), macMsg))
            throw new CryptographicException("HMAC verification failed");

        DotNetAesCbcDec(encMsg, aesKey2, ivMsg);
    }

    static byte[] DotNetAesCbcEnc(byte[] input, byte[] key, byte[] iv)
    {
        using var aes = System.Security.Cryptography.Aes.Create();
        aes.KeySize = 256; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
        aes.Key = key; aes.IV = iv;
        using var enc = aes.CreateEncryptor();
        using var ms  = new MemoryStream();
        using var cs  = new CryptoStream(ms, enc, CryptoStreamMode.Write);
        cs.Write(input); cs.FlushFinalBlock();
        return ms.ToArray();
    }

    static byte[] DotNetAesCbcDec(byte[] input, byte[] key, byte[] iv)
    {
        using var aes = System.Security.Cryptography.Aes.Create();
        aes.KeySize = 256; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
        aes.Key = key; aes.IV = iv;
        using var dec = aes.CreateDecryptor();
        using var ms  = new MemoryStream(input);
        using var cs  = new CryptoStream(ms, dec, CryptoStreamMode.Read);
        using var out_ = new MemoryStream(); cs.CopyTo(out_);
        return out_.ToArray();
    }

    static byte[] DotNetHmac(byte[] key, byte[] a, byte[] b, byte[] c)
    {
        using var hmac = new HMACSHA256(key);
        hmac.TransformBlock(a, 0, a.Length, null, 0);
        hmac.TransformBlock(b, 0, b.Length, null, 0);
        hmac.TransformFinalBlock(c, 0, c.Length);
        return hmac.Hash!;
    }

    static void DotNetSha256() => SHA256.HashData(data);
    static void DotNetMd5()    => MD5.HashData(data);

    static void DotNetRsaSign()
    {
        using var rsa = RSA.Create(RsaKeySize);
        byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }
}