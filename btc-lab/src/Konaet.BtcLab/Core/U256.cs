using System.Runtime.InteropServices;

namespace Konaet.BtcLab.Core;

/// <summary>
/// 256-bit unsigned integer, 4 little-endian 64-bit limbs, with field arithmetic
/// modulo the secp256k1 prime p = 2^256 - 2^32 - 977.
/// Deliberately dependency-free so the whole lab builds offline with the base .NET SDK.
/// </summary>
public readonly struct U256 : IEquatable<U256>
{
    public readonly ulong L0, L1, L2, L3;

    public U256(ulong l0, ulong l1, ulong l2, ulong l3)
    {
        L0 = l0; L1 = l1; L2 = l2; L3 = l3;
    }

    public static readonly U256 Zero = default;
    public static readonly U256 One = new(1, 0, 0, 0);

    // secp256k1 field prime
    public static readonly U256 P = new(0xFFFFFFFE_FFFFFC2FUL, 0xFFFFFFFF_FFFFFFFFUL, 0xFFFFFFFF_FFFFFFFFUL, 0xFFFFFFFF_FFFFFFFFUL);
    // secp256k1 group order n
    public static readonly U256 N = new(0xBFD25E8C_D0364141UL, 0xBAAEDCE6_AF48A03BUL, 0xFFFFFFFF_FFFFFFFEUL, 0xFFFFFFFF_FFFFFFFFUL);
    // generator, SEC 2 ver 2.0 section 2.7.1 (same bytes as bitcoin-core's SECP256K1_G)
    public static readonly U256 Gx = new(0x59F2815B_16F81798UL, 0x029BFCDB_2DCE28D9UL, 0x55A06295_CE870B07UL, 0x79BE667E_F9DCBBACUL);
    public static readonly U256 Gy = new(0x9C47D08F_FB10D4B8UL, 0xFD17B448_A6855419UL, 0x5DA4FBFC_0E1108A8UL, 0x483ADA77_26A3C465UL);

    // 2^256 mod p = 2^32 + 977
    public const ulong K_LO = 0x00000001_000003D1UL;
    public static readonly U256 K = new(K_LO, 0, 0, 0);

    public bool IsZero => (L0 | L1 | L2 | L3) == 0;
    public bool IsOdd => (L0 & 1UL) != 0;

    public bool Equals(U256 other) => L0 == other.L0 && L1 == other.L1 && L2 == other.L2 && L3 == other.L3;
    public override bool Equals(object? obj) => obj is U256 u && Equals(u);
    public override int GetHashCode() => HashCode.Combine(L0, L1, L2, L3);
    public static bool operator ==(U256 a, U256 b) => a.Equals(b);
    public static bool operator !=(U256 a, U256 b) => !a.Equals(b);

    public static int Compare(in U256 a, in U256 b)
    {
        if (a.L3 != b.L3) return a.L3 > b.L3 ? 1 : -1;
        if (a.L2 != b.L2) return a.L2 > b.L2 ? 1 : -1;
        if (a.L1 != b.L1) return a.L1 > b.L1 ? 1 : -1;
        if (a.L0 != b.L0) return a.L0 > b.L0 ? 1 : -1;
        return 0;
    }

    public override string ToString() => $"{{{L3:X16}:{L2:X16}:{L1:X16}:{L0:X16}}}";

    /// <summary>Big-endian 32 bytes.</summary>
    public void ToBytes(Span<byte> dst)
    {
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(dst[0..8], L3);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(dst[8..16], L2);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(dst[16..24], L1);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(dst[24..32], L0);
    }

    public byte[] ToBytes()
    {
        var b = new byte[32];
        ToBytes(b);
        return b;
    }

    public static U256 FromBytes(ReadOnlySpan<byte> src)
    {
        if (src.Length != 32) throw new ArgumentException("need 32 bytes");
        return new U256(
            System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(src[24..]),
            System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(src[16..]),
            System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(src[8..]),
            System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(src[0..]));
    }

    public static U256 FromHex(string hex)
    {
        hex = hex.Trim().Replace("0x", "").Replace("_", "").Replace(" ", "");
        if (hex.Length % 2 == 1) hex = "0" + hex;
        if (hex.Length > 64) hex = hex[^(64)..];
        var bytes = new byte[32];
        int n = hex.Length / 2;
        for (int i = 0; i < n; i++)
            bytes[32 - n + i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return FromBytes(bytes);
    }

    public string ToHex() => Convert.ToHexString(ToBytes()).ToLowerInvariant();

    // ---------------- additive ----------------

    public static U256 AddRaw(in U256 a, in U256 b, out ulong hi)
    {
        UInt128 s = (UInt128)a.L0 + b.L0; ulong l0 = (ulong)s; ulong c = (ulong)(s >> 64);
        s = (UInt128)a.L1 + b.L1 + c; ulong l1 = (ulong)s; c = (ulong)(s >> 64);
        s = (UInt128)a.L2 + b.L2 + c; ulong l2 = (ulong)s; c = (ulong)(s >> 64);
        s = (UInt128)a.L3 + b.L3 + c; ulong l3 = (ulong)s; hi = (ulong)(s >> 64);
        return new U256(l0, l1, l2, l3);
    }

    /// <summary>
    /// (a+b) mod p for a,b &lt; p. a+b can reach 2^257: the overflow above 2^256 is
    /// folded back as +K (because 2^256 = K mod p), then normalised by conditional subtract.
    /// </summary>
    public static U256 AddMod(in U256 a, in U256 b)
    {
        var r = AddRaw(a, b, out ulong hi);
        if (hi != 0) r = AddRaw(r, K, out _);
        while (Compare(r, P) >= 0) r = SubRaw(r, P);
        return r;
    }

    public static U256 SubRaw(in U256 a, in U256 b)
    {
        UInt128 s = (UInt128)a.L0 - b.L0; ulong l0 = (ulong)s; ulong br = (ulong)(s >> 64) & 1;
        s = (UInt128)a.L1 - b.L1 - br; ulong l1 = (ulong)s; br = (ulong)(s >> 64) & 1;
        s = (UInt128)a.L2 - b.L2 - br; ulong l2 = (ulong)s; br = (ulong)(s >> 64) & 1;
        s = (UInt128)a.L3 - b.L3 - br; ulong l3 = (ulong)s;
        return new U256(l0, l1, l2, l3);
    }

    /// <summary>
    /// (a-b) mod p for a,b &lt; p. When a &lt; b the wrap-around left us with a-b+2^256,
    /// so remove 2^256-P = K instead of trying to add P back (which overflows again).
    /// </summary>
    public static U256 SubMod(in U256 a, in U256 b)
    {
        var d = SubRaw(a, b);
        if (Compare(a, b) < 0) d = SubRaw(d, K);
        while (Compare(d, P) >= 0) d = SubRaw(d, P);
        return d;
    }

    public static U256 ShiftRight1(in U256 a) =>
        new U256((a.L0 >> 1) | (a.L1 << 63), (a.L1 >> 1) | (a.L2 << 63), (a.L2 >> 1) | (a.L3 << 63), a.L3 >> 1);

    // ---------------- multiplicative ----------------

    /// <summary>512-bit product limbs (little endian, 8 entries) of a*b.</summary>
    private static void MulWide(in U256 a, in U256 b, Span<ulong> c)
    {
        Span<ulong> al = stackalloc ulong[4] { a.L0, a.L1, a.L2, a.L3 };
        Span<ulong> bl = stackalloc ulong[4] { b.L0, b.L1, b.L2, b.L3 };
        c.Clear();
        for (int i = 0; i < 4; i++)
        {
            ulong carry = 0;
            for (int j = 0; j < 4; j++)
            {
                ulong hi = Math.BigMul(al[i], bl[j], out ulong lo);   // BigMul returns the HIGH word
                UInt128 acc = (UInt128)c[i + j] + lo + carry;
                c[i + j] = (ulong)acc;
                carry = hi + (ulong)(acc >> 64);
            }
            c[i + 4] += carry; // safe: c[4..7] accumulate at most 2^64-1 total per position here
        }
    }

    /// <summary>a*b mod p.</summary>
    public static U256 MulMod(in U256 a, in U256 b)
    {
        Span<ulong> c = stackalloc ulong[8];
        MulWide(a, b, c);
        return Reduce(c);
    }

    public static U256 SqrMod(in U256 a) => MulMod(a, a);

    /// <summary>
    /// Reduce a 512-bit product modulo p. Uses 2^256 = K (mod p) with K = 2^32 + 977,
    /// folding each limb above 2^256 down. Folds strictly move mass to lower limb
    /// indices, so the descending loop always terminates.
    /// </summary>
    public static U256 Reduce(Span<ulong> c)
    {
        Span<ulong> acc = stackalloc ulong[6];
        acc[0] = c[0]; acc[1] = c[1]; acc[2] = c[2]; acc[3] = c[3]; acc[4] = 0; acc[5] = 0;

        for (int i = 4; i <= 7; i++)
            if (c[i] != 0) FoldInto(acc, c[i], i - 4);

        for (int j = 5; j >= 4; j--)
            while (acc[j] != 0)
            {
                ulong v = acc[j];
                acc[j] = 0;
                FoldInto(acc, v, j - 4);
            }

        var r = new U256(acc[0], acc[1], acc[2], acc[3]);
        while (Compare(r, P) >= 0) r = SubRaw(r, P);
        return r;
    }

    /// <summary>acc += value * K * 2^(64*off), where value*K is a 97-bit quantity.</summary>
    private static void FoldInto(Span<ulong> acc, ulong value, int off)
    {
        ulong hi = Math.BigMul(value, K_LO, out ulong lo);            // BigMul returns the HIGH word
        ulong carry = AddAt(acc, off, lo);
        carry = AddAt(acc, off + 1, hi + carry); // hi < 2^33, carry <= 1: cannot overflow
        if (carry != 0) AddAt(acc, off + 2, carry);
    }

    private static ulong AddAt(Span<ulong> acc, int index, ulong value)
    {
        UInt128 s = (UInt128)acc[index] + value;
        acc[index] = (ulong)s;
        return (ulong)(s >> 64);
    }

    /// <summary>a^e mod p (square and multiply, MSB first).</summary>
    public static U256 PowMod(in U256 a, in U256 e)
    {
        var result = One;
        bool started = false;
        for (int i = 255; i >= 0; i--)
        {
            if (started) result = SqrMod(result);
            if (Bit(e, i))
            {
                result = started ? MulMod(result, a) : a;
                started = true;
            }
        }
        return result;
    }

    public static bool Bit(in U256 a, int index) =>
        ((index >> 6) switch { 0 => a.L0, 1 => a.L1, 2 => a.L2, _ => a.L3 } >> (index & 63) & 1) != 0;

    /// <summary>Modular inverse via a^(p-2); slow in isolation but only used once per batch.</summary>
    public static U256 InvMod(in U256 a)
    {
        if (a.IsZero) throw new DivideByZeroException("inverse of zero");
        return PowMod(a, SubRaw(P, new U256(2, 0, 0, 0)));
    }

    public static U256 Neg(in U256 a) => a.IsZero ? a : SubRaw(P, a);
}
