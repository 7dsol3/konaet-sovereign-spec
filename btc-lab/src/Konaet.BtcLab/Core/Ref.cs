using System.Numerics;

namespace Konaet.BtcLab.Core;

/// <summary>
/// Independent, deliberately naive BigInteger implementation of the same math.
/// Only used to cross-check the fast path (selftest) and as a source of truth for
/// one-off key -> address derivations. Slow but obviously correct.
/// </summary>
public static class Ref
{
    public static readonly BigInteger P = U256.P.ToBig();
    public static readonly BigInteger N = U256.N.ToBig();
    public static readonly BigInteger Gx = U256.Gx.ToBig();
    public static readonly BigInteger Gy = U256.Gy.ToBig();

    public static BigInteger ToBig(this in U256 v) =>
        new(v.ToBytes(), true, isBigEndian: true);

    public static U256 ToU256(this BigInteger v)
    {
        var b = new byte[32];
        v.WriteToBytesBigEndian(b);
        return U256.FromBytes(b);
    }

    private static void WriteToBytesBigEndian(this BigInteger v, Span<byte> dst)
    {
        var tmp = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        dst.Clear();
        tmp.CopyTo(dst[(dst.Length - tmp.Length)..]);
    }

    private static BigInteger Mod(BigInteger a)
    {
        var r = a % P;
        return r.Sign < 0 ? r + P : r;
    }

    public static BigInteger Inv(BigInteger a) => BigInteger.ModPow(a, P - 2, P);

    public static (BigInteger x, BigInteger y)? Add((BigInteger x, BigInteger y)? p, (BigInteger x, BigInteger y)? q)
    {
        if (p is null) return q;
        if (q is null) return p;
        var (x1, y1) = p.Value;
        var (x2, y2) = q.Value;
        if (x1 == x2)
        {
            if (Mod(y1 + y2) == 0) return null;               // P + (-P) = infinity
            var s = Mod((3 * x1 * x1) * Inv(2 * y1));          // doubling
            var x3 = Mod(s * s - 2 * x1);
            var y3 = Mod(s * (x1 - x3) - y1);
            return (x3, y3);
        }
        {
            var s = Mod((y2 - y1) * Inv(x2 - x1));
            var x3 = Mod(s * s - x1 - x2);
            var y3 = Mod(s * (x1 - x3) - y1);
            return (x3, y3);
        }
    }

    public static (BigInteger x, BigInteger y)? MulGenerator(BigInteger k)
    {
        k = Mod(k - BigInteger.Zero) % N;
        (BigInteger x, BigInteger y)? result = null;
        (BigInteger, BigInteger)? addend = (Gx, Gy);
        for (int i = 0; i < 256; i++)
        {
            if ((k >> i & BigInteger.One) == BigInteger.One) result = Add(result, addend);
            addend = Add(addend, addend);
        }
        return result;
    }

    public static byte[] Compressed(BigInteger x, BigInteger y)
    {
        var dst = new byte[33];
        dst[0] = (byte)((y & 1) == 1 ? 0x03 : 0x02);
        var xb = x.ToByteArray(isUnsigned: true, isBigEndian: true);
        xb.CopyTo(dst.AsSpan(33 - xb.Length));
        return dst;
    }

    public static string AddressForPrivateKey(BigInteger k)
    {
        var pt = MulGenerator(k) ?? throw new InvalidOperationException("k*G is infinity");
        return BtcHash.AddressFromPublicKey(Compressed(pt.x, pt.y).AsSpan());
    }

    public static string AddressForPrivateKey(in U256 k) => AddressForPrivateKey(k.ToBig());
}
