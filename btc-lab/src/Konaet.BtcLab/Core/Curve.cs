namespace Konaet.BtcLab.Core;

/// <summary>
/// secp256k1 in Jacobian coordinates. Point format: affine when Z == 1,
/// point at infinity when Z == 0.
/// </summary>
public readonly struct JPoint
{
    public readonly U256 X, Y, Z;

    public JPoint(U256 x, U256 y, U256 z) { X = x; Y = y; Z = z; }

    public static readonly JPoint Infinity = new(U256.Zero, U256.Zero, U256.Zero);
    public static readonly JPoint G = new(U256.Gx, U256.Gy, U256.One);

    public bool IsInfinity => Z.IsZero;

    public static JPoint Affine(U256 x, U256 y) => new(x, y, U256.One);

    /// <summary>2*P, dbl-2009-l.</summary>
    public static JPoint Double(in JPoint p)
    {
        if (p.Z.IsZero || p.Y.IsZero) return Infinity;
        var a = U256.SqrMod(p.X);
        var b = U256.SqrMod(p.Y);
        var c = U256.SqrMod(b);
        var xpb = U256.AddMod(p.X, b);
        var d = U256.SubMod(U256.SubMod(U256.SqrMod(xpb), a), c);
        d = U256.AddMod(d, d);                       // D = 2*((X+B)^2 - A - C)
        var e = U256.AddMod(a, U256.AddMod(a, a));   // E = 3A
        var f = U256.SqrMod(e);
        var x3 = U256.SubMod(f, U256.AddMod(d, d));
        var c8 = U256.AddMod(c, c); c8 = U256.AddMod(c8, c8); c8 = U256.AddMod(c8, c8); // 8C
        // Derivado à mão (Z1=1): X3 = F-2D, Y3 = E*(3D-F)-8C, Z3 = 2*Y1*Z1.
        // A versão "E*(D-F)" que anda circulando como dbl-2009-l não satisfaz Y^2=X^3+7Z^6.
        var d3 = U256.AddMod(d, U256.AddMod(d, d));
        var y3 = U256.SubMod(U256.MulMod(e, U256.SubMod(d3, f)), c8);
        var z3 = U256.AddMod(U256.MulMod(p.Y, p.Z), U256.MulMod(p.Y, p.Z));
        return new JPoint(x3, y3, z3);
    }

    /// <summary>Generic P+Q, add-2009-l.</summary>
    public static JPoint Add(in JPoint p, in JPoint q)
    {
        if (p.IsInfinity) return q;
        if (q.IsInfinity) return p;

        var z1z1 = U256.SqrMod(p.Z);
        var z2z2 = U256.SqrMod(q.Z);
        var u1 = U256.MulMod(p.X, z2z2);
        var u2 = U256.MulMod(q.X, z1z1);
        var s1 = U256.MulMod(p.Y, U256.MulMod(q.Z, z2z2));
        var s2 = U256.MulMod(q.Y, U256.MulMod(p.Z, z1z1));
        var h = U256.SubMod(u2, u1);
        var r = U256.SubMod(s2, s1);
        if (h.IsZero) return r.IsZero ? Double(p) : Infinity;

        var hh = U256.SqrMod(h);
        var hhh = U256.MulMod(hh, h);
        var u1hh = U256.MulMod(u1, hh);                   // U1*P^2, kept undoubled for the Y3 term
        var x3 = U256.SubMod(U256.SubMod(U256.SqrMod(r), hhh), U256.AddMod(u1hh, u1hh));
        var y3 = U256.SubMod(U256.MulMod(r, U256.SubMod(u1hh, x3)), U256.MulMod(s1, hhh));
        var z3 = U256.MulMod(h, U256.MulMod(p.Z, q.Z));
        return new JPoint(x3, y3, z3);
    }

    /// <summary>P + G specialised for the constant generator (Z2 = 1). The scanner's hot loop.</summary>
    public static JPoint AddG(in JPoint p)
    {
        if (p.IsInfinity) return G;

        var z1z1 = U256.SqrMod(p.Z);
        var u2 = U256.MulMod(z1z1, U256.Gx);            // Gx * Z1^2
        var s2 = U256.MulMod(U256.MulMod(z1z1, p.Z), U256.Gy);
        var h = U256.SubMod(u2, p.X);
        var r = U256.SubMod(s2, p.Y);
        if (h.IsZero) return r.IsZero ? Double(p) : Infinity;

        var hh = U256.SqrMod(h);
        var hhh = U256.MulMod(hh, h);
        var u1hh = U256.MulMod(p.X, hh);                // U1 = X1 (Z2 = 1)
        var x3 = U256.SubMod(U256.SubMod(U256.SqrMod(r), hhh), U256.AddMod(u1hh, u1hh));
        var y3 = U256.SubMod(U256.MulMod(r, U256.SubMod(u1hh, x3)), U256.MulMod(p.Y, hhh));
        var z3 = U256.MulMod(h, p.Z);
        return new JPoint(x3, y3, z3);
    }

    /// <summary>k*G by double-and-add (used to seed each scan chunk, not the hot loop).</summary>
    public static JPoint MulGenerator(in U256 k) => Mul(G, k);

    /// <summary>scalar*P for an arbitrary point (used by the Kangaroo benchmark).</summary>
    public static JPoint Mul(in JPoint p, in U256 k)
    {
        var result = Infinity;
        var addend = p;
        for (int i = 0; i < 256; i++)
        {
            if (U256.Bit(k, i)) result = Add(result, addend);
            addend = Double(addend);
        }
        return result;
    }

    public static (U256 x, U256 y) ToAffine(in JPoint p)
    {
        if (p.IsInfinity) throw new InvalidOperationException("point at infinity has no affine coordinates");
        var zi = U256.InvMod(p.Z);
        var zi2 = U256.SqrMod(zi);
        var zi3 = U256.MulMod(zi2, zi);
        return (U256.MulMod(p.X, zi2), U256.MulMod(p.Y, zi3));
    }

    /// <summary>33-byte SEC compressed encoding of the affine x coordinate.</summary>
    public static void Compress(U256 x, U256 y, Span<byte> dst)
    {
        dst[0] = (byte)(y.IsOdd ? 0x03 : 0x02);
        x.ToBytes(dst[1..33]);
    }

    /// <summary>In-place batch inverse of zs[0..count-1] using Montgomery's trick:
    /// one modular inversion for the whole batch plus 3 multiplications per element.</summary>
    public static void BatchInvert(Span<U256> zs, int count, Span<U256> prefix)
    {
        if (count == 0) return;
        prefix[0] = zs[0];
        for (int i = 1; i < count; i++) prefix[i] = U256.MulMod(prefix[i - 1], zs[i]);

        var inv = U256.InvMod(prefix[count - 1]);
        for (int i = count - 1; i >= 1; i--)
        {
            var zi = U256.MulMod(inv, prefix[i - 1]);
            inv = U256.MulMod(inv, zs[i]);
            zs[i] = zi;
        }
        zs[0] = inv;
    }

    /// <summary>
    /// Converts a batch of Jacobian points to affine x coordinates, one inversion per batch.
    /// zs is overwritten with the inverses; xs/ys are overwritten with affine coordinates.
    /// </summary>
    public static void BatchToAffine(Span<U256> xs, Span<U256> ys, Span<U256> zs, int count, Span<U256> prefix)
    {
        BatchInvert(zs, count, prefix);
        for (int i = 0; i < count; i++)
        {
            var z2 = U256.SqrMod(zs[i]);
            var z3 = U256.MulMod(z2, zs[i]);
            xs[i] = U256.MulMod(xs[i], z2);
            ys[i] = U256.MulMod(ys[i], z3);
        }
    }
}
