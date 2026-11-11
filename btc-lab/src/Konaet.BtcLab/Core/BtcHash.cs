using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Konaet.BtcLab.Core;

/// <summary>
/// Hash160 = RIPEMD160(SHA256(x)) and Base58Check, implemented from scratch so the
/// lab has zero external dependencies. Verified against published test vectors
/// (see selftest): RIPEMD160("") and the puzzle #1 address.
/// </summary>
public static class BtcHash
{
    private const string Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static readonly int[] DigitMap = BuildDigitMap();

    private static int[] BuildDigitMap()
    {
        var map = new int[128];
        Array.Fill(map, -1);
        for (int i = 0; i < Alphabet.Length; i++) map[Alphabet[i]] = i;
        return map;
    }

    public static byte[] Sha256(ReadOnlySpan<byte> data)
    {
        var dst = new byte[32];
        SHA256.HashData(data, dst);
        return dst;
    }

    public static void Sha256(ReadOnlySpan<byte> data, Span<byte> dst) => SHA256.HashData(data, dst);

    public static byte[] DoubleSha256(ReadOnlySpan<byte> data)
    {
        var tmp = new byte[32];
        SHA256.HashData(data, tmp);
        var dst = new byte[32];
        SHA256.HashData(tmp, dst);
        return dst;
    }

    public static byte[] Hash160(ReadOnlySpan<byte> data)
    {
        var dst = new byte[20];
        Hash160(data, dst);
        return dst;
    }

    /// <summary>Non-allocating Hash160 for the scanning hot loop.</summary>
    public static void Hash160(ReadOnlySpan<byte> data, Span<byte> dst)
    {
        Span<byte> sha = stackalloc byte[32];
        SHA256.HashData(data, sha);
        Ripemd160(sha, dst);
    }

    public static string AddressFromPublicKey(Span<byte> compressedPubKey) =>
        Base58CheckEncode(0x00, Hash160(compressedPubKey));

    public static string Base58CheckEncode(byte version, ReadOnlySpan<byte> payload)
    {
        Span<byte> buf = stackalloc byte[1 + payload.Length + 4];
        buf[0] = version;
        payload.CopyTo(buf[1..]);
        Span<byte> sum = stackalloc byte[32];
        SHA256.HashData(buf[..(1 + payload.Length)], sum);
        SHA256.HashData(sum, sum);
        sum[..4].CopyTo(buf[(1 + payload.Length)..]);
        return Base58Encode(buf);
    }

    public static string Base58Encode(ReadOnlySpan<byte> data)
    {
        int zeros = 0;
        while (zeros < data.Length && data[zeros] == 0) zeros++;

        var digits = new int[data.Length * 2 + 3];
        int len = 0;
        for (int i = zeros; i < data.Length; i++)
        {
            int carry = data[i];
            for (int j = 0; j < len || carry != 0; j++)
            {
                if (j == len) len++;
                int v = digits[j] * 256 + carry;
                digits[j] = v % 58;
                carry = v / 58;
            }
        }

        var chars = new char[zeros + len];
        for (int i = 0; i < zeros; i++) chars[i] = '1';
        for (int i = 0; i < len; i++) chars[zeros + i] = Alphabet[digits[len - 1 - i]];
        return new string(chars);
    }

    /// <summary>Decodes Base58 and verifies the 4-byte checksum. Returns version + payload.</summary>
    public static (byte version, byte[] payload) Base58CheckDecode(string address)
    {
        byte[] raw = Base58Decode(address);
        if (raw.Length < 5) throw new FormatException("address too short");
        Span<byte> body = raw[..^4];
        Span<byte> sum = stackalloc byte[32];
        SHA256.HashData(body, sum);
        SHA256.HashData(sum, sum);
        for (int i = 0; i < 4; i++)
            if (sum[i] != raw[raw.Length - 4 + i]) throw new FormatException($"bad checksum in '{address}'");
        return (raw[0], raw[1..^4]);
    }

    public static byte[] Base58Decode(string s)
    {
        int leadingOnes = 0;
        while (leadingOnes < s.Length && s[leadingOnes] == '1') leadingOnes++;

        var bytes = new byte[s.Length * 2 + 3];
        int len = 0;
        for (int i = leadingOnes; i < s.Length; i++)
        {
            int carry = s[i] < 128 ? DigitMap[s[i]] : -1;
            if (carry < 0) throw new FormatException($"invalid base58 char '{s[i]}'");
            for (int j = 0; j < len || carry != 0; j++)
            {
                if (j == len) len++;
                int v = bytes[j] * 58 + carry;
                bytes[j] = (byte)(v & 0xFF);
                carry = v >> 8;
            }
        }

        var result = new byte[leadingOnes + len];
        for (int i = 0; i < len; i++) result[leadingOnes + i] = bytes[len - 1 - i];
        return result;
    }

    // ------------------- RIPEMD-160 -------------------

    private static readonly int[] RL =
    {
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
        7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
        3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
        1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
        4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13
    };

    // Message-word indexes and shift amounts transcribed mechanically from Bitcoin Core's
    // unrolled ripemd160.cpp, then validated against openssl's RIPEMD-160 KATs (see selftest).
    private static readonly int[] RR =
    {
        5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
        6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
        15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
        8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
        12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11
    };

    private static readonly int[] SL =
    {
        11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
        7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
        11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
        11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
        9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6
    };

    private static readonly int[] SR =
    {
        8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
        9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
        9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
        15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
        8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11
    };

    private static readonly uint[] KL = { 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E };
    private static readonly uint[] KR = { 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000 };

    private static uint F(int j, uint x, uint y, uint z) => j switch
    {
        < 16 => x ^ y ^ z,
        < 32 => (x & y) | (~x & z),
        < 48 => (x | ~y) ^ z,
        < 64 => (x & z) | (y & ~z),
        _ => x ^ (y | ~z),
    };

    private static uint Rotl(uint x, int n) => (x << n) | (x >> (32 - n));

    public static byte[] Ripemd160(ReadOnlySpan<byte> input)
    {
        var dst = new byte[20];
        Ripemd160(input, dst);
        return dst;
    }

    public static void Ripemd160(ReadOnlySpan<byte> input, Span<byte> outBytes)
    {
        uint h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
        long totalBits = (long)input.Length * 8;

        int padded = (int)(((input.Length + 72) / 64) * 64);
        Span<byte> buf = padded <= 512 ? stackalloc byte[padded] : new byte[padded];
        buf.Clear();
        input.CopyTo(buf);
        buf[input.Length] = 0x80;
        BinaryPrimitives.WriteInt64LittleEndian(buf[^8..], totalBits);

        Span<uint> x = stackalloc uint[16];
        for (int off = 0; off < padded; off += 64)
        {
            for (int i = 0; i < 16; i++) x[i] = BinaryPrimitives.ReadUInt32LittleEndian(buf[(off + i * 4)..]);

            uint a = h0, b = h1, c = h2, d = h3, e = h4;
            for (int j = 0; j < 80; j++)
            {
                uint t = Rotl(a + F(j, b, c, d) + x[RL[j]] + KL[j / 16], SL[j]) + e;
                a = e; e = d; d = Rotl(c, 10); c = b; b = t;
            }
            uint aa = h0, bb = h1, cc = h2, dd = h3, ee = h4;
            for (int j = 0; j < 80; j++)
            {
                uint t = Rotl(aa + F(79 - j, bb, cc, dd) + x[RR[j]] + KR[j / 16], SR[j]) + ee;
                aa = ee; ee = dd; dd = Rotl(cc, 10); cc = bb; bb = t;
            }
            // the two pipelines are combined crosswise: left (a,b,c,d,e) with right (aa..ee)
            uint tmp = h1 + c + dd;
            h1 = h2 + d + ee;
            h2 = h3 + e + aa;
            h3 = h4 + a + bb;
            h4 = h0 + b + cc;
            h0 = tmp;
        }

        BinaryPrimitives.WriteUInt32LittleEndian(outBytes[0..], h0);
        BinaryPrimitives.WriteUInt32LittleEndian(outBytes[4..], h1);
        BinaryPrimitives.WriteUInt32LittleEndian(outBytes[8..], h2);
        BinaryPrimitives.WriteUInt32LittleEndian(outBytes[12..], h3);
        BinaryPrimitives.WriteUInt32LittleEndian(outBytes[16..], h4);
    }
}
