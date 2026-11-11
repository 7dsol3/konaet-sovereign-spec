using System.Numerics;
using Konaet.BtcLab.Core;

namespace Konaet.BtcLab.Solver;

/// <summary>
/// Self-challenge kit: generates a fresh random key inside [2^(bits-1), 2^bits) and hands
/// the scanner only the resulting address hash. Nothing about the key is passed to the
/// hunt, so a hit is a real ECDLP solution, not a lookup. This is the honest way to prove
/// the engine works without pretending we can win a live puzzle on a desktop CPU.
/// </summary>
public static class RoundtripKit
{
    public static (TargetSet Set, ScanRange Range, U256 ExpectedKey, string Address) Make(int bits, int trial = 1)
    {
        if (bits is < 2 or > 62) throw new ArgumentOutOfRangeException(nameof(bits), "use 2..62 bits for a self-challenge");
        var rng = new Random(unchecked(Environment.TickCount * 31 + trial * 7919));
        BigInteger lo = BigInteger.One << (bits - 1);
        BigInteger hi = BigInteger.One << bits;
        var bytes = new byte[32];
        BigInteger k;
        do
        {
            rng.NextBytes(bytes);
            k = new BigInteger(bytes, true, true) % (hi - lo) + lo;
        } while (k < lo || k >= hi);

        var key = ScanRange.FromBig(k);
        var addr = KeyHunter.DeriveAddress(key);
        var set = new TargetSet();
        set.Add(new Target(BtcHash.Base58CheckDecode(addr).payload, $"autodesafio de {bits} bits", 0));
        return (set, new ScanRange(ScanRange.FromBig(lo), ScanRange.FromBig(hi)), key, addr);
    }
}
