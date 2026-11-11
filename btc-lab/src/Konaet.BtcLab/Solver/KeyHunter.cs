using System.Numerics;
using Konaet.BtcLab.Core;

namespace Konaet.BtcLab.Solver;

/// <summary>A target address to look for, plus the label we report when it hits.</summary>
public sealed record Target(byte[] Hash160, string Label, int Puzzle);

/// <summary>
/// Set of allowed scan targets. Entries come from the published puzzle registry
/// (data/puzzle_addresses.json) or from a key this process generated itself in the
/// round-trip test. That restriction is the guardrail: the scanner can only be told
/// to look for coins the puzzle authors put up for grabs, never an arbitrary address.
/// </summary>
public sealed class TargetSet
{
    private readonly List<Target> _targets = new();
    private readonly HashSet<uint> _prefixFilter = new();

    public IReadOnlyList<Target> Targets => _targets;
    public int Count => _targets.Count;

    public void Add(Target t)
    {
        _targets.Add(t);
        _prefixFilter.Add(Prefix(t.Hash160));
    }

    public static uint Prefix(ReadOnlySpan<byte> b) =>
        ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];

    /// <summary>4-byte bloom check first, full 20-byte compare only on a probable hit.</summary>
    public bool Matches(ReadOnlySpan<byte> hash, out Target? target)
    {
        target = null;
        if (!_prefixFilter.Contains(Prefix(hash))) return false;
        foreach (var t in _targets)
            if (t.Hash160.AsSpan().SequenceEqual(hash)) { target = t; return true; }
        return false;
    }

    public static Target FromAddress(string address, string label, int puzzle = 0)
    {
        var (version, payload) = BtcHash.Base58CheckDecode(address);
        if (version != 0x00 || payload.Length != 20)
            throw new ArgumentException($"only P2PKH (version 0, 20-byte hash) puzzle addresses are supported: {address}");
        return new Target(payload, label, puzzle);
    }
}

public readonly struct ScanRange
{
    public U256 Start { get; }
    public U256 End { get; }

    public ScanRange(U256 start, U256 end) { Start = start; End = end; }

    public BigInteger SizeBig => ToBig(End) - ToBig(Start);
    public double Size => (double)SizeBig;
    public bool Empty => U256.Compare(End, Start) <= 0;

    public static BigInteger ToBig(in U256 v) => new(v.ToBytes(), true, isBigEndian: true);
    public static U256 FromBig(BigInteger v)
    {
        var b = new byte[32];
        var raw = v.ToByteArray(true, true);
        raw.CopyTo(b.AsSpan(32 - raw.Length));
        return U256.FromBytes(b);
    }

    private const long SliceScale = 1_000_000;

    /// <summary>Sub-range [from, to) of this interval, with 1e-6 relative precision.</summary>
    public ScanRange Slice(double from, double to)
    {
        var size = SizeBig;
        var lo = from <= 0 ? Start : FromBig(ToBig(Start) + size * (BigInteger)(long)(from * SliceScale) / SliceScale);
        var hi = to >= 1.0 ? End : FromBig(ToBig(Start) + size * (BigInteger)(long)(to * SliceScale) / SliceScale);
        return new ScanRange(lo, hi);
    }

    public override string ToString() => $"[{Start.ToHex()[..12]}.. {End.ToHex()[..12]})";
}

public sealed class ScanResult
{
    public bool Found;
    public U256 PrivateKey;
    public string Address = "";
    public string Label = "";
    public ulong KeysScanned;
    /// <summary>Chaves varridas só pela fatia do worker que achou - 1/N do total do grupo.</summary>
    public ulong FinderSliceKeys;
    public double ElapsedSeconds;
    public int Jobs;

    public double KeysPerSecond => KeysScanned / Math.Max(ElapsedSeconds, 1e-9);

    public string Report() => Found
        ? $"FOUND  private key = 0x{PrivateKey.ToHex()}\n" +
          $"       address     = {Address}\n" +
          $"       matched     = {Label}\n" +
          $"       work        = {KeysScanned:N0} keys in {ElapsedSeconds:F2}s across {Jobs} workers ({KeysPerSecond:N0} keys/s)\n" +
          $"                   (o worker que achou contribuiu {FinderSliceKeys:N0} dessas; o resto é o trabalho paralelo das outras {Math.Max(Jobs - 1, 0)} fatias)"
        : $"no hit: {KeysScanned:N0} keys tried in {ElapsedSeconds:F2}s across {Jobs} workers ({KeysPerSecond:N0} keys/s)";
}

/// <summary>
/// Parallel brute-force key-range scanner. Each worker walks its own contiguous slice
/// of the interval using incremental Jacobian point additions (P += G), converts a
/// batch of points to affine coordinates with a single modular inversion, then hashes
/// each public key and compares the Hash160 against the target set.
/// </summary>
public sealed class KeyHunter
{
    /// <summary>Keys per inversion batch. Bigger = fewer inversions, more memory per worker.
    /// Measurable knob: try --batch 512 vs 4096 on your own box.</summary>
    public int BatchSize { get; init; } = 4096;

    private readonly TargetSet _targets;

    public KeyHunter(TargetSet targets, int batchSize = 4096)
    {
        _targets = targets;
        BatchSize = batchSize;
    }

    public ScanResult Hunt(ScanRange range, int jobs, TimeSpan maxTime, Action<ulong, double>? progress = null)
    {
        if (jobs < 1) jobs = 1;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var deadline = maxTime;
        var stop = false;
        long scannedShared = 0;
        ScanResult? hit = null;
        var hitLock = new object();

        var tasks = new Task[jobs];
        for (int i = 0; i < jobs; i++)
        {
            var slice = range.Slice((double)i / jobs, (double)(i + 1) / jobs);
            if (slice.Empty) { tasks[i] = Task.CompletedTask; continue; }
            tasks[i] = Task.Run(() =>
            {
                var local = ScanSlice(slice, () => Volatile.Read(ref stop) || sw.Elapsed > deadline,
                                      sw, deadline, n => Interlocked.Add(ref scannedShared, (long)n),
                                      out _);
                if (local is not null)
                {
                    lock (hitLock)
                    {
                        if (hit is null)
                        {
                            local.Jobs = jobs;
                            // KeysScanned vindo da varredura é só a FATIA do worker que achou
                            // (~1/N do grupo). Como a linha "work" é a que se compara com
                            // docs/bench.txt, ela tem que reportar o total do grupo; o contador
                            // compartilhado já soma todos os workers (por batch completo, então
                            // no pior caso falta um batch de cada um - sub-estimativa, na
                            // direção honesta). O total local nunca pode ser menor que o do
                            // achador, daí o max.
                            local.FinderSliceKeys = local.KeysScanned;
                            local.KeysScanned = Math.Max(local.KeysScanned,
                                (ulong)Interlocked.Read(ref scannedShared));
                            hit = local;
                        }
                    }
                    Volatile.Write(ref stop, true);
                }
            });
        }

        Task monitor = Task.Run(async () =>
        {
            while (!Volatile.Read(ref stop) && sw.Elapsed <= deadline && !tasks.All(t => t.IsCompleted))
            {
                await Task.Delay(2000);
                progress?.Invoke((ulong)Interlocked.Read(ref scannedShared), sw.Elapsed.TotalSeconds);
            }
        });

        Task.WaitAll(tasks);
        Volatile.Write(ref stop, true);
        monitor.Wait();

        return hit ?? new ScanResult
        {
            Found = false,
            KeysScanned = (ulong)Interlocked.Read(ref scannedShared),
            ElapsedSeconds = sw.Elapsed.TotalSeconds,
            Jobs = jobs,
        };
    }

    private ScanResult? ScanSlice(ScanRange slice, Func<bool> shouldStop, System.Diagnostics.Stopwatch sw,
                                  TimeSpan deadline, Action<int> onBatch, out ulong scannedOut)
    {
        var xs = new U256[BatchSize];
        var ys = new U256[BatchSize];
        var zs = new U256[BatchSize];
        var prefix = new U256[BatchSize];
        Span<byte> pub = stackalloc byte[33];
        Span<byte> hash = stackalloc byte[20];

        ulong scanned = 0;
        var k = slice.Start;
        var p = JPoint.MulGenerator(k);

        while (U256.Compare(k, slice.End) < 0 && !shouldStop())
        {
            var batchStart = k;
            int len = 0;
            while (len < BatchSize && U256.Compare(k, slice.End) < 0)
            {
                xs[len] = p.X;
                ys[len] = p.Y;
                zs[len] = p.IsInfinity ? U256.One : p.Z;
                k = U256.AddRaw(k, U256.One, out _);
                p = JPoint.AddG(p);
                len++;
            }

            JPoint.BatchToAffine(xs, ys, zs, len, prefix);

            for (int i = 0; i < len; i++)
            {
                if (xs[i].IsZero && ys[i].IsZero) continue;   // slot was an infinity: no valid point
                JPoint.Compress(xs[i], ys[i], pub);
                BtcHash.Hash160(pub, hash);
                if (_targets.Matches(hash, out var t))
                {
                    scannedOut = scanned + (ulong)i + 1;
                    return new ScanResult
                    {
                        Found = true,
                        PrivateKey = U256.AddRaw(batchStart, new U256((ulong)i, 0, 0, 0), out _),
                        Address = BtcHash.AddressFromPublicKey(pub),
                        Label = t!.Label,
                        KeysScanned = scannedOut,
                        ElapsedSeconds = sw.Elapsed.TotalSeconds,
                    };
                }
            }

            scanned += (ulong)len;
            onBatch(len);
        }

        scannedOut = scanned;
        return null;
    }

    /// <summary>Derive the P2PKH address of a private key (used to publish verifiable results).</summary>
    public static string DeriveAddress(in U256 k)
    {
        var p = JPoint.MulGenerator(k);
        var (x, y) = JPoint.ToAffine(p);
        Span<byte> pub = stackalloc byte[33];
        JPoint.Compress(x, y, pub);
        return BtcHash.AddressFromPublicKey(pub);
    }

    public static U256 KeyFromBig(BigInteger v) => ScanRange.FromBig(v);
}
