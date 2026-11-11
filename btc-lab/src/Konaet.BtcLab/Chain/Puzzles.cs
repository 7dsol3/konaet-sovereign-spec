using System.Numerics;
using System.Text.Json;
using Konaet.BtcLab.Core;
using Konaet.BtcLab.Solver;

namespace Konaet.BtcLab.Chain;

public sealed record PuzzleEntry(int N, string Address, string Status, long FundedSats, long SpentSats, int UtxoCount);

/// <summary>
/// The published Bitcoin Puzzle Transaction list (puzzle #1..#100), loaded from
/// data/puzzle_addresses.json. This file is the allowlist that the scanner is
/// restricted to. Guardrails.ValidateTarget() refuses anything not in it.
/// </summary>
public sealed class PuzzleRegistry
{
    private readonly Dictionary<int, PuzzleEntry> _byNumber = new();
    private readonly Dictionary<string, PuzzleEntry> _byAddress = new();

    public string Source { get; private set; } = "(not loaded)";
    public string FetchedAt { get; private set; } = "(not loaded)";
    public IReadOnlyCollection<PuzzleEntry> Puzzles => _byNumber.Values;

    public static PuzzleRegistry Load(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"puzzle registry not found at {path}. It must contain the published puzzle addresses.");

        var reg = new PuzzleRegistry();
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var root = doc.RootElement;
        reg.Source = root.TryGetProperty("source", out var s) ? s.GetString() ?? "?" : "?";
        reg.FetchedAt = root.TryGetProperty("fetchedAt", out var f) ? f.GetString() ?? "?" : "?";

        foreach (var p in root.GetProperty("puzzles").EnumerateArray())
        {
            var n = p.GetProperty("n").GetInt32();
            var addr = p.GetProperty("address").GetString()!;
            var status = p.TryGetProperty("status", out var st) ? st.GetString() ?? "unknown" : "unknown";
            long funded = 0, spent = 0;
            int utxos = 0;
            if (p.TryGetProperty("chain", out var c))
            {
                funded = c.TryGetProperty("fundedSats", out var a) ? a.GetInt64() : 0;
                spent = c.TryGetProperty("spentSats", out var b) ? b.GetInt64() : 0;
                utxos = c.TryGetProperty("utxoCount", out var u) ? u.GetInt32() : 0;
            }
            var e = new PuzzleEntry(n, addr, status, funded, spent, utxos);
            reg._byNumber[n] = e;
            reg._byAddress[addr] = e;
        }
        return reg;
    }

    public bool TryGet(int n, out PuzzleEntry entry) => _byNumber.TryGetValue(n, out entry!);

    public bool IsPublished(string address) => _byAddress.ContainsKey(address);

    /// <summary>Build the scan target set from published entries (P2PKH only, which is what the puzzle uses).</summary>
    public TargetSet BuildTargetSet(IEnumerable<int>? only = null)
    {
        var set = new TargetSet();
        foreach (var e in _byNumber.Values.OrderBy(e => e.N))
        {
            if (only is not null && !only.Contains(e.N)) continue;
            try { set.Add(TargetSet.FromAddress(e.Address, $"puzzle #{e.N} ({e.Status})", e.N)); }
            catch (FormatException) { /* non-P2PKH entry, skip */ }
        }
        return set;
    }

    /// <summary>
    /// Interval for puzzle n: keys in [2^(n-1), 2^n) for n &gt; 1, and [1, 2) for n = 1.
    /// </summary>
    public static ScanRange RangeFor(int n)
    {
        if (n < 1 || n > 100) throw new ArgumentOutOfRangeException(nameof(n), "the published puzzle series is #1..#100");
        if (n == 1) return new ScanRange(new U256(1, 0, 0, 0), new U256(2, 0, 0, 0));
        var lo = BigInteger.One << (n - 1);
        var hi = BigInteger.One << n;
        return new ScanRange(KeyHunter.KeyFromBig(lo), KeyHunter.KeyFromBig(hi));
    }

    /// <summary>
    /// Refuses to build a scan whose target set contains an address that is not a
    /// published puzzle entry. Finding a random private key that happens to control
    /// somebody's wallet is not a puzzle solution, it is theft; this tool only plays
    /// the games whose authors put up the prize.
    /// </summary>
    public void AssertAllowedTargetSet(TargetSet set)
    {
        foreach (var t in set.Targets)
        {
            var known = t.Puzzle > 0 && _byNumber.TryGetValue(t.Puzzle, out var e)
                && BtcHash.Base58CheckEncode(0x00, t.Hash160) == e.Address;
            if (known) continue;
            throw new UnauthorizedAccessException(
                $"recusando varrer: '{t.Label}' não é um endereço de puzzle publicado na lista oficial. " +
                "Procurar chaves de carteiras de terceiros não é desafio, é roubo.");
        }
    }
}

/// <summary>
/// Feasibility arithmetic. Everything here is a formula plus a measured input, so
/// you can recompute the numbers yourself with your own hardware instead of taking
/// anyone's word for it (including ours).
/// </summary>
public static class Feasibility
{
    /// <summary>Keys in the interval of puzzle n.</summary>
    public static double Keyspace(int n) => n == 1 ? 1 : Math.Pow(2, n - 1);

    /// <summary>Wall-clock seconds for exhaustive search at the measured aggregate rate.</summary>
    public static double BruteForceSeconds(int n, double keysPerSecond) => Keyspace(n) / keysPerSecond;

    /// <summary>
    /// Pollard's Kangaroo / lambda: expected group operations to solve ECDLP in an
    /// interval of size N is about 2*sqrt(N). Each kangaroo step costs a generic point
    /// addition (no generator shortcut, plus table/distinguished-point work), so the
    /// honest comparison is against measured generic-add throughput, not hash rate.
    /// </summary>
    public static double KangarooOps(int n) => 2.0 * Math.Sqrt(Keyspace(n));

    public static double KangarooSeconds(int n, double genericAddsPerSecond, double stepOverhead = 3.0) =>
        KangarooOps(n) * stepOverhead / genericAddsPerSecond;

    /// <summary>
    /// Pollard rho com pontos distinguidos (Pollard 1978; van Oorschot &amp; Wiener,
    /// J. Cryptology 12, 1-28, 1999): ~sqrt(pi*ordem/2) = 1,253*sqrt(ordem) somas
    /// de ponto para o ECDLP em um grupo de ordem ~2^bits. Para o grupo inteiro (chave de
    /// 256 bits) é o MELHOR ataque genérico conhecido - não existe "engenharia reversa" que
    /// faça melhor enquanto a implementação não tiver falha de entropia.
    /// </summary>
    public static double RhoOps(int bits) => Math.Sqrt(Math.PI / 2.0 * Math.Pow(2, bits));

    public static double RhoSeconds(int bits, double genericAddsPerSecond, double stepOverhead = 3.0) =>
        RhoOps(bits) * stepOverhead / genericAddsPerSecond;

    /// <summary>
    /// O mesmo piso em ANOS para uma máquina hipotética. Existe por um motivo prático: a
    /// resposta "não dá" sem número é adjetivo, e adjetivo não sustenta uma linha vermelha.
    /// </summary>
    public static double RhoYears(int bits, double genericAddsPerSecond, double stepOverhead = 3.0) =>
        RhoSeconds(bits, genericAddsPerSecond, stepOverhead) / (86400 * 365.25);

    public static string HumanTime(double seconds)
    {
        if (seconds < 1) return $"{seconds * 1000:N1} ms";
        if (seconds < 60) return $"{seconds:N1} s";
        if (seconds < 3600) return $"{seconds / 60:N1} min";
        if (seconds < 86400) return $"{seconds / 3600:N1} h";
        if (seconds < 86400 * 365) return $"{seconds / 86400:N1} dias";
        double years = seconds / (86400 * 365.25);
        if (years < 1e6) return $"{years:N1} anos";
        return $"{years:E2} anos";
    }

    public static string HumanCount(double v)
    {
        if (v < 1e3) return $"{v:N0}";
        if (v < 1e6) return $"{v / 1e3:N1} mil";
        if (v < 1e9) return $"{v / 1e6:N1} MM";
        if (v < 1e12) return $"{v / 1e9:N1} Bi";
        return $"{v:E3}";
    }
}
