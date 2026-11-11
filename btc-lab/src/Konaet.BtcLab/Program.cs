using System.Diagnostics;
using System.Numerics;
using Konaet.BtcLab.Chain;
using Konaet.BtcLab.Core;
using Konaet.BtcLab.Solver;

// Konaet BTC Lab. Leitura de chain pública + busca de chave restrita a puzzles publicados.
// Não constrói, não assina e não transmite transação - em lugar nenhum do projeto.

// Sem isto, redirecionar a saída para docs/*.txt grava no codepage OEM do Windows e
// todo acento vira "?" no arquivo. UTF-8 sem BOM, sempre.
try { Console.OutputEncoding = new System.Text.UTF8Encoding(false); } catch { }

var opts = ParseOptions(args.Skip(1));
string cmd = args.Length > 0 ? args[0].ToLowerInvariant() : "help";

string labRoot = FindLabRoot();
string registryPath = opts.TryGetValue("registry", out var rp) ? rp : Path.Combine(labRoot, "data", "puzzle_addresses.json");
int batchSize = opts.TryGetValue("batch", out var bso) ? OptInt(bso) : 4096;

switch (cmd)
{
    case "selftest": await SelfTest(); break;
    case "dbg": DbgCurve(); break;
    case "address": PrintAddress(opts); break;
    case "public-address":
        if (!opts.TryGetValue("public-key", out var publicKeyHex)) throw new ArgumentException("--public-key required");
        var publicKeyBytes = Convert.FromHexString(publicKeyHex);
        if (publicKeyBytes.Length != 33 || publicKeyBytes[0] is not (2 or 3))
            throw new ArgumentException("compressed secp256k1 public key required");
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new {
            network = "bitcoin-mainnet", address = BtcHash.AddressFromPublicKey(publicKeyBytes)
        }));
        break;
    case "bench": Bench(opts); break;
    case "solve": Solve(opts); break;
    case "solve-chunk": SolveChunk(opts); break;
    case "roundtrip": Roundtrip(opts); break;
    case "puzzles": await Puzzles(opts); break;
    case "dormant": await Dormant(opts); break;
    case "moves": await Moves(opts); break;
    case "stack": await Stack(opts); break;
    case "probe": await Probe(opts); break;
    case "audit": Konaet.BtcLab.Audit.BinaryAudit.Run(opts); break;
    default: Help(); break;
}

// Diagnóstico de curva: cada primitivo tem que produzir um ponto que satisfaça
// Y^2 = X^3 + 7*Z^6 (a equação do projeto em coords Jacobianas).
void DbgCurve()
{
    BigInteger Pb = U256.P.ToBig(), seven = 7;
    string OnCurve(in U256 x, in U256 y) =>
        BigInteger.ModPow(y.ToBig(), 2, Pb) == (BigInteger.ModPow(x.ToBig(), 3, Pb) + seven) % Pb ? "na curva" : "FORA da curva";
    string Proj(JPoint j)
    {
        var z6 = U256.PowMod(j.Z, new U256(6, 0, 0, 0));
        var lhs = U256.SqrMod(j.Y);
        var rhs = U256.AddMod(U256.MulMod(U256.SqrMod(j.X), j.X), U256.MulMod(new U256(7, 0, 0, 0), z6));
        return lhs == rhs ? "na curva" : "FORA da curva";
    }
    void Line(string what, JPoint j)
    {
        if (j.IsInfinity) { Console.WriteLine($"  {what,-22} infinito"); return; }
        var (x, y) = JPoint.ToAffine(j);
        Console.WriteLine($"  {what,-22} x={x.ToHex()[..24]}..  {OnCurve(x, y)}  [jac: {Proj(j)}]");
    }

    Console.WriteLine("2*G por caminhos diferentes:");
    Line("AddG(G)", JPoint.AddG(JPoint.G));
    Line("Double(G)", JPoint.Double(JPoint.G));
    Line("Add(G,G)", JPoint.Add(JPoint.G, JPoint.G));
    Line("Mul(G,2)", JPoint.Mul(JPoint.G, new U256(2, 0, 0, 0)));
    var rp = Ref.MulGenerator(2)!.Value;
    Console.WriteLine($"  {"Ref (BigInteger)":,-22} x={Ref.ToU256(rp.x).ToHex()[..24]}..  {OnCurve(Ref.ToU256(rp.x), Ref.ToU256(rp.y))}");

    Console.WriteLine("3*G por caminhos diferentes:");
    Line("AddG(AddG(G))", JPoint.AddG(JPoint.AddG(JPoint.G)));
    Line("Add(Double(G),G)", JPoint.Add(JPoint.Double(JPoint.G), JPoint.G));
    Line("Mul(G,3)", JPoint.Mul(JPoint.G, new U256(3, 0, 0, 0)));
    var r3 = Ref.MulGenerator(3)!.Value;
    Console.WriteLine($"  {"Ref (BigInteger)":,-22} x={Ref.ToU256(r3.x).ToHex()[..24]}..  {OnCurve(Ref.ToU256(r3.x), Ref.ToU256(r3.y))}");

    Console.WriteLine("Bit() e ToAffine:");
    Console.WriteLine($"  Bit(2,0)={U256.Bit(new U256(2, 0, 0, 0), 0)} Bit(2,1)={U256.Bit(new U256(2, 0, 0, 0), 1)} Bit(2,64)={U256.Bit(new U256(2, 0, 0, 0), 64)}");
    var gAff = JPoint.ToAffine(JPoint.G);
    Console.WriteLine($"  ToAffine(G) = ({gAff.x.ToHex()[..16]}.., {gAff.y.ToHex()[..16]}..)  esperado x=79be667e.. y=483ada77..");
}

// ---------------------------------------------------------------- help

static void Help()
{
    Console.WriteLine("""
        Konaet BTC Lab - laboratório de curva elíptica + leitura da chain pública

          selftest                 valida campo/curva/hash/base58 e resolve um autodesafio
          dbg                      tabela de pontos 2G/3G por 5 caminhos de código (debug de curva)
          address --key <hex|dec>  chave privada -> endereço P2PKH (para conferir contas alheias)
          bench [--seconds N]      mede chaves/s e somas de ponto/s AQUI + tabela de viabilidade
          solve --puzzle N         varre o intervalo do puzzle oficial #N  [--seconds S] [--jobs J]
          roundtrip --bits N       esconde uma chave sua em 2^N e caça ela de volta
          puzzles [--live]         status on-chain dos puzzles (lista + saldo real)  [--spot N]
          dormant [--find N]       caça recompensas antigas ainda intactas: o que a chain prova
                                   [--max M] blocos, [--from H], [--stride S], [--all],
                                   [--per-block N] saídas por bloco com --all (default 40),
                                   [--per-tx N] saídas por transação (default 2),
                                   [--min-age ANOS], [--par P] blocos em voo, [--retry N]
                                   tentativas por bloco, [--delay S] piso de 1 pedido
          moves [--from N --to M]  datas on-chain de entrada/saída dos prêmios dos puzzles (63..70)
          stack  [--from N --to M] de onde veio o saldo de cada puzzle aberto: UTXOs agrupados
                                   por data, em camadas. [--dust S] omite da linha o que estiver
                                   abaixo de S sats; [--delay S] piso global de 1 pedido
          probe [--n N] [--every S] [--fresh]
                                   A/B do NOSSO cliente HTTP no endpoint público: keep-alive
                                   vs uma conexão nova por pedido, com latência e contabilidade
          audit [--exe <arquivo>] [--surface N] [--attrs]
                                   engenharia reversa do ARTEFATO: parseia o PE e o metadata
                                   ECMA-335 do dll compilado (sem carrega-lo nem executa-lo) e
                                   lista todo membro externo que o código pode chamar. A linha
                                   vermelha deixa de ser promessa de fonte e vira 0 linhas no
                                   MemberRef. --exe aponta para o binário de OUTRA pessoa, antes
                                   de você roda-lo; sem --exe, audita a si mesmo.

        Opções que valem para varredura: --jobs N (threads), --batch N (chaves por inversão
        modular; 512..8192 é a faixa que vale a pena testar na sua máquina), --seconds S.

        Ritmo de rede: --delay é um piso GLOBAL (1 pedido a cada N segundos, não por worker) e
        429/5xx/timeout têm backoff de 2s/4s/8s. --par P faz P blocos em voo sem aumentar o
        ritmo; é o servidor que decide a velocidade, e a linha de progresso mostra GETs, retries
        e 429 para você conferir isso em vez de confiar na palavra do README.

        Guardrail: o scanner só aceita alvos que estejam em data/puzzle_addresses.json (a lista
        pública dos 100 puzzles). Endereço que não é puzzle publicado = varredura recusada.
        """);
    Console.WriteLine();
    Console.WriteLine("        E o chão do projeto, que nenhuma bandeira muda: este lab LÊ chain pública e caça");
    Console.WriteLine("        chave DENTRO de intervalo publicado. Recuperar chave de endereço que não está na");
    Console.WriteLine("        lista não é 'modo avançado' nem falta de engenharia reversa - é a conta de rho");
    Console.WriteLine("        para o grupo inteiro: sqrt(pi/2 * 2^256) = 4,26e38 somas de ponto (2^128,33),");
    Console.WriteLine("        que `bench` converte em anos com a taxa medida AQUI. Refaça com a sua taxa:");
    Console.WriteLine("        awk -v rate=<somas/s> -f tools/ecdlp_floor.awk. Auditamos o binário (`audit`)");
    Console.WriteLine("        porque prova é olhar o artefato; não quebramos secp256k1 porque aritmética não");
    Console.WriteLine("        tem modo - e engenharia reversa de dll mostra o que ele chama, não a chave de");
    Console.WriteLine("        ninguém. O que quebra chave na vida real é falha de implementação (k repetido,");
    Console.WriteLine("        entropia ruim), e essa se procura on-chain, em assinatura que já é pública.");
}

static string Short(string s, int n = 88) => s.Length <= n ? s : s[..n].TrimEnd() + "...";

// `--delay 0.5` numa máquina em pt-BR virava "5,00s": aqui "." é separador de milhar,
// então double.Parse("0.5") lê "05". Toda opção numérica passa por estes helpers -
// invariant culture na entrada (aceita '.' e ','), locale da máquina na saída formatada.
static double OptD(string s) => double.Parse(s.Trim().Replace(',', '.'), System.Globalization.CultureInfo.InvariantCulture);
static long OptLong(string s) => long.Parse(s.Trim().Replace(",", ""), System.Globalization.CultureInfo.InvariantCulture);
static int OptInt(string s) => checked((int)OptLong(s));

static Dictionary<string, string> ParseOptions(IEnumerable<string> rest)
{
    var list = rest.ToList();
    var d = new Dictionary<string, string>();
    for (int i = 0; i < list.Count; i++)
    {
        if (!list[i].StartsWith("--")) continue;
        string key = list[i][2..];
        if (i + 1 < list.Count && !list[i + 1].StartsWith("--")) { d[key] = list[i + 1]; i++; }
        else d[key] = "true";
    }
    return d;
}

static string FindLabRoot()
{
    // Prefer the lab root that actually holds the registry; otherwise the "btc-lab" folder
    // we are nested in; otherwise wherever the process was started.
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    for (int i = 0; i < 12 && dir is not null; i++, dir = dir.Parent)
    {
        if (File.Exists(Path.Combine(dir.FullName, "data", "puzzle_addresses.json"))) return dir.FullName;
        if (string.Equals(dir.Name, "btc-lab", System.StringComparison.OrdinalIgnoreCase)) return dir.FullName;
    }
    return Directory.GetCurrentDirectory();
}

// ---------------------------------------------------------------- selftest

async Task SelfTest()
{
    int pass = 0, fail = 0;
    void Check(string name, bool ok, string detail = "")
    {
        Console.WriteLine($"  {(ok ? "ok    " : "FALHOU")}  {name}{(detail.Length > 0 ? "   -> " + detail : "")}");
        if (ok) pass++; else fail++;
    }

    Console.WriteLine("[1] campo: caminho rápido (limbs + redução p = 2^256-2^32-977) vs referência BigInteger");
    var rng = new Random(12345);
    // parse como SEM SINAL: BigInteger.Parse(text, HexNumber) lê o F inicial como negativo,
    // o que fazia a "referência" comparar contra um p falso e acusar tudo como divergente.
    BigInteger P = new(Convert.FromHexString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
        isUnsigned: true, isBigEndian: true);
    int badMul = 0, badAdd = 0, badSub = 0, badInv = 0;
    string firstBad = "";
    for (int i = 0; i < 3000; i++)
    {
        var a = RandU256(rng); var b = RandU256(rng);
        if (U256.MulMod(a, b).ToBig() != a.ToBig() * b.ToBig() % P) { if (badMul++ == 0) firstBad = $"mul a={a.ToHex()} b={b.ToHex()}"; }
        if (U256.AddMod(a, b).ToBig() != (a.ToBig() + b.ToBig()) % P) { if (badAdd++ == 0) firstBad = $"add a={a.ToHex()} b={b.ToHex()}"; }
        if (U256.SubMod(a, b).ToBig() != ((a.ToBig() - b.ToBig()) % P + P) % P) { if (badSub++ == 0) firstBad = $"sub a={a.ToHex()} b={b.ToHex()}"; }
        if (U256.MulMod(a, U256.InvMod(a)).ToBig() != 1) { if (badInv++ == 0) firstBad = $"inv a={a.ToHex()}"; }
    }
    Console.WriteLine($"        mul={badMul} add={badAdd} sub={badSub} inv={badInv}  primeiro problema: {firstBad}");
    Check("3000 vetores aleatórios: mul / add / sub / inverso", badMul + badAdd + badSub + badInv == 0);

    Console.WriteLine("[1b] parâmetros da curva, checados contra a definição (SEC2 2.7.1 / bitcoin-core)");
    {
        var gx = U256.Gx.ToBig(); var gy = U256.Gy.ToBig(); var seven = new BigInteger(7);
        Check("Gy^2 = Gx^3 + 7 (mod p)  -> p, Gx, Gy e b são coerentes",
            BigInteger.ModPow(gy, 2, P) == (BigInteger.ModPow(gx, 3, P) + seven) % P,
            $"Gx={U256.Gx.ToHex()}");
        Check("n*G = infinito (ordem do grupo confere)", JPoint.MulGenerator(U256.N).IsInfinity);
        var nPlus1 = JPoint.ToAffine(JPoint.MulGenerator(U256.AddRaw(U256.N, U256.One, out _)));
        Check("(n+1)*G = G (a aritmética respeita a ordem)", nPlus1.x == U256.Gx && nPlus1.y == U256.Gy, nPlus1.x.ToHex());
        int offCurve = 0;
        foreach (int k in new[] { 1, 2, 3, 5, 8, 13, 123_456_789, 987_654_321 })
        {
            var (x, y) = JPoint.ToAffine(JPoint.MulGenerator(ScanRange.FromBig(k)));
            if (BigInteger.ModPow(y.ToBig(), 2, P) != (BigInteger.ModPow(x.ToBig(), 3, P) + seven) % P) offCurve++;
        }
        Check("8 pontos k*G satisfazem a equação da curva", offCurve == 0, $"{offCurve} fora da curva");
    }

    Console.WriteLine("[2] curva: k*G do caminho rápido vs referência ingênua");
    int bad = 0;
    foreach (int k in new[] { 1, 2, 3, 7, 255, 65537, 123_456_789 })
    {
        var (fx, fy) = JPoint.ToAffine(JPoint.MulGenerator(ScanRange.FromBig(k)));
        var rp = Ref.MulGenerator(k) ?? throw new Exception("referência devolveu infinito");
        if (fx != Ref.ToU256(rp.x) || fy != Ref.ToU256(rp.y)) bad++;
    }
    Check("7 escalares conferem ponto a ponto", bad == 0, $"{bad} divergências");

    Console.WriteLine("[3] laço do scanner: P += G incremental + inversão em massa (Montgomery)");
    var xs = new U256[64]; var ys = new U256[64]; var zs = new U256[64]; var pre = new U256[64];
    var p = JPoint.MulGenerator(new U256(1000, 0, 0, 0));
    for (int i = 0; i < 64; i++) { xs[i] = p.X; ys[i] = p.Y; zs[i] = p.Z; p = JPoint.AddG(p); }
    JPoint.BatchToAffine(xs, ys, zs, 64, pre);
    int badBatch = 0;
    for (int i = 0; i < 64; i++)
    {
        var rp = Ref.MulGenerator(1000 + i)!.Value;
        if (xs[i] != Ref.ToU256(rp.x) || ys[i] != Ref.ToU256(rp.y)) badBatch++;
    }
    Check("64 chaves consecutivas viram os pontos certos", badBatch == 0, $"{badBatch} divergências");

    Console.WriteLine("[4] RIPEMD-160 + Base58Check   (valores abaixo conferidos com `openssl dgst -ripemd160`)");
    Check("ripemd160(\"\")", Hex(BtcHash.Ripemd160(Array.Empty<byte>())) == "9c1185a5c5e9fc54612808977ee8f548b2258d31",
        Hex(BtcHash.Ripemd160(Array.Empty<byte>())));
    Check("ripemd160(\"a\")", Hex(BtcHash.Ripemd160("a"u8)) == "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
        Hex(BtcHash.Ripemd160("a"u8)));
    Check("ripemd160(\"abc\")", Hex(BtcHash.Ripemd160("abc"u8)) == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
        Hex(BtcHash.Ripemd160("abc"u8)));
    Check("ripemd160(\"message digest\")",
        Hex(BtcHash.Ripemd160("message digest"u8)) == "5d0689ef49d2fae572b881b123a85ffa21595f36",
        Hex(BtcHash.Ripemd160("message digest"u8)));
    Check("ripemd160(\"abcdefghijklmnopqrstuvwxyz\")",
        Hex(BtcHash.Ripemd160("abcdefghijklmnopqrstuvwxyz"u8)) == "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
        Hex(BtcHash.Ripemd160("abcdefghijklmnopqrstuvwxyz"u8)));

    // KAT gerado por `openssl dgst -ripemd160` sobre entradas aleatórias de 0 a 1000 bytes:
    // cobre o padding nas fronteiras de bloco (55/56, 63/64/65, 127/128/129) e multi-bloco.
    var katPath = Path.Combine(labRoot, "tests", "ripemd160_kat.txt");
    if (File.Exists(katPath))
    {
        int katTotal = 0, katBad = 0;
        foreach (var line in File.ReadLines(katPath))
        {
            var parts = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2) continue;
            katTotal++;
            var input = Convert.FromHexString(parts[0]);
            if (Hex(BtcHash.Ripemd160(input)) != parts[1]) katBad++;
        }
        Check($"KAT openssl: {katTotal} vetores (0..1000 bytes)", katBad == 0, $"{katBad} divergências");
    }
    else Check("KAT openssl encontrado", false, katPath);
    var h = BtcHash.Hash160("abc"u8);
    var enc = BtcHash.Base58CheckEncode(0x00, h);
    var dec = BtcHash.Base58CheckDecode(enc);
    Check("base58check ida e volta + checksum", dec.version == 0 && dec.payload.SequenceEqual(h), enc);

    Console.WriteLine("[5] prova de fogo: a chave 1 produz o endereço histórico do puzzle #1?");
    var addr1 = KeyHunter.DeriveAddress(new U256(1, 0, 0, 0));
    Console.WriteLine($"        address(1) = {addr1}");
    // 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH = saída #1 da transação-puzzle. Está na chain:
    // recebeu 25.034.358 sat e foi 100% gasta, ou seja, a chave privada 1 é pública e conhecida.
    Check("casa com a saída #1 da tx-puzzle (vista na chain)", addr1 == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", addr1);
    if (File.Exists(registryPath))
    {
        var reg0 = PuzzleRegistry.Load(registryPath);
        Check("chave 1 -> endereço do puzzle #1 do registro",
            reg0.TryGet(1, out var e1) && e1.Address == addr1, e1?.Address ?? "?");

        // Varredura EXAUSTIVA real dos puzzles baixos: nenhumas chaves "chupadas" da lista,
        // o scanner acha a chave sozinho e o endereço bate com o que está na blockchain.
        var low = Enumerable.Range(1, 12).ToArray();
        var setLow = reg0.BuildTargetSet(low);
        reg0.AssertAllowedTargetSet(setLow);
        int solved = 0;
        var foundKeys = new List<string>();
        foreach (int n in low)
        {
            var r = PuzzleRegistry.RangeFor(n);
            var onlyOne = reg0.BuildTargetSet(new[] { n });
            var hit = new KeyHunter(onlyOne, batchSize).Hunt(r, 4, TimeSpan.FromSeconds(30));
            if (hit.Found) { solved++; foundKeys.Add($"#{n}=0x{hit.PrivateKey.ToHex()}"); }
        }
        Check("resolvemos 12 puzzles publicados varrendo o intervalo deles", solved == low.Length,
            $"{solved}/{low.Length}  " + string.Join(" ", foundKeys));

        // o guardrail: alvo que não é puzzle publicado tem que ser recusado, e alvo legítimo aceito
        var rogue = new TargetSet();
        rogue.Add(new Target(BtcHash.Hash160("carteira de terceiro"u8), "saldo de outra pessoa", 0));
        bool refused = false;
        try { reg0.AssertAllowedTargetSet(rogue); }
        catch (UnauthorizedAccessException) { refused = true; }
        bool accepted = true;
        try { reg0.AssertAllowedTargetSet(setLow); } catch { accepted = false; }
        Check("guardrail: recusa alvo não publicado, aceita alvo publicado", refused && accepted,
            $"recusou={refused} aceitou={accepted}");
    }
    else Check("registro de puzzles encontrado", false, registryPath);

    Console.WriteLine("[6] autodesafio: crio uma chave em 2^22, uso só o endereço dela, e caço a chave");
    var kit = RoundtripKit.Make(22, 100_000);
    var res = new KeyHunter(kit.Set, batchSize).Hunt(kit.Range, Environment.ProcessorCount, TimeSpan.FromSeconds(60));
    Check("scanner recuperou exatamente a chave escondida", res.Found && res.PrivateKey == kit.ExpectedKey,
        res.Report());

    // [7] validação em largura de bits: chaves de 104/109/114 bits publicadas por terceiros
    // (JeanLucPons/Kangaroo, puzzle32.txt - coletado 2026-11-08) têm que reproduzir a pubkey
    // comprimida e o endereço que aquele arquivo anuncia. Não é autodesafio: é dado externo,
    // e por isso pega erro de campo/curva/hash que um teste circular deixaria passar.
    Console.WriteLine("[7] chaves publicadas de 104/109/114 bits (puzzle #105/#110/#115) -> endereço");
    (string Key, string Pub, string Addr, string Tag)[] published =
    {
        ("0x16F14FC2054CD87EE6396B33DF3",
         "03bcf7ce887ffca5e62c9cabbdb7ffa71dc183c52c04ff4ee5ee82e0c55c39d77b",
         "1CMjscKB3QW7SDyQ4c3C3DEUHiHRhiZVib", "#105"),
        ("0x35C0D7234DF7DEB0F20CF7062444",
         "0309976ba5570966bf889196b7fdf5a0f9a1e9ab340556ec29f8bb60599616167d",
         "12JzYkkN76xkwvcPT6AWKZtGX6w2LAgsJg", "#110"),
        ("0x60F4D11574F5DEEE49961D9609AC6",
         "0248d313b0398d4923cdca73b8cfa6532b91b96703902fc8b32fd438a3b7cd7f55",
         "1NLbHuJebVwUZ1XqDjsAyfTRUPwDQbemfv", "#115"),
    };
    int pubOk = 0, addrOk = 0;
    foreach (var (hexKey, wantPub, wantAddr, tag) in published)
    {
        var kk = U256.FromHex(hexKey);
        var aff = JPoint.ToAffine(JPoint.MulGenerator(kk));
        byte[] pub = new byte[33];                 // Span/stackalloc não vivem em método async
        JPoint.Compress(aff.x, aff.y, pub);
        if (Convert.ToHexString(pub).ToLowerInvariant() == wantPub) pubOk++;
        if (BtcHash.AddressFromPublicKey(pub) == wantAddr) addrOk++;
        else Console.WriteLine($"        {tag}: endereço calculado != publicado");
    }
    Check($"pubkey comprimida bate com a publicada ({published.Length} chaves de 104-114 bits)",
        pubOk == published.Length, $"{pubOk}/{published.Length}");
    Check("endereço Base58Check bate com o publicado (e com o pipeline do scanner)",
        addrOk == published.Length, $"{addrOk}/{published.Length}");

    // [8] O predicado que decide "esta saída está na lista" - a matéria-prima do veredito do
    // dormant. As duas fixtures abaixo são o UTXO real do puzzle #71 (tx 5d45587c..., vout 19, bloco
    // 475240) copiado da resposta de address/.../utxo. O teste não fala com a rede: ele prova
    // que a comparação aceita a forma que o servidor usa, recusa vout errado e recusa txid
    // errado. Se um dia o endpoint responder em maiúsculo, ou se alguém trocar o
    // OrdinalIgnoreCase por ==, aqui aparece - e não dez páginas depois, com "0 intactas"
    // escrito onde o certo seria "não deu para conferir".
    Console.WriteLine("[8] predicado de UTXO (o que decide parado != movido)");
    var fixture = new List<Konaet.BtcLab.Chain.Utxo>
    {
        new("5d45587cfd1d5b0fb826805541da7d94c61fe432259e68ee26f4a04544384164", 19, 63900000, 475240, 1499749253),
        new("08389f34c98c606322740c0be6a7125d9860bb8d5cb182c02f98461e5fa6cd15", 70, 7100000, 339085, 1421345234),
    };
    Check("outpoint real do #71 é reconhecido como está no lugar",
        UtxoSet.Contains(fixture, "5d45587cfd1d5b0fb826805541da7d94c61fe432259e68ee26f4a04544384164", 19));
    Check("mesmo txid em MAIÚSCULO ainda bate (comparação não sensível a caixa)",
        UtxoSet.Contains(fixture, "5D45587CFD1D5B0FB826805541DA7D94C61FE432259E68EE26F4A04544384164", 19));
    Check("vout errado no mesmo txid = não está no lugar",
        !UtxoSet.Contains(fixture, "5d45587cfd1d5b0fb826805541da7d94c61fe432259e68ee26f4a04544384164", 18));
    Check("txid que não é da lista = não está no lugar",
        !UtxoSet.Contains(fixture, "0000000000000000000000000000000000000000000000000000000000000001", 19));
    Check("txid vazio não vira 'está no lugar' por acidente",
        !UtxoSet.Contains(fixture, "", 19) && !UtxoSet.Contains(fixture, null!, 19));

    // [9] A régua do veredito de três estados. Foi a ausência dela que produziu
    // "0 intactas em 180 coinbases": um P2PK ausente da lista virava "já foi movida".
    // Fixture real: o coinbase do bloco 33 (tx bdeaa008..., vout 0, 50 BTC) - scriptpubkey_type
    // "p2pk" e NENHUM scriptpubkey_address na resposta. O endereço 1MKRkcXG... abaixo é o que o
    // NOSSO decoder tira do script cru; ele existe no índice do endpoint (address/1MKRkcXG...
    // responde 200 com 9 saídas de poeira de 2019, spent_txo_count 0), mas o coinbase de 2009 não
    // está lá - porque o índice dele não cobre P2PK, não porque a moeda tenha se movido.
    Console.WriteLine("[9] veredito de três estados + decoder de P2PK contra dados reais");
    Check("presente na lista = Intacta, com ou sem índice cobrindo o tipo",
        UtxoSet.Verdict(true, true) == Spentness.Intacta && UtxoSet.Verdict(true, false) == Spentness.Intacta);
    Check("ausente em tipo QUE O ENDPOINT INDEXA = Gasta (aqui a ausência tem significado)",
        UtxoSet.Verdict(false, true) == Spentness.Gasta);
    Check("ausente em tipo que o endpoint NÃO indexa = NaoConferivel (nunca 'gasta')",
        UtxoSet.Verdict(false, false) == Spentness.NaoConferivel,
        "regressão do bug que chamava buraco de índice de gasto");
    var (pkAddr, pkKind) = Scripts.Decode(
        "4104804d71f6a91c908a973cae7ef4363f7689520116b995d6936328de00be56f92baee0dabf3a240e0ed2dce7f374f12cbba7649808528236cb04c558f028dd61edac");
    Check("P2PK cru do coinbase do bloco 33 vira o endereço publicado dele",
        pkAddr == "1MKRkcXG7cUb83EGNjK5TSHcKgVjVMTou5" && pkKind == "p2pk", pkAddr ?? "null");
    var p2pkOut = new TxOut(pkAddr, 5000000000, 0, "p2pk", ApiAddress: false, Decoded: pkAddr);
    var p2pkhOut = new TxOut("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", 1000, 0, "p2pkh", ApiAddress: true,
        Decoded: "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    Check("TxOut de P2PK sem endereço do endpoint NÃO é oráculo (Indexed=false)", !p2pkOut.Indexed);
    Check("TxOut com endereço do endpoint É oráculo (Indexed=true), e o decoder bate com ele",
        p2pkhOut.Indexed && p2pkhOut.Decoded == p2pkhOut.Address);
    // hash160(G) = 751e76e8...bd6, conferido na seção [de endereço] acima vindo da chave zero;
    // aqui os mesmos bytes entram já embalados num script, e o script tem que devolver o
    // endereço da saída #1 da transação-puzzle - ou seja, o decoder vale para o que a chain usa.
    Check("p2pkh clássico (76a914..88ac) decodifica sem o endpoint",
        Scripts.Decode("76a914751e76e8199196d454941c45d1b3a323f1433bd688ac").Address
            == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");

    // [10] A recusa de lista e o remendo pelos contadores - tudo OFFLINE, com os corpos exatos
    // capturados desta máquina em 2026-11-08 (três HTTP 400 diferentes do MESMO endpoint):
    //   address/1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa/utxo  -> "Too many unspent transaction outputs (>500). Contact support to raise limits."
    //   address/3Eif1JfqeMERRsQHtvGEacNN9hhuvnsfe9/utxo  -> idem (funded 4.929 / spent 266 em address/<a>, que responde 200)
    //   address/zzz/utxo                                 -> "Invalid Bitcoin address"
    // Reconhecer a diferença é a régua: chamar o "Invalid Bitcoin address" de recusa de lista
    // silenciosamente transformaria um erro de entrada em "sem veredito", e chamar a recusa de
    // "gasta" é o erro que já cometemos uma vez.
    Console.WriteLine("[10] recusa de lista (>500 UTXOs) e o veredito por contadores, com os corpos medidos");
    const string Refusal = "Too many unspent transaction outputs (>500). Contact support to raise limits.";
    Check("recognize o corpo medido da recusa (gênesis e 3Eif1J... respondem exatamente isto)",
        Mempool.IsUtxoListRefusal(Refusal));
    Check("NÃO confunde recusa de lista com o outro HTTP 400 medido ('Invalid Bitcoin address')",
        !Mempool.IsUtxoListRefusal("Invalid Bitcoin address"));
    Check("NÃO confunde com o HTTP 400 de índice de tx que não é múltiplo de 25",
        !Mempool.IsUtxoListRefusal("start index must be a multipication of 25"));
    Check("corpo vazio, nulo ou HTML de erro não dispara",
        !Mempool.IsUtxoListRefusal("") && !Mempool.IsUtxoListRefusal(null) &&
        !Mempool.IsUtxoListRefusal("<!DOCTYPE html><html lang=\"en\"><head><title>Error</title>"));
    Check("0 gastos => INTACTA sem precisar da lista (o caso do endereço da gênesis)",
        UtxoSet.VerdictFromCounters(83441, 0, 5770718386, 5000000000) == Spentness.Intacta,
        "83.440 recebidas / 0 gastas, soma 57,70718386 BTC >= 50 BTC do coinbase, tudo medido");
    Check("1 saída na história, e ela gasta => GASTA (a única que existiu aqui foi consumida)",
        UtxoSet.VerdictFromCounters(1, 1, 2509394000, 2509394000) == Spentness.Gasta);
    Check("muitas saídas e gastos parciais => SEM VEREDITO, nunca 'gasta' a nossa em particular",
        UtxoSet.VerdictFromCounters(4929, 266, 1000000000, 1000) == Spentness.NaoConferivel &&
        UtxoSet.VerdictFromCounters(100, 1, 1000000000, 1000) == Spentness.NaoConferivel,
        "regressão: o agregado não identifica QUAL saída saiu");
    Check("endereço sem nada recebido não ganha veredito por acidente",
        UtxoSet.VerdictFromCounters(0, 0, 0, 1000) == Spentness.NaoConferivel &&
        UtxoSet.VerdictFromCounters(0, 5, 0, 1000) == Spentness.NaoConferivel,
        "'spent == 0' sozinho diria 'intacta' de um endereço que nunca existiu no índice");
    // A régua que faltava: o agregado só pode responder pela saída se ele a COMPORTA. Um índice
    // que não contém aquele tipo de script soma outra coisa, e "0 gastos" dele não é sobre nós.
    Check("se funded_txo_sum não comporta o valor da saída, o agregado não está falando dela",
        UtxoSet.VerdictFromCounters(900, 0, 4_000_000_000, 5000000000) == Spentness.NaoConferivel,
        "50 BTC de coinbase numa soma de 40 BTC: o índice não contém esta saída");
    Check("e o corte é na borda exata, não em 1 satoshi de folga",
        UtxoSet.VerdictFromCounters(900, 0, 5000000000, 5000000000) == Spentness.Intacta &&
        UtxoSet.VerdictFromCounters(900, 0, 4999999999, 5000000000) == Spentness.NaoConferivel);

    // [11] O caderno de endereços IP. A pane de 2026-11-08 às 06:31Z não foi o servidor: dos 9 IPs
    // que o DNS de mempool.space devolvia naquela hora, três (…200, …203, …206) não recusavam a
    // conexão, eles ENGOLIAM o SYN, e o ConnectTimeout do framework vale para a operação inteira -
    // os 10s morriam no morto e o vivo nunca era tentado. `curl` funcionava com o mesmo DNS na mesma
    // hora. Na medição seguinte, ~50 min depois, o pool tinha 8 IPs e NENHUM engolia: a paisagem
    // muda, e é por isso que o caderno é por observação, com cooldown, e não uma lista fixa de
    // endereços ruins. O que dá para testar sem rede é a REGRA deste caderno; o que ela conserta é
    // o scan, e isso está em docs/rate-probe.txt.
    Console.WriteLine("[11] caderno de endereços: suspeito vai para o fim da fila, e a fila não perde ninguém");
    var ipGood1 = System.Net.IPAddress.Parse("103.165.192.201");
    var ipDead = System.Net.IPAddress.Parse("103.165.192.200");
    var ipGood2 = System.Net.IPAddress.Parse("103.165.192.202");
    var clock = new List<DateTime> { new(2026, 11, 8, 9, 0, 0, DateTimeKind.Utc) };
    var health = new ConnectHealth(cooldownSeconds: 300, now: () => clock[0]);
    var pool = new[] { ipGood1, ipDead, ipGood2 };
    Check("sem histórico, a ordem do DNS é preservada (nada de embaralhar por gosto)",
        health.Order(pool).SequenceEqual(pool));
    health.MarkSuspect(ipDead);
    Check("endereço marcado como suspeito vai para o FIM, os demais mantêm a ordem",
        health.Order(pool).SequenceEqual(new[] { ipGood1, ipGood2, ipDead }));
    Check("a fila nunca perde endereço: os 3 continuam candidatos (um IP ruim pode sarar)",
        health.Order(pool).Length == 3);
    Check("antes do cooldown ele segue suspeito", health.IsSuspect(ipDead) && !health.IsSuspect(ipGood1));
    clock[0] = clock[0].AddSeconds(301);
    Check("depois do cooldown volta a ser tentado normalmente",
        !health.IsSuspect(ipDead) && health.Order(pool).SequenceEqual(pool));
    health.MarkSuspect(ipGood1);
    health.Clear(ipGood1);
    Check("conectar bem limpa a suspeita (senão um tropeço rebaixa o IP para sempre)",
        !health.IsSuspect(ipGood1));
    Check("o orcamento por endereco e menor que o antigo timeout de operacao inteira",
        Mempool.PerAddressConnectSeconds < 10, $"{Mempool.PerAddressConnectSeconds:F0}s por IP");

    // [12] A linha vermelha lida no BINÁRIO. Fonte não roda; o que roda é o dll compilado, e o
    // ECMA-335 fecha a saída: chamar qualquer coisa fora do módulo exige uma linha na tabela
    // MemberRef. Então "este artefato não referencia primitiva de gasto" é verificável sem
    // executar nada - e no binário de outra pessoa também. As duas linhas de controle abaixo
    // são a razão do bloco existir: sem POSITIVO, 0 violação poderia ser regra morta; sem
    // NEGATIVO, poderia ser regra que pega tudo, inclusive GET.
    Console.WriteLine("[12] auditoria do artefato: a bandeira lida no PE, com os dois controles");
    {
        var own = Konaet.BtcLab.Audit.BinaryAudit.Inspect(typeof(Konaet.BtcLab.Audit.BinaryAudit).Assembly.Location);
        Check("nosso dll: 0 referência proibida, 0 P/Invoke, todos os corpos de IL lidos",
            own.Clean && own.PInvokes.Count == 0 && own.BadBodies == 0,
            $"{own.MemberRefRows} MemberRef, {own.MethodDefs} MethodDef, {own.ILBytes:N0} bytes de IL");
        var foreignPath = Path.Combine(
            System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory(), "System.Net.Http.dll");
        var foreign = File.Exists(foreignPath)
            ? Konaet.BtcLab.Audit.BinaryAudit.Inspect(foreignPath) : null;
        Check("controle POSITIVO: a própria stack de HTTP acusa escrita TLS, então a regra vive",
            foreign is not null && foreign.Forbidden.Count > 0,
            $"{foreign?.Forbidden.Count ?? -1} violação(ões): " +
            string.Join(", ", (foreign?.Forbidden ?? []).Select(h => h.Member).Distinct()));
        var verbo = Konaet.BtcLab.Audit.BinaryAudit.Rules.Single(x => x.Id == "verbo");
        bool nega = !Konaet.BtcLab.Audit.BinaryAudit.Matches(verbo, "System.Net.Http.HttpClient", "GetAsync");
        bool pega = Konaet.BtcLab.Audit.BinaryAudit.Matches(verbo, "System.Net.Http.HttpClient", "PostAsync");
        Check("controle NEGATIVO: GET não casa na regra de verbo que escreve; POST casa", nega && pega,
            $"GetAsync={(nega ? "livre" : "CASADO")}, PostAsync={(pega ? "casado" : "NÃO CASA")}");
    }

    Console.WriteLine();
    Console.WriteLine($"{pass} checks ok, {fail} falhas.");
    if (fail > 0) Environment.ExitCode = 1;
    await Task.CompletedTask;

    static U256 RandU256(Random r)
    {
        var b = new byte[32]; r.NextBytes(b); b[0] = 0;                  // keep well below p
        var v = U256.FromBytes(b);
        return v.IsZero ? U256.One : v;
    }
    static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
}

// ---------------------------------------------------------------- address

void PrintAddress(Dictionary<string, string> opt)
{
    if (!opt.TryGetValue("key", out var keyStr)) { Console.WriteLine("uso: address --key <hex|decimal>"); return; }
    keyStr = keyStr.Trim();
    U256 k = keyStr.All(char.IsDigit)
        ? ScanRange.FromBig(BigInteger.Parse(keyStr))
        : U256.FromHex(keyStr);

    var pt = JPoint.ToAffine(JPoint.MulGenerator(k));
    Span<byte> pub = stackalloc byte[33];
    JPoint.Compress(pt.x, pt.y, pub);
    Console.WriteLine($"chave privada : 0x{k.ToHex()}");
    Console.WriteLine($"public key    : {Convert.ToHexString(pub).ToLowerInvariant()}");
    Console.WriteLine($"endereço      : {BtcHash.AddressFromPublicKey(pub)}");
    Console.WriteLine($"conferência   : {KeyHunter.DeriveAddress(k)} (pipeline do scanner)");
}

// ---------------------------------------------------------------- roundtrip

void Roundtrip(Dictionary<string, string> opt)
{
    int bits = opt.TryGetValue("bits", out var b) ? OptInt(b) : 24;
    int jobs = opt.TryGetValue("jobs", out var j) ? OptInt(j) : Environment.ProcessorCount;
    double secs = opt.TryGetValue("seconds", out var s) ? OptD(s) : 120;

    var kit = RoundtripKit.Make(bits, 1);
    Console.WriteLine($"autodesafio de {bits} bits ({Feasibility.HumanCount(kit.Range.Size)} chaves no intervalo)");
    Console.WriteLine($"  alvo publicado: {KeyHunter.DeriveAddress(kit.ExpectedKey)}");
    Console.WriteLine($"  workers: {jobs}, orçamento: {secs}s");
    var res = new KeyHunter(kit.Set, batchSize).Hunt(kit.Range, jobs, TimeSpan.FromSeconds(secs),
        (keys, t) => Console.WriteLine($"    ... {keys / Math.Max(t, 1e-9) / 1e3:N0} mil chaves/s ({keys:N0} em {t:F1}s)"));
    Console.WriteLine(res.Report());
    Console.WriteLine(res.Found && res.PrivateKey == kit.ExpectedKey
        ? "conferido: a chave caçada é a que foi escondida. Pipeline correto de ponta a ponta."
        : "NÃO ENCONTRADA dentro do orçamento de tempo.");
}

// ---------------------------------------------------------------- bench

double MeasureScanRate(int jobs, double seconds)
{
    var probe = new KeyHunter(new TargetSet(), batchSize).Hunt(
        new ScanRange(new U256(0x1000_0000_0000UL, 0, 0, 0), new U256(0, 1, 0, 0)),
        jobs, TimeSpan.FromSeconds(seconds));
    return probe.KeysPerSecond;
}

void Bench(Dictionary<string, string> opt)
{
    int jobs = Math.Min(opt.TryGetValue("jobs", out var j) ? OptInt(j) : Environment.ProcessorCount, Environment.ProcessorCount);
    double secs = opt.TryGetValue("seconds", out var s) ? OptD(s) : 15;

    Console.WriteLine($"máquina: {Environment.ProcessorCount} CPUs lógicos, .NET {Environment.Version}, {jobs} workers, batch {batchSize}\n");

    // 1) multiplicação modular
    long fieldOps = 0;
    var sp = Stopwatch.StartNew();
    var t1 = new U256(0x1234_5678_9ABC_DEF0UL, 0xFEDC_BA98_7654_3210UL, 0x0BAD_F00D_1357_9BDFUL, 0x2468_ACE0_F1E2_D3C4UL);
    while (sp.Elapsed.TotalSeconds < secs / 3)
    {
        var acc = t1;
        for (int i = 0; i < 50_000; i++) acc = U256.MulMod(acc, t1);
        fieldOps += 50_000;
        GC.KeepAlive(acc);
    }
    double fieldRate = fieldOps / sp.Elapsed.TotalSeconds;

    // 2) soma de ponto genérica (o primitivo do Kangaroo)
    long adds = 0;
    var pa = JPoint.MulGenerator(new U256(0x1234_5678_9ABC_DEF0UL, 0x0F0F_0F0F_1234_5678UL, 0x1357_9BDF_2468_ACE0UL, 0x99));
    var pb = JPoint.MulGenerator(new U256(0xABCD_EF01_2345_6789UL, 0x7654_3210_FEDC_BA98UL, 0x0E1D_2C3B_4A59_6877UL, 0x55));
    sp.Restart();
    while (sp.Elapsed.TotalSeconds < secs / 3)
    {
        for (int i = 0; i < 20_000; i++) { pa = JPoint.Add(pa, pb); pb = JPoint.Double(pb); }
        adds += 40_000;
    }
    double addRate = adds / sp.Elapsed.TotalSeconds;
    Console.WriteLine($"medições nesta máquina ({Feasibility.HumanTime(secs)} de amostragem)");
    Console.WriteLine($"  mult. modulares : {fieldRate / 1e6:N1} MM/s");
    Console.WriteLine($"  soma de ponto   : {addRate / 1e6:N2} MM/s   (Add genérico + Double, sem hash)");

    // 3) pipeline completo de varredura (aquece antes de medir: JIT + GC não entram na conta)
    MeasureScanRate(2, 1.5);
    sp.Restart();
    double keysRate = MeasureScanRate(jobs, secs / 3);
    Console.WriteLine($"  varredura total : {keysRate / 1e3:N1} mil chaves/s  (ponto + affine em lote + hash160, batch {batchSize})");
    Console.WriteLine($"                  = {keysRate / jobs / 1e3:N1} mil/s por worker");

    // escala com o número de workers - measured, not assumed
    var scale = new List<(int jobs, double rate)>();
    foreach (int jj in new[] { 1, 2, 4, 8, jobs }.Distinct().Where(x => x <= Environment.ProcessorCount))
        scale.Add((jj, MeasureScanRate(jj, 1.5)));
    Console.WriteLine($"  escala: " + string.Join("   ", scale.Select(s => $"{s.jobs}w={s.rate / 1e6:F2}M/s")));
    Console.WriteLine();

    Console.WriteLine("as duas contas (troque pelas SUAS taxas medidas e a tabela é a mesma):");
    Console.WriteLine("  busca exaustiva : t = 2^(n-1) / chaves_por_segundo            <- escala 2x por bit");
    Console.WriteLine("  Pollard Kangaroo: ops = 2*sqrt(2^(n-1)), t = ops*overhead/add_rate  <- escala raiz");
    Console.WriteLine();
    Console.WriteLine($"  {"puzzle",7} {"chaves",15} {"exaustivo",17} {"kangaroo",17}");
    Console.WriteLine($"  {new string('-', 58)}");
    foreach (int n in new[] { 40, 50, 60, 66, 70, 71, 80, 100 })
    {
        double keys = Feasibility.Keyspace(n);
        Console.WriteLine($"  {n,7} {Feasibility.HumanCount(keys),15} " +
            $"{Feasibility.HumanTime(Feasibility.BruteForceSeconds(n, keysRate)),17} " +
            $"{Feasibility.HumanTime(Feasibility.KangarooSeconds(n, addRate)),17}");
    }
    Console.WriteLine();
    Console.WriteLine("não tome a tabela como promessa: o Kangaroo real paga memória e passos mais caros");
    Console.WriteLine("que uma soma simples, então a linha 'kangaroo' é um piso, não um orçamento.");
    Console.WriteLine();

    // E o que NÃO está na tabela: chave completa. Os puzzles acima existem porque publicam um
    // INTERVALO (2^(n-1) chaves). Um endereço real de wallet não publica nada: a chave é
    // qualquer coisa em [1, n), e o melhor ataque genérico conhecido é rho com pontos
    // distinguidos, ~sqrt(pi*n/2) somas de ponto. Nada em engenharia reversa muda isso -
    // mudar exige uma falha na IMPLEMENTAÇÃO (entropia, RNG repetido), não no artefato.
    Console.WriteLine("fora da tabela: uma chave COMPLETA de 256 bits (todo endereço seu, todo saldo de exchange)");
    Console.WriteLine($"  ops de rho    ~ sqrt(pi/2 * 2^256) = {Feasibility.RhoOps(256):E2} somas de ponto  (= 2^{Math.Log2(Feasibility.RhoOps(256)):F2})");
    Console.WriteLine($"  nesta máquina : {Feasibility.RhoYears(256, addRate):E2} anos  com as {addRate / 1e6:N2} MM soma/s medidas acima");
    foreach (var (heroic, label) in new[] { (1e12, "1 trilhão de somas/s"), (1e15, "1 quatrilhão de somas/s") })
        Console.WriteLine($"  {label,-22}: {Feasibility.RhoYears(256, heroic):E2} anos  " +
                          $"= {Feasibility.RhoYears(256, heroic) / (1.38e10):E1} vezes a idade do universo (1,38e10 anos)");
    Console.WriteLine("  o que muda a conta é CORTE DE ESPAÇO, não talento: cada bit cortado divide");
    Console.WriteLine("  por ~1,414 (raiz quadrada). O #66 publica 2^65 chaves e por isso fecha em horas;");
    Console.WriteLine("  uma chave completa exige cortar os ~190 bits que faltam, e ninguém publica isso -");
    Console.WriteLine("  publicar o intervalo É o desafio. Sem corte não há ataque: há esta conta.");
    Console.WriteLine();
    // 10^(ordens) = rho(256) / kangaroo(#66), nas DUAS moedas: trabalho e tempo de parede.
    double ops66 = Feasibility.KangarooOps(66);
    Console.WriteLine($"  em números, a diferença entre auditar o artefato e 'quebrar' a curva: o #66 custa");
    Console.WriteLine($"  {ops66:E2} somas ({Feasibility.HumanTime(Feasibility.KangarooSeconds(66, addRate))} aqui); uma chave de 256 bits custa");
    Console.WriteLine($"  {Feasibility.RhoOps(256):E2} ({Feasibility.HumanTime(Feasibility.RhoSeconds(256, addRate))} aqui) - " +
                      $"{Math.Log10(Feasibility.RhoOps(256) / ops66):F1} ordens de magnitude de trabalho, " +
                      $"{Math.Log10(Feasibility.RhoSeconds(256, addRate) / Feasibility.KangarooSeconds(66, addRate)):F1} de tempo.");
    Console.WriteLine();
    Console.WriteLine("  em resumo: `audit` faz engenharia reversa do ARTEFATO e mostra o que ele chama;");
    Console.WriteLine("  engenharia reversa da secp256k1 não mostra a chave de ninguém. Mesma palavra,");
    Console.WriteLine($"  {Math.Log10(Feasibility.RhoSeconds(256, addRate) / Feasibility.KangarooSeconds(66, addRate)):F0} ordens de magnitude de diferença no resultado.");
}

// ---------------------------------------------------------------- solve

void SolveChunk(Dictionary<string, string> opt)
{
    const string publishedRegistrySha256 = "97ad3092f01c37049bf7ef461f740d34187c4244aa5223e5f16a4772743365e0";
    if (Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(registryPath))).ToLowerInvariant() != publishedRegistrySha256)
        throw new UnauthorizedAccessException("published puzzle registry changed");
    int puzzle = OptInt(opt["puzzle"]);
    long count = OptLong(opt["count"]);
    int jobs = opt.TryGetValue("jobs", out var j) ? OptInt(j) : 2;
    double seconds = opt.TryGetValue("seconds", out var secondsOption) ? OptD(secondsOption) : 45;
    if (count < 1 || count > 33_554_432 || jobs < 1 || jobs > 4 || seconds < 1 || seconds > 60)
        throw new ArgumentOutOfRangeException("bounded chunk, 1..4 workers and 1..60 seconds required");
    var reg = PuzzleRegistry.Load(registryPath);
    if (!reg.TryGet(puzzle, out var entry)) throw new UnauthorizedAccessException("published puzzle required");
    var allowed = PuzzleRegistry.RangeFor(puzzle);
    var start = U256.FromHex(opt["start"]);
    var endBig = start.ToBig() + count;
    if (start.ToBig() < allowed.Start.ToBig() || endBig > allowed.End.ToBig())
        throw new UnauthorizedAccessException("chunk is outside the published puzzle interval");
    var targets = reg.BuildTargetSet(new[] { puzzle });
    reg.AssertAllowedTargetSet(targets);
    var result = new KeyHunter(targets, batchSize).Hunt(new ScanRange(start, ScanRange.FromBig(endBig)), jobs, TimeSpan.FromSeconds(seconds));
    if (result.Found && Ref.AddressForPrivateKey(result.PrivateKey) != entry.Address)
        throw new InvalidOperationException("independent address verification failed");
    // This command is consumed over a private process pipe. The supervisor protects a hit
    // with Windows DPAPI before emitting its public summary; it never logs this payload.
    Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new {
        puzzle, address = entry.Address, start = start.ToHex(), requestedCount = count.ToString(System.Globalization.CultureInfo.InvariantCulture),
        found = result.Found, privateKey = result.Found ? result.PrivateKey.ToHex() : null,
        keysScanned = result.KeysScanned.ToString(System.Globalization.CultureInfo.InvariantCulture),
        completed = !result.Found && result.KeysScanned == (ulong)count, elapsedSeconds = result.ElapsedSeconds
    }));
}

void Solve(Dictionary<string, string> opt)
{
    if (!opt.TryGetValue("puzzle", out var pStr) || !int.TryParse(pStr, out int puzzle))
    {
        Console.WriteLine("uso: solve --puzzle N [--seconds S] [--jobs J]");
        return;
    }
    int jobs = opt.TryGetValue("jobs", out var j) ? OptInt(j) : Environment.ProcessorCount;
    double secs = opt.TryGetValue("seconds", out var s) ? OptD(s) : 15;

    var reg = PuzzleRegistry.Load(registryPath);
    if (!reg.TryGet(puzzle, out var entry))
    {
        Console.WriteLine($"puzzle #{puzzle} não está em {registryPath}.");
        Console.WriteLine("Sem alvo publicado, sem varredura: é o guardrail, não um bug.");
        return;
    }

    var set = reg.BuildTargetSet(new[] { puzzle });
    reg.AssertAllowedTargetSet(set);
    var range = PuzzleRegistry.RangeFor(puzzle);

    Console.WriteLine($"alvo      : {entry.Address}   status na lista: {entry.Status}");
    Console.WriteLine($"fonte     : {Short(reg.Source)} (coletado em {reg.FetchedAt})");
    Console.WriteLine($"intervalo : 2^{puzzle - 1} .. 2^{puzzle} = {Feasibility.HumanCount(range.Size)} chaves");

    double rate = MeasureScanRate(jobs, 3);
    double full = range.Size / rate;
    double covered = secs * rate;
    Console.WriteLine($"taxa real : {rate / 1e3:N1} mil chaves/s com {jobs} workers nesta máquina");
    Console.WriteLine($"orçamento : {secs}s -> {Feasibility.HumanCount(covered)} chaves" +
        (covered >= range.Size ? " (suficiente para esgotar o intervalo)"
                               : $" = {(covered / range.Size) * 100:E2}% do intervalo"));
    Console.WriteLine($"se esgotar: {Feasibility.HumanTime(full)} de CPU contínua aqui (exaustivo).");

    var res = new KeyHunter(set, batchSize).Hunt(range, jobs, TimeSpan.FromSeconds(secs),
        (keys, t) => Console.WriteLine($"  progresso {(double)keys / range.Size * 100:E4}%  {keys / Math.Max(t, 1e-9) / 1e3:N0} mil chaves/s"));
    Console.WriteLine(res.Report());
    if (res.Found)
    {
        // segunda opinião: deriva o endereço da chave achada pela referência BigInteger,
        // caminho totalmente separado do laço rápido do scanner.
        var via = Ref.AddressForPrivateKey(res.PrivateKey);
        Console.WriteLine($"confirmação independente (BigInteger): {via}  {(via == entry.Address ? "== alvo da chain ✓" : "!= alvo ✗")}");
    }
    else Console.WriteLine($"cobertura: {(double)res.KeysScanned / range.Size * 100:E4}% do intervalo nesta rodada.");
}

// ---------------------------------------------------------------- puzzles

async Task Puzzles(Dictionary<string, string> opt)
{
    var reg = PuzzleRegistry.Load(registryPath);
    bool live = opt.ContainsKey("live");
    int spot = opt.TryGetValue("spot", out var sp) ? OptInt(sp) : 4;
    double perCall = opt.TryGetValue("delay", out var dl) ? OptD(dl) : 0.6;
    Console.WriteLine($"lista: {Short(reg.Source)}");
    Console.WriteLine($"coletada em: {reg.FetchedAt}");
    var numbers = reg.Puzzles.Select(p => p.N).Order().ToList();
    Console.WriteLine($"entradas: {numbers.Count}" +
        (live ? $"  (re-confirmando na chain: os pendentes + {spot} gastos de amostra)" : "  (sem reconsulta; use --live)"));
    Console.WriteLine();
    Console.WriteLine($"  {"#",4} {"endereço",35} {"status",10} {"não gasto",13} {"utxos",6} {"maior saída",12} {"gastos",7} {"utxo em",14}");
    Console.WriteLine($"  {new string('-', 116)}");

    long unspentTotal = 0;
    int pending = 0, checkedLive = 0, divergentes = 0;
    // As duas contas que decidem QUAL ataque existe para cada puzzle pendente:
    //   saídas == 0  -> o endereço nunca assinou, então P = k*G nunca esteve na chain.
    //                    Sem o ponto, kangaroo/BSGS não têm o que resolver: só brute force
    //                    com hash160 de cada chave pública candidate.
    //   maior < saldo -> o "prêmio" do catálogo é saldo acumulado de endereço (recepção em
    //                    cima de recepção), não um único output enterrado. O número é
    //                    fotográfico: vale na data da coleta.
    int nuncaGastou = 0, saldoMultiOutput = 0;

    // quem merece re-consulta: tudo que a lista diz que ainda tem saldo, mais uma amostra do que
    // diz que já foi gasto (para pegar lista velha ou status inventado).
    var toCheck = new HashSet<int>();
    if (live)
    {
        foreach (var n in numbers.Where(n => reg.TryGet(n, out var e) && e.FundedSats - e.SpentSats > 0)) toCheck.Add(n);
        foreach (var n in numbers.Where(n => reg.TryGet(n, out var e) && e.FundedSats - e.SpentSats == 0).Take(spot)) toCheck.Add(n);
    }

    await using var mp = live ? new Mempool() : null;
    foreach (int n in numbers)
    {
        if (!reg.TryGet(n, out var e)) continue;
        double unspent = (e.FundedSats - e.SpentSats) / 1e8;
        string status = e.Status;
        string when = "-";
        int utxos = e.UtxoCount;
        string biggest = "-", spentTxt = "-";
        if (mp is not null && toCheck.Contains(n))
        {
            try
            {
                var st = await mp.AddressAsync(e.Address);
                var u = await mp.UtxosAsync(e.Address);
                double liveUnspent = st.UnspentSats / 1e8d;
                status = st.UnspentSats > 0 ? "pendente" : "gasto";
                utxos = u.Count;
                spentTxt = st.SpentCount.ToString();
                biggest = (u.Count == 0 ? 0 : u.Max(x => x.ValueSats) / 1e8).ToString("F4");
                if (status == "pendente")
                {
                    if (st.SpentCount == 0) nuncaGastou++;
                    if (u.Count > 0 && u.Max(x => x.ValueSats) < st.UnspentSats) saldoMultiOutput++;
                }
                when = u.Count > 0
                    ? DateTimeOffset.FromUnixTimeSeconds(u.Max(x => x.BlockTime)).ToString("yyyy-MM-dd")
                    : "-";
                if (Math.Abs(liveUnspent - unspent) > 1e-9) divergentes++;
                checkedLive++;
                unspent = liveUnspent;
                await Task.Delay(TimeSpan.FromSeconds(perCall));
            }
            catch (Exception ex) { status = "erro"; when = ex.GetType().Name; }
        }
        if (unspent > 0) { unspentTotal += (long)(unspent * 1e8); pending++; }
        Console.WriteLine($"  {n,4} {e.Address,35} {status,10} {unspent,10:F5} {utxos,6} {biggest,12} {spentTxt,7} {when,14}");
    }

    Console.WriteLine();
    Console.WriteLine($"  pendentes: {pending} puzzles somando {unspentTotal / 1e8:F4} BTC");
    if (live)
    {
        Console.WriteLine($"  re-confirmado na chain: {checkedLive} endereços, {divergentes} divergência(s) de saldo contra a lista" +
                          (divergentes == 0 ? " -> a lista bate com a rede." : " -> desconfie da lista."));
        Console.WriteLine($"  qual ataque EXISTE, derivado da chain: {nuncaGastou} pendente(s) com 0 saída(s) na chain (de {checkedLive}");
        Console.WriteLine("     endereços re-consultados) -> para esses nenhum P = k*G foi assinado por aquele endereço,");
        Console.WriteLine("     então kangaroo/BSGS não têm entrada. O único ataque é varrer o intervalo e bater o");
        Console.WriteLine("     hash160 de cada chave pública candidate contra o alvo: a coluna exaustiva da tabela.");
        Console.WriteLine($"  o número do catálogo é fotográfico: {saldoMultiOutput} dos pendentes têm saldo feito de MAIS de um");
        Console.WriteLine("     output (o maior deles é menor que o saldo). Não é um UTXO enterrado: é endereço recebendo");
        Console.WriteLine("     em cima de endereço recebido. Valor sem data de coleta não é cifra, é torcida.");
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(perCall));
            var (pt, usd) = await mp!.PriceUsdAsync();
            Console.WriteLine($"  grandeza do número (não é recomendação de nada): {unspentTotal / 1e8:F4} BTC x US$ {usd:N0}/BTC " +
                $"(spot {DateTimeOffset.FromUnixTimeSeconds(pt):yyyy-MM-dd HH:mm} UTC) = US$ {unspentTotal / 1e8 * usd:N0}");
        }
        catch (Exception ex) { Console.WriteLine($"  preço spot indisponível: {ex.GetType().Name}"); }
    }
    Console.WriteLine();
    Console.WriteLine("  saldo pendente não é prêmio de graça: é o que está na frente de um intervalo de");
    Console.WriteLine("  chaves. Quem esgotar o intervalo leva; todo o resto é ruído matemático.");
}

// ---------------------------------------------------------------- dormant

async Task Dormant(Dictionary<string, string> opt)
{
    int find = opt.TryGetValue("find", out var fi) ? OptInt(fi) : 5;
    int maxBlocks = opt.TryGetValue("max", out var mx) ? OptInt(mx) : 120;
    int startHeight = opt.TryGetValue("from", out var fh) ? OptInt(fh) : 9;
    int stride = opt.TryGetValue("stride", out var sd) ? OptInt(sd) : 1;
    int par = opt.TryGetValue("par", out var pr) ? OptInt(pr) : 4;
    bool coinbaseOnly = !opt.ContainsKey("all");
    double perCall = opt.TryGetValue("delay", out var d) ? OptD(d) : 0.8;
    int blockRetries = opt.TryGetValue("retry", out var rt) ? OptInt(rt) : 3;
    long olderThanYears = opt.TryGetValue("min-age", out var ma) ? OptLong(ma) : 10;
    // Teto de saídas conferidas POR BLOCO. Sem `--all` o laço só olha a coinbase (1-2 saídas),
    // então o teto não aperta nada; com `--all`, um bloco de 2016 tem centenas de transações e
    // cada saída é um GET - o default declarado é o que impede a amostra de virar flood.
    int perBlock = opt.TryGetValue("per-block", out var pbn) ? OptInt(pbn) : (coinbaseOnly ? 0 : 40);
    // Saídas conferidas POR TRANSAÇÃO. O default (2) é o troco típico; `--per-tx 99` é o que
    // permite mirar uma tx específica - por exemplo a tx-puzzle, cujos 99 outputs são 99
    // endereços diferentes e cuja contagem de intactas é conferível contra `puzzles --live`.
    int perTx = opt.TryGetValue("per-tx", out var ptx) ? OptInt(ptx) : 2;

    Console.WriteLine($"alvo: {find} saída(s) com mais de {olderThanYears} ano(s) ainda intacta(s), examinando até {maxBlocks} blocos");
    Console.WriteLine($"        a partir da altura {startHeight} (stride {stride}, {(coinbaseOnly ? "só coinbase" : "todas as saídas")})" +
        (perBlock > 0 ? $", teto de {perBlock} saída(s) conferida(s) por bloco." : "."));
    Console.WriteLine($"        1 pedido a cada {perCall:F2}s (piso GLOBAL) + backoff + AIMD se o endpoint reclamar.");
    Console.WriteLine("        por que não um 'máximo seguro' medido: o MESMO ritmo já passou limpo numa janela e levou");
    Console.WriteLine("        429 em outra - `docs/rate-probe.txt` tem rajada sequencial a ~4/s e 48 pedidos simultâneos");
    Console.WriteLine("        sem um 429; `docs/dormant.txt` tem o scan sustentado a ~1,1 GET/s com 429 periódico.");
    Console.WriteLine("        O limitador tem estado, como o pool de DNS: daí piso + AIMD, não 'a taxa que passou'.");
    Console.WriteLine($"        {par} blocos em voo, até {blockRetries} tentativa(s) por bloco; conexão com orçamento de " +
        $"{Mempool.PerAddressConnectSeconds:F0}s POR ENDEREÇO do DNS (já pegamos IP do pool engolindo SYN; a lista muda de janela a janela - docs/rate-probe.txt).");
    Console.WriteLine("só GET em endpoint público: block-height, block, block/txs, address/<a>, address/<a>/utxo.");
    Console.WriteLine("Nada assinado, nada transmitido.");
    Console.WriteLine("vereditos possíveis: AINDA NO LUGAR (o outpoint está na lista de UTXOs, ou - marcado");
    Console.WriteLine("[contadores] - nenhum gasto jamais registrado para aquele endereço), já foi movida");
    Console.WriteLine("(não está, e o endpoint indexa esse tipo de script) e SEM VEREDITO, que tem duas causas");
    Console.WriteLine("medidas: 'fora do índice' (o índice de endereço não contém este tipo de script, P2PK)");
    Console.WriteLine("e 'lista recusada' (o Esplora devolve HTTP 400 \"Too many unspent transaction outputs");
    Console.WriteLine("(>500)\" para este endereço, E os contadores agregados também não decidem). Nas duas a");
    Console.WriteLine("ausência é buraco do oráculo, não fato sobre a moeda. Quando a lista é recusada, os");
    Console.WriteLine("contadores de address/<a> ainda respondem em dois casos: spent_txo_count = 0 (nada jamais");
    Console.WriteLine("saiu deste endereço) e funded_txo_count = 1 com gasto (a única saída que existiu aqui");
    Console.WriteLine("foi consumida) - mas só depois de funded_txo_sum comportar o valor DESTA saída, senão");
    Console.WriteLine("aquele agregado não está falando dela. A linha vem marcada [contadores], porque a força");
    Console.WriteLine("da prova é outra.");
    Console.WriteLine();

    await using var mp = new Mempool(minIntervalSeconds: perCall);
    var scan = new DormantScanner(mp, coinbaseOnly, perBlock, perTx);
    var rows = new List<DormantRow>();
    var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    var sw = Stopwatch.StartNew();

    // Fila com `par` blocos em voo, mas com a contagem num thread só (o loop abaixo).
    // A primeira versão abria um bloco por worker com 0,15s de pausa *por worker*:
    // ~26 pedidos/s no total, e o endpoint devolveu 429 em série, conexão cortada e
    // timeout - a saída virava lista de "falha de rede" e o scan parava no bloco 84.
    // O ritmo agora é global (token bucket dentro do Mempool), o bloco que falha volta
    // para o fim da fila, e quem esgota as tentativas é contado como falha - não como
    // "não existe saída parada aqui".
    var queue = new Queue<int>(Enumerable.Range(0, maxBlocks).Select(i => startHeight + i * stride));
    var retry = new Queue<int>();
    var attempts = new Dictionary<int, int>();
    var inFlight = new List<Task<(int H, List<DormantRow> Rows, Exception? Err)>>();
    int read = 0, failures = 0;

    Task<(int, List<DormantRow>, Exception?)> Work(int h) => Task.Run(async () =>
    {
        try { return (h, await scan.ScanBlockAsync(h), (Exception?)null); }
        catch (Exception ex) { return (h, new List<DormantRow>(), ex); }
    });

    static string VerdictText(DormantRow r) => r.V switch
    {
        Spentness.Intacta => "AINDA NO LUGAR ",
        Spentness.Gasta => "já foi movida  ",
        // Dois buracos, duas frases: o índice não contém este TIPO de script, ou o endpoint
        // se recusa a dar a LISTA deste endereço (teto dele) E os contadores também não
        // decidem. Os dois autorizam a mesma conclusão - nenhuma - e proíbem as duas
        // conclusões falsas, "está parado" e "foi gasto".
        _ => r.ListOk ? "fora do índice  " : "lista recusada  ",
    };

    void Report(List<DormantRow> found)
    {
        foreach (var r in found)
        {
            double yrs = (now - r.BlockTime) / (365.25 * 86400);
            if (yrs < olderThanYears) continue;
            rows.Add(r);
            Console.WriteLine($"  bloco {r.Height,6} ({yrs,5:F1} anos) {(r.Coinbase ? "coinbase    " : "transferência")} " +
                $"{r.Sats / 1e8,10:F5} BTC  {VerdictText(r)}  {r.Type,9}  {r.Address}" +
                (r.Via == "lista" ? "" : $"   [{r.Via}: {r.FundedCount} saída(s) recebida(s), {r.SpentCount} gasta(s)]"));
        }
    }

    while (queue.Count + retry.Count + inFlight.Count > 0 && rows.Count(r => r.V == Spentness.Intacta) < find)
    {
        while (inFlight.Count < par && (queue.Count > 0 || retry.Count > 0))
        {
            int h = queue.Count > 0 ? queue.Dequeue() : retry.Dequeue();
            attempts[h] = attempts.TryGetValue(h, out var a) ? a + 1 : 1;
            inFlight.Add(Work(h));
        }
        var finished = await Task.WhenAny(inFlight);
        inFlight.Remove(finished);
        var (bh, found, err) = finished.Result;
        if (err is null) { read++; Report(found); }
        else if (attempts[bh] < blockRetries) retry.Enqueue(bh);
        else { failures++; Console.WriteLine($"  bloco {bh,6}: {err.GetType().Name} {Short(err.Message, 58)} -> sem retry"); }
        Console.WriteLine($"  {read + failures}/{maxBlocks} blocos fechados ({read} lidos, {failures} falha(s), " +
            $"{queue.Count + retry.Count} na fila, {inFlight.Count} em voo) em {sw.Elapsed.TotalSeconds:F0}s: " +
            $"{mp.Stats.Requests} GET, {mp.Stats.Retries} retry, {mp.Stats.Throttled} x 429" +
            (mp.Stats.Refusals > 0 ? $", {mp.Stats.Refusals} lista recusada" : ""));
    }
    // se o --find chegou antes do fim, o que está em voo ainda é lido e impresso: é dado
    // da chain, não sobra de orçamento.
    foreach (var t in inFlight)
    {
        var (h, found, err) = await t;
        if (err is null) { read++; Report(found); } else failures++;
    }

    if (read == 0) { Console.WriteLine("nada lido (rede indisponível?)."); return; }
    if (rows.Count == 0) Console.WriteLine("  (nenhuma saída da amostra passa do corte de idade; ainda assim a tabela de cobertura abaixo é medida)");

    var intactas = rows.Where(r => r.V == Spentness.Intacta).OrderByDescending(r => r.Sats).ToList();
    var movidas = rows.Where(r => r.V == Spentness.Gasta).ToList();
    var semVeredito = rows.Where(r => r.V == Spentness.NaoConferivel).ToList();
    long unspentSats = intactas.Sum(r => r.Sats);
    long spentSats = movidas.Sum(r => r.Sats);
    long blindSats = semVeredito.Sum(r => r.Sats);

    Console.WriteLine();
    Console.WriteLine($"  AS INTACTAS (conferidas uma a uma: o outpoint na lista de UTXOs do endereço, ou -");
    Console.WriteLine($"  quando a lista foi recusada - zero gastos registrados para o endereço inteiro)");
    Console.WriteLine($"  {"bloco",7} {"idade",8} {"origem",13} {"endereço",36} {"valor",12} {"script",9} {"como sei",28}");
    Console.WriteLine($"  {new string('-', 110)}");
    foreach (var r in intactas)
    {
        double yrs = (now - r.BlockTime) / (365.25 * 86400);
        string how = r.Via == "lista" ? "outpoint na lista de UTXOs"
            : $"contadores: {r.FundedCount} receb., {r.SpentCount} gasta(s)";
        Console.WriteLine($"  {r.Height,7} {yrs,6:F1} a {(r.Coinbase ? "coinbase" : "transferência"),13} {r.Address,36} {r.Sats / 1e8,10:F5} BTC {r.Type,9}  {how}");
    }
    if (intactas.Count == 0) Console.WriteLine("  (nenhuma nesta amostra)");
    else if (scan.VerdictsFromCounters > 0)
    {
        Console.WriteLine($"  nota: {scan.VerdictsFromCounters} dela(s) vêm dos CONTADORES de address/<a>, não da lista de");
        Console.WriteLine("  UTXOs - o endpoint recusou a lista (>500 saídas) e os agregados decidiram mesmo assim:");
        Console.WriteLine("  'spent_txo_count = 0' quer dizer que NENHUMA saída daquele endereço foi jamais gasta.");
        Console.WriteLine("  Reserva honesta: contadores falam do endereço inteiro, não do outpoint (só são");
        Console.WriteLine("  aceitos quando a soma do endereço comporta o valor desta saída), e só valem");
        Console.WriteLine("  sobre blocos confirmados - um gasto parado no mempool não aparece neles.");
    }

    // A tabela que diz até onde esta ferramenta pode ir, medida na própria corrida: quantas
    // saídas de cada tipo o endpoint indexa por endereço. Sem ela, "0 intactas" lê como
    // "não há moeda parada" e a frase verdadeira é "não há prova aqui".
    Console.WriteLine();
    Console.WriteLine("  COBERTURA DO ORÁCULO POR TIPO DE SCRIPT (é o que limita a frase acima)");
    Console.WriteLine($"  {"script",12} {"saídas",7} {"o endpoint deu endereço?",25} {"intactas",9} {"movidas",8} {"sem veredito",13} {"BTC",11}");
    Console.WriteLine($"  {new string('-', 92)}");
    foreach (var g in rows.GroupBy(r => r.Type).OrderByDescending(g => g.Sum(x => x.Sats)))
    {
        int idx = g.Count(r => r.Indexed);
        Console.WriteLine($"  {g.Key,12} {g.Count(),7} {idx,25} {g.Count(r => r.V == Spentness.Intacta),9} " +
            $"{g.Count(r => r.V == Spentness.Gasta),8} {g.Count(r => r.V == Spentness.NaoConferivel),13} {g.Sum(x => x.Sats) / 1e8,11:F4}");
    }

    Console.WriteLine();
    Console.WriteLine($"  lidos: {read}/{maxBlocks} blocos ({rows.Count} saídas conferidas, {failures} que não fecharam em {blockRetries} tentativa(s))");
    if (perBlock > 0)
        Console.WriteLine($"  amostra: teto de {perBlock} saída(s) por bloco; {scan.OutputsSkipped} candidatura(s) ficaram de fora dele " +
            "(as primeiras do bloco, na ordem em que a API as devolve - corte declarado, não varredura completa).");
    Console.WriteLine($"  veredito: {intactas.Count} intacta(s) = {unspentSats / 1e8:F4} BTC | {movidas.Count} movída(s) = {spentSats / 1e8:F4} BTC | " +
        $"{semVeredito.Count} SEM VEREDITO = {blindSats / 1e8:F4} BTC");
    // O SEM VEREDITO tem duas causas medidas, e elas não são a mesma frase: um tipo de script
    // que o índice não contém, e uma lista que o servidor se recusa a entregar. Separar as duas
    // é o que impede "o oráculo está cego" de virar, na próxima versão, "o oráculo respondeu não".
    if (semVeredito.Count > 0)
    {
        int foraDoIndice = semVeredito.Count(r => r.ListOk);
        int recusada = semVeredito.Count(r => !r.ListOk);
        Console.WriteLine($"     ├─ {foraDoIndice} por 'fora do índice' (o endpoint não indexa este tipo de script por endereço)");
        Console.WriteLine($"     └─ {recusada} por 'lista recusada' (HTTP 400 \">500 UTXOs\" e os contadores não decidem;" +
            $" {scan.ListRefusals} endereço(s) distintos recusados)");
        Console.WriteLine($"     vereditos que vieram dos contadores em vez da lista: {scan.VerdictsFromCounters}");
    }
    Console.WriteLine($"  traffic do servidor: {mp.Stats.Requests} GET, {mp.Stats.Retries} retry(s), {mp.Stats.Throttled} x HTTP 429, " +
        $"{mp.Stats.Refusals} recusa(s) de lista em {sw.Elapsed.TotalSeconds:F0}s" +
        $" ({scan.CacheHits} lookup(s) de UTXO aproveitados da cache em vez de pedidos).");
    Console.WriteLine($"  decoder local contra o endpoint: {scan.DecodeAgree} endereço(s) em que os dois batem, " +
        $"{scan.DecodeDisagree} divergindo.");
    if (scan.DecodeAgree > 0 && scan.DecodeDisagree == 0)
        Console.WriteLine("     -> é isto que autoriza mostrar um endereço derivado de um P2PK sem tratá-lo como chave de");
    else if (scan.DecodeAgree > 0)
        Console.WriteLine("     -> DIVERGÊNCIA entre o nosso decoder e o endpoint; linhas de exemplo abaixo.");
    else
        Console.WriteLine("     -> nesta amostra o endpoint nunca deu endereço: o controle não roda aqui, e é por isso");
    if (scan.DecodeAgree > 0 && scan.DecodeDisagree == 0)
        Console.WriteLine("        endereço alheio: o mesmo Hash160+Base58Check que ele valida num P2PKH roda no script cru.");
    else
        Console.WriteLine("        mesmo assim que o P2PK sai marcado como SEM VEREDITO, e não como gasto.");
    lock (scan.DecodeBad) foreach (var msg in scan.DecodeBad) Console.WriteLine(msg);
    if (unspentSats > 0)
    {
        double minAge = intactas.Select(r => (now - r.BlockTime) / (365.25 * 86400)).Min();
        Console.WriteLine($"  moeda mais nova deste conjunto: {minAge:F1} anos sem um único gasto registrado.");
    }
    Console.WriteLine();
    Console.WriteLine("  O QUE \"SEM VEREDITO\" QUER DIZER (e não é timidez): este deployment não indexa");
    Console.WriteLine("  P2PK por endereço, e nós NÃO inventamos o índice - medimos. Os oráculos de outpoint");
    Console.WriteLine("  do Esplora (/spending/<txid>/<vout>, /script/<hex>/txs, is_spent em /tx) não existem");
    Console.WriteLine("  aqui nem no blockstream.info: 404 em todos (docs/dormant-oracles.txt). Então a");
    Console.WriteLine("  ausência de um coinbase P2PK na lista de UTXOs do endereço dele não diz que ele foi");
    Console.WriteLine("  gasto; diz que a gente não perguntou do jeito que o servidor entende. Corrigir isto");
    Console.WriteLine("  exige um índice de inputs construído por nós, bloco a bloco - não uma frase mais forte.");
    Console.WriteLine("  A segunda causa é do servidor, não nossa: em address/<a>/utxo o mempool.space responde");
    Console.WriteLine("  HTTP 400 \"Too many unspent transaction outputs (>500)\" para endereço muito usado - é o");
    Console.WriteLine($"  caso de {scan.ListRefusals} endereço(s) nesta corrida, inclusive o da gênesis");
    // Sem número absoluto aqui: `funded_txo_count` da gênesis sobe a cada doação (83.440 numa
    // leitura de 2026-11-08 e 83.441 em outra, horas depois), e uma frase colada no rodapé viraria
    // mentira sozinha. O valor conferível é o que a própria linha imprime:
    // `[contadores: N recebida(s), 0 gasta(s)]`.
    Console.WriteLine("  (1A1zP1..., mais de 83 mil saídas recebidas e NENHUMA gasta - agregado medido em");
    Console.WriteLine("  2026-11-08; o número exato desta corrida é o que a linha acima imprime). address/<a>");
    Console.WriteLine("  continua respondendo 200, e quando spent_txo_count = 0 os contadores decidem sem");
    Console.WriteLine("  lista: nunca saiu um satoshi dali.");
    Console.WriteLine();
    Console.WriteLine("  o que a chain PROVA: outpoint por outpoint, o que segue parado e o que já se");
    Console.WriteLine("  moveu (gastar é público). O que ela NÃO prova: que o dono perdeu a chave, que o");
    Console.WriteLine("  dono morreu, ou que a moeda está disponível para alguém - parado != abandonado.");
    Console.WriteLine("  Nada aqui toca fundo alheio: sem montar, assinar ou transmitir transação.");
}

// ---------------------------------------------------------------- probe
//
// A/B do NOSSO cliente HTTP contra o endpoint público, para separar as três explicações
// que se parecem demais na saída de um scan: "o servidor nos limitou", "a nossa conexão
// keep-alive morreu" e "foi o build/tls". `--fresh` abre um Mempool (logo uma conexão)
// por pedido; sem ele o mesmo HttpClient atende todos, que é o comportamento do scan.
async Task Probe(Dictionary<string, string> opt)
{
    int n = opt.TryGetValue("n", out var ns) ? OptInt(ns) : 10;
    double every = opt.TryGetValue("every", out var ev) ? OptD(ev) : 1.0;
    int start = opt.TryGetValue("from", out var fr) ? OptInt(fr) : 200;
    bool fresh = opt.ContainsKey("fresh");

    Console.WriteLine($"probe: {n} GETs em block-height/{start}..{start + n - 1}, {every:F2}s de intervalo, " +
        $"{(fresh ? "uma conexao nova por pedido (--fresh)" : "mesmo HttpClient para todos (keep-alive)")}");
    Console.WriteLine("               (mesmo codigo do scan: Mempool + token bucket + backoff)");
    Console.WriteLine();

    Mempool? shared = fresh ? null : new Mempool(minIntervalSeconds: Math.Min(every, 0.05));
    int ok = 0, bad = 0;
    var times = new List<double>();
    for (int i = 0; i < n; i++)
    {
        await using var oneShot = fresh ? new Mempool(minIntervalSeconds: 0) : null;
        var mp = oneShot ?? shared!;
        var sw = Stopwatch.StartNew();
        string line;
        try
        {
            var hash = await mp.BlockHashAtHeightAsync(start + i);
            sw.Stop(); times.Add(sw.Elapsed.TotalMilliseconds);
            ok++;
            line = $"200  {sw.Elapsed.TotalMilliseconds,7:F0} ms  {Short(hash, 24)}";
        }
        catch (Exception ex)
        {
            sw.Stop(); bad++;
            var inner = ex.InnerException is { } e2 ? $" | inner {e2.GetType().Name}: {Short(e2.Message, 90)}" : "";
            line = $"ERRO {sw.Elapsed.TotalMilliseconds,6:F0} ms  {ex.GetType().Name}: {Short(ex.Message, 110)}{inner}";
        }
        Console.WriteLine($"  {i,3}  {line}");
        if (i < n - 1) await Task.Delay(TimeSpan.FromSeconds(every));
    }
    double med = times.Count > 0 ? times.OrderBy(t => t).ElementAt(times.Count / 2) : 0;
    Console.WriteLine();
    Console.WriteLine($"  {ok} x 200, {bad} falha(s); mediana {med:F0} ms; min {(times.Count > 0 ? times.Min() : 0):F0} ms " +
        $"max {(times.Count > 0 ? times.Max() : 0):F0} ms");
    if (shared is not null)
    {
        var s = shared.Stats;
        Console.WriteLine($"  contabilidade do cliente: {s.Requests} GET, {s.Retries} retry, {s.Throttled} x 429, " +
            $"{s.Failed} falha definitiva, ritmo atual x{s.Pace:F1}");
        await shared.DisposeAsync();
    }
    Console.WriteLine();
    Console.WriteLine("  leitura: 200 em ~0,5s com conexao nova e timeout com keep-alive = conexao morta.");
    Console.WriteLine("  429 = o servidor pediu pausa (Retry-After). Rajada curta nem sempre produz;");
    Console.WriteLine("  varredura sustentada produz (veja a linha 'traffic do servidor' em");
    Console.WriteLine("  docs/dormant.txt, que conta os 429 da corrida inteira). Falha nos");
    Console.WriteLine("  dois modos = o endpoint nao quer mais falar com este IP agora (nesse caso a");
    Console.WriteLine("  saida honesta e esperar, nao insistir).");
}

// ---------------------------------------------------------------- moves

async Task Moves(Dictionary<string, string> opt)
{
    int from = opt.TryGetValue("from", out var f) ? OptInt(f) : 63;
    int to = opt.TryGetValue("to", out var t) ? OptInt(t) : 70;
    int pages = opt.TryGetValue("pages", out var pg) ? OptInt(pg) : 2;
    double perCall = opt.TryGetValue("delay", out var d) ? OptD(d) : 0.25;

    var reg = PuzzleRegistry.Load(registryPath);
    Console.WriteLine($"o que a CHAIN registra sobre os puzzles #{from}..#{to} - datas de entrada e de saída do prêmio.");
    Console.WriteLine($"histórico lido: {pages} chamada(s) de txs por endereço (mempool.space, só GET). Cada chamada devolve" +
        " a janela que a API quiser, e o `?after=` dela é ignorado nesta implantação - o que soma certo é o dedupe por" +
        " txid, e a contabilidade dele está no rodapé.");
    Console.WriteLine();
    Console.WriteLine($"  {"#",4} {"endereço",35} {"entrou",10} {"saiu",10} {"saldo",9} {"1ª tx",11} {"última tx",11} {"txs",4}  saídas (data: quanto)");
    Console.WriteLine($"  {new string('-', 128)}");

    await using var mp = new Mempool();
    int totRaw = 0, totDup = 0, totDistinct = 0, cut = 0, anomaly = 0;
    for (int n = from; n <= to; n++)
    {
        if (!reg.TryGet(n, out var e)) { Console.WriteLine($"  {n,4} (não está na lista)"); continue; }
        try
        {
            var st = await mp.AddressAsync(e.Address);
            await Task.Delay(TimeSpan.FromSeconds(perCall));
            var h = await mp.AddressTxsAsync(e.Address, pages);
            await Task.Delay(TimeSpan.FromSeconds(perCall));
            var hist = h.Txs;

            long entered = hist.Sum(x => x.InSats), left = hist.Sum(x => x.OutSats);
            var ordered = hist.Where(x => x.BlockTime > 0).OrderBy(x => x.BlockTime).ToList();
            var firstIn = ordered.FirstOrDefault(x => x.InSats > 0);
            var outs = ordered.Where(x => x.OutSats > 0).ToList();
            string saldo = (st.UnspentSats / 1e8).ToString("F5");
            string quando = $"{(firstIn?.BlockDate ?? "-"),11} {(ordered.Count == 0 ? "-" : ordered[^1].BlockDate),11} {ordered.Count,4}";
            string saidas = outs.Count == 0 ? "-"
                : string.Join("  ", outs.Take(3).Select(o => $"{o.BlockDate}: {o.OutSats / 1e8:F6}"))
                  + (outs.Count > 3 ? $"  (+{outs.Count - 3})" : "");
            Console.WriteLine($"  {n,4} {e.Address,35} {entered / 1e8,8:F4}  {left / 1e8,8:F4} {saldo,9} {quando}  {Short(saidas, 60)}");
            totRaw += h.RawRows; totDup += h.DuplicateRows; totDistinct += h.Txs.Count;
            // A janela é um corte, não o histórico: diz quantas txs a chain registra ao todo.
            // Sem isso, "saiu 12,5 BTC" de um endereço que nunca recebeu mais de 6,6 parece fato
            // quando é soma de página sobreposta.
            if (h.Txs.Count < st.TxCount) { cut++; }
            if (left > entered + 1000) { anomaly++; }
            if (h.Txs.Count < st.TxCount || left > entered + 1000)
                Console.WriteLine($"       ({h.Txs.Count} txs distintas de {st.TxCount} que a chain registra;" +
                    $" entrou {entered / 1e8:F4} / saiu {left / 1e8:F4}" +
                    $"{(left > entered + 1000 ? "  <- SAIU > ENTROU na janela lida: reliquial de soma duplicada, confira" : "")})");
        }
        catch (Exception ex) { Console.WriteLine($"  {n,4} {e.Address,35} {ex.GetType().Name}"); }
    }

    Console.WriteLine();
    Console.WriteLine($"  contabilidade da leitura: {totRaw} linhas devolvidas pela API, {totDup} duplicata(s) de paginação" +
        $" cortada(s) por txid, {totDistinct} transações distintas somadas; {cut} endereço(s) com histórico maior que a" +
        $" janela, {anomaly} com saiu>entrou depois do dedupe.");
    Console.WriteLine("  leitura honesta destas datas:");
    Console.WriteLine("   - 'entrou'/'saiu' somam a JANELA lida, inclusive troco e re-movimentações. O que vale como");
    Console.WriteLine("     fato em qualquer linha é o saldo atual, as datas de saída e a contabilidade acima.");
    Console.WriteLine("   - os múltiplos de 5 (#65, #70) têm uma saída de 1.000 sats em 2019-06-01, seis e oito dias");
    Console.WriteLine("     antes de o prêmio sair. Gastar de um endereço P2PKH publica a chave pública dele no");
    Console.WriteLine("     scriptSig daquela tx - é isto que transforma um intervalo de chaves em ECDLP com P=k·G");
    Console.WriteLine("     conhecido, e portanto em problema de sqrt(N). Não é hipótese de fórum: é a mecânica de");
    Console.WriteLine("     assinatura do Bitcoin, visível numa tx de 1.000 sats.");
    Console.WriteLine("   - a data em que o prêmio saiu do endereço do puzzle é pública e conferível; a data");
    Console.WriteLine("     'em que o puzzle foi resolvido' que circula em fórum é outra coisa (às vezes o");
    Console.WriteLine("     dia do anúncio, às vezes a tx de teste do achador). Confira, não repita.");
    Console.WriteLine("   - o endereço que recebeu é o destino da tx de saída: quem tem a chave gasta, e isso");
    Console.WriteLine("     não diz nada sobre quem achou a chave nem sobre quem detém as moedas agora.");
    Console.WriteLine("   - saldo != 0 com 'status: gasto' na lista de terceiros = a lista está errada (ou o");
    Console.WriteLine("     puzzle foi pago e voltou a ter UTXO por poeira). A chain manda, a lista não.");
    Console.WriteLine("   - o que estava ERRADO nesta seção antes do dedupe: #66/#68/#69 pareciam gastar o prêmio");
    Console.WriteLine("     DUAS vezes no mesmo dia, e eu chamei aquilo de assinatura on-chain dos double-spend que a");
    Console.WriteLine("     comunidade narrou. Eram as mesmas linhas contadas de novo. Depois do dedupe, entrou ==");
    Console.WriteLine("     saiu em todos os endereços (o #66 fecha em 5,94 + 0,66 no mesmo dia = o prêmio inteiro,");
    Console.WriteLine("     em duas txs) e não há duas saídas grandes concorrentes em lugar nenhum.");
    Console.WriteLine("     Número sem contabilidade é opinião - inclusive quando o número é o nosso próprio log.");
}

// ---------------------------------------------------------------- stack
//
// "Quanto vale o puzzle #N" é uma pergunta sobre o SALDO DE UM ENDEREÇO, e saldo tem
// história. Esta subcomando lê o conjunto de UTXOs de cada pendente e agrupa por data de
// confirmação: em vez de um número de catálogo, sai a lista de eventos que formaram aquele
// dinheiro. É read-only, um GET por endereço, e não fala com ninguém - mostra de onde veio.
async Task Stack(Dictionary<string, string> opt)
{
    int from = opt.TryGetValue("from", out var f) ? OptInt(f) : 1;
    int to = opt.TryGetValue("to", out var t) ? OptInt(t) : 200;
    double perCall = opt.TryGetValue("delay", out var d) ? OptD(d) : 0.2;
    long dustSats = opt.TryGetValue("dust", out var ds) ? OptLong(ds) : 100_000;   // 0,001 BTC

    var reg = PuzzleRegistry.Load(registryPath);
    var pending = reg.Puzzles.Where(p => p.N >= from && p.N <= to && p.FundedSats - p.SpentSats > 0)
                            .OrderBy(p => p.N).ToList();
    Console.WriteLine($"de onde vem o dinheiro dos puzzles #{from}..#{to} que a lista diz estarem abertos: {pending.Count} endereços.");
    Console.WriteLine($"um GET de UTXO por endereço; agrupo por data de confirmação. Só leitura, nada assinado.");
    Console.WriteLine();
    Console.WriteLine($"  {"#",4} {"endereço",35} {"saldo",11} {"outputs",8} {"maior",8} {"por data (BTC / % do saldo)",44}");
    Console.WriteLine($"  {new string('-', 132)}");

    var byDate = new Dictionary<string, (long Sats, int Addrs)>();
    long totalSats = 0; int read = 0, errs = 0, ninetyCount = 0;
    await using var mp = new Mempool();
    foreach (var e in pending)
    {
        List<Utxo> u;
        try { u = await mp.UtxosAsync(e.Address); }
        catch (Exception ex) { errs++; Console.WriteLine($"  {e.N,4} {e.Address,35} {ex.GetType().Name}"); continue; }
        await Task.Delay(TimeSpan.FromSeconds(perCall));

        long sum = u.Sum(x => x.ValueSats);
        if (sum == 0) { Console.WriteLine($"  {e.N,4} {e.Address,35} {"(sem UTXO)",11}"); continue; }
        read++; totalSats += sum;

        var groups = u.GroupBy(x => DateTimeOffset.FromUnixTimeSeconds(x.BlockTime).ToString("yyyy-MM-dd"))
                      .Select(g => (Date: g.Key, Sats: g.Sum(x => x.ValueSats)))
                      .OrderByDescending(g => g.Sats).ToList();
        long biggest = groups[0].Sats;
        double share = (double)biggest / sum;
        if (Math.Abs(share - 0.90) < 0.005) ninetyCount++;
        foreach (var g in groups)
        {
            var cur = byDate.TryGetValue(g.Date, out var v) ? v : (0L, 0);
            byDate[g.Date] = (cur.Item1 + g.Sats, cur.Item2 + 1);
        }
        string trail = string.Join("  ", groups.Where(g => g.Sats >= dustSats).Take(3).Select(g =>
            $"{g.Date}: {g.Sats / 1e8:F4} ({100.0 * g.Sats / sum:F1}%)"));
        Console.WriteLine($"  {e.N,4} {e.Address,35} {sum / 1e8,11:F5} {u.Count,8} {100 * share,7:F1}%  {Short(trail, 44)}");
    }

    Console.WriteLine();
    Console.WriteLine($"  lidos: {read} endereços, {errs} falha(s) de rede, {totalSats / 1e8:F4} BTC no total " +
        $"({ninetyCount} com um único evento formando 90% do saldo), {byDate.Count} datas distintas");
    Console.WriteLine();
    Console.WriteLine("  os eventos, somados entre todos os endereços abertos - é isto que 'prêmio' quer dizer:");
    Console.WriteLine($"  {"data",12} {"BTC",12} {"% do total",11} {"endereços",10}");
    foreach (var g in byDate.OrderByDescending(x => x.Value.Sats).Take(12))
        Console.WriteLine($"  {g.Key,12} {g.Value.Sats / 1e8,12:F4} {100.0 * g.Value.Sats / totalSats,10:F1}% {g.Value.Addrs,10}");
    long top = byDate.OrderByDescending(x => x.Value.Sats).FirstOrDefault().Value.Sats;
    // A estrutura das camadas, sem eu ter que deduzir de tabela: as três datas que mais pesam,
    // normalizadas pela menor delas. Se todo endereço aberto tem a mesma razão, o "prêmio" não
    // cresceu organicamente - foi reabastecido em camadas proporcionais, no mesmo dia.
    var three = byDate.OrderByDescending(x => x.Value.Sats).Take(3).Select(x => (x.Key, x.Value.Sats)).ToList();
    string ratio = three.Count == 3 && three[^1].Sats > 0
        ? string.Join(" : ", three.Select(x => $"{(double)x.Sats / three[^1].Sats:F2} ({x.Key})"))
        : "(menos de três camadas para comparar)";
    Console.WriteLine();
    Console.WriteLine($"  camadas, na razão da menor para a maior: {ratio}");
    Console.WriteLine($"  endereços abertos com a maior camada formando ~90% do saldo: {ninetyCount}/{read}");
    Console.WriteLine($"  leitura: a data que mais pesa não é a do criador do puzzle - é a de quem reabastiu a");
    Console.WriteLine($"  mesa. {totalSats / 1e8:F4} BTC 'em prêmio' é saldo corrente de endereço, e {100.0 * top / Math.Max(totalSats, 1):F0}%");
    Console.WriteLine("  disso chegou num único dia, por transações de terceiros. O número do catálogo muda com");
    Console.WriteLine("  doação alheia; a conta de viabilidade não muda, porque ela depende do intervalo, não do");
    Console.WriteLine("  saldo. Quem resolve leva o que estiver lá NA QUELE BLOCO - confira a data.");
}

// Uma saída conferida outpoint por outpoint no dormant: bloco de origem, hora do bloco,
// endereço (do endpoint, ou nosso quando ele não manda), valor, tipo de script, e o veredito
// de três estados - Intacta / Gasta / NaoConferivel. `Indexed` é o que separa "não está na
// lista porque foi gasto" de "não está na lista porque o índice do endpoint não olha esse script".
// `Via` diz QUAL evidência respondeu ("lista", "contadores" ou "-"), porque as duas não têm a
// mesma força: a lista nomeia o outpoint, os contadores só conseguem falar do endereço inteiro.
internal sealed record DormantRow(int Height, long BlockTime, string Address, long Sats,
    Spentness V, bool Coinbase, string Type, bool Indexed, bool ListOk, string Via,
    int FundedCount, int SpentCount);

/// <summary>
/// Um bloco lido = duas GETs (block-height + block/txs) + uma GET por endereço distinto
/// conferido. A cache de UTXO existe porque nos blocos modernos o mesmo endereço aparece em
/// várias saídas do mesmo bloco, e cada GET a mais numa API que já nos cortou no meio de
/// um scan (429 periódico numa varredura sustentada a ~1,1 pedido/s, `docs/dormant.txt`)
/// é risco, não informação. Os contadores são Interlocked porque `--par` põe blocos em voo
/// na mesma instância: ++ perdido em corrida é exatamente o erro que transforma "conferido"
/// em número bonito.
/// </summary>
internal sealed class DormantScanner
{
    private readonly Mempool _mp;
    private readonly bool _coinbaseOnly;
    private readonly int _maxOutputsPerBlock;
    private readonly int _outputsPerTx;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, Lazy<Task<(List<Utxo>, bool, AddressStats?)>>> _utxos = new();

    public int CacheHits, DecodeAgree, DecodeDisagree;

    // Contabilidade do TETO de amostragem, não do achado: `--all` num bloco moderno são
    // milhares de saídas, e cada uma é um GET num endpoint que devolve 429 no meio de uma
    // varredura de 360 pedidos.
    // Sem declarar o que foi cortado, a frase "examinei o bloco" seria mentira; com ela, a
    // amostra é o que ela é: as primeiras N saídas candidatas de cada bloco tocado.
    public long OutputsSkipped;

    /// <summary>
    /// Endereços cuja lista de UTXOs o endpoint RECUSOU dar (teto de 500 do Esplora). É um
    /// buraco do oráculo de tipo diferente do "este script não é indexado": aqui a pergunta
    /// foi feita direito e a resposta foi "não te dou esta lista". Conta separado porque a
    /// frase honesta para os dois casos é a mesma (sem veredito) e a causa não é.
    /// </summary>
    public int ListRefusals;

    /// <summary>
    /// Linhas cujo veredito veio dos CONTADORES de `address/<a>` e não da lista de UTXOs - o
    /// remendo mediado para a recusa acima. Conta porque as duas evidências têm forças
    /// diferentes e o relatório não tem o direito de apresentá-las iguais.
    /// </summary>
    public int VerdictsFromCounters;

    public readonly List<string> DecodeBad = new();

    public DormantScanner(Mempool mp, bool coinbaseOnly, int maxOutputsPerBlock, int outputsPerTx)
    {
        _mp = mp; _coinbaseOnly = coinbaseOnly;
        _maxOutputsPerBlock = maxOutputsPerBlock; _outputsPerTx = Math.Max(1, outputsPerTx);
    }

    /// <summary>
    /// A lista de UTXOs do endereço, ou a informação de que o endpoint se recusou a dá-la.
    /// Os dois casos viram linha no relatório, mas por caminhos diferentes: recusa é resposta
    /// definitiva do servidor (fica na cache, retry só gastaria pedido), falha de rede não é
    /// (evicta, senão o erro congela na cache e o resto da corrida repete a mesma mentira).
    /// Na recusa, os contadores agregados vêm junto: eles continuam respondendo 200 quando a
    /// lista não vem, e em dois casos (ver <see cref="UtxoSet.VerdictFromCounters"/>) respondem
    /// a pergunta sem lista.
    /// </summary>
    private async Task<(List<Utxo> Utxos, bool ListOk, AddressStats? Stats)> UtxosOf(string addr)
    {
        Lazy<Task<(List<Utxo>, bool, AddressStats?)>> lazy;
        if (_utxos.TryGetValue(addr, out var cached) && cached is not null)
        {
            lazy = cached;
            System.Threading.Interlocked.Increment(ref CacheHits);
        }
        else lazy = _utxos.GetOrAdd(addr, a => new Lazy<Task<(List<Utxo>, bool, AddressStats?)>>(async () =>
        {
            try { return (await _mp.UtxosAsync(a), true, (AddressStats?)null); }
            catch (UtxoListRefusedException)
            {
                System.Threading.Interlocked.Increment(ref ListRefusals);
                AddressStats? st = null;
                try { st = await _mp.AddressAsync(a); } catch { /* sem contadores também: linha fica sem veredito */ }
                return (new List<Utxo>(), false, st);
            }
        }, System.Threading.LazyThreadSafetyMode.ExecutionAndPublication));
        try { return await lazy.Value; }
        catch { _utxos.TryRemove(addr, out _); throw; }   // falha não pode ficar congelada na cache
    }

    public async Task<List<DormantRow>> ScanBlockAsync(int h)
    {
        var local = new List<DormantRow>();
        var hash = await _mp.BlockHashAtHeightAsync(h);
        var txs = await _mp.BlockTxsAsync(hash);
        long btime = txs.Count > 0 ? txs[0].BlockTime : 0;   // vem no status da propria tx: zero round-trip extra

        // Candidatas do bloco primeiro, depois o teto. A ordem importa: assim o número de
        // "cortadas" é exato e custa zero pedidos. O teto existe porque `--all` num bloco
        // moderno são milhares de saídas, cada uma um GET num endpoint que devolve 429 no meio
        // de uma varredura de 360 pedidos; sem declarar o que ele corta, "examinei o bloco" seria uma frase
        // sobre uma amostra que não é a amostra.
        var cand = new List<(BlockTx Tx, TxOut Out)>();
        foreach (var tx in txs)
        {
            if (_coinbaseOnly && !tx.IsCoinbase) continue;
            foreach (var o in tx.Outputs.Where(o => o.Address is not null).Take(_outputsPerTx)) cand.Add((tx, o));
        }
        if (_maxOutputsPerBlock > 0 && cand.Count > _maxOutputsPerBlock)
        {
            System.Threading.Interlocked.Add(ref OutputsSkipped, cand.Count - _maxOutputsPerBlock);
            cand = cand.GetRange(0, _maxOutputsPerBlock);
        }

        foreach (var (tx, o) in cand)
        {
            var addr = o.Address!;
            // Controle gratuito do NOSSO decoder: quando o endpoint também manda o endereço,
            // os dois têm que bater. É isto que autoriza confiar no endereço que derivamos de
            // um P2PK (mesmo Hash160 + Base58Check nas duas direções), e custa zero pedidos.
            if (o.ApiAddress && o.Decoded is not null)
            {
                if (o.Decoded == addr) System.Threading.Interlocked.Increment(ref DecodeAgree);
                else
                {
                    System.Threading.Interlocked.Increment(ref DecodeDisagree);
                    lock (DecodeBad)
                        if (DecodeBad.Count < 5)
                            DecodeBad.Add($"  ! {tx.Txid[..12]}:{o.Index} endpoint {addr} | nosso decoder {o.Decoded}");
                }
            }
            var (utxos, listOk, st) = await UtxosOf(addr);
            // Três fontes possíveis de resposta, nesta ordem de força:
            //   1. a lista de UTXOs do endereço saiu -> presença/ausência decide, e a ausência
            //      só quer dizer "gasta" se o endpoint indexa o TIPO deste script (P2PK não);
            //   2. a lista foi RECUSADA (>500 saídas) -> os contadores agregados respondem em
            //      dois casos exatos (0 gastos, ou 1 saída na história e ela gasta), e só depois
            //      de o funded_txo_sum provar que comporta o valor DESTA saída;
            //   3. nenhuma das duas -> SEM VEREDITO. As três saídas têm causas diferentes e o
            //      relatório distingue; o que elas nunca produzem é "gasta" por ignorância.
            Spentness v; string via;
            if (listOk)
            {
                v = UtxoSet.Verdict(UtxoSet.Contains(utxos, tx.Txid, o.Index), o.Indexed);
                via = "lista";
            }
            else if (st is not null)
            {
                v = UtxoSet.VerdictFromCounters(st.FundedCount, st.SpentCount, st.FundedSats, o.Value);
                via = "contadores";
                if (v != Spentness.NaoConferivel) System.Threading.Interlocked.Increment(ref VerdictsFromCounters);
            }
            else { v = Spentness.NaoConferivel; via = "-"; }
            local.Add(new DormantRow(h, btime, addr, o.Value, v, tx.IsCoinbase, o.Type, o.Indexed, listOk, via,
                st?.FundedCount ?? 0, st?.SpentCount ?? 0));
        }
        return local;
    }
}
