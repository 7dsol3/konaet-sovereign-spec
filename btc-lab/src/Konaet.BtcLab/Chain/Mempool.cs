using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Konaet.BtcLab.Chain;

/// <summary>
/// O caderno de quais endereços IP do pool já nos enrolaram.
///
/// Fato medido nesta máquina em 2026-11-08, às 06:31 (UTC-3), quando o scan parou de funcionar
/// enquanto `curl` continuava funcionando: `mempool.space` resolve para UM POOL DE 9 ENDEREÇOS
/// (103.165.192.200..208) e ligar na porta 443 de três deles (…200, …203, …206) não é recusado
/// - é ENXO: o SYN sai e nada responde até o cronômetro. Os outros seis respondem 200 em ~0,5s.
/// Um HttpClient que dá um orçamento de conexão para a OPERAÇÃO inteira (o `ConnectTimeout` do
/// SocketsHttpHandler) gasta os 10s no endereço morto e nunca chega no vivo; por isso o sintoma
/// é "TaskCanceledException sem inner, 0 GET, retry atrás de retry" exatamente quando o DNS
/// sorteia um endereço ruim primeiro - e por isso ele parecia aleatório entre uma hora e outra.
///
/// A regra fica aqui, separada do socket, porque é ela que dá para conferir sem rede: endereço
/// suspeito vai para o FIM da fila (ordem estável: sem suspeita, o que o DNS respondeu é o que
/// se tenta, na ordem) e volta a ser tentado depois do cooldown - um IP ruim pode sarar, e um
/// IP bom pode ser rebaixado para sempre se a lista não expirar.
/// </summary>
internal sealed class ConnectHealth
{
    private readonly ConcurrentDictionary<string, DateTime> _suspectUntil = new();
    private readonly int _cooldownSeconds;
    private readonly Func<DateTime> _now;

    public ConnectHealth(int cooldownSeconds = 300, Func<DateTime>? now = null)
    {
        _cooldownSeconds = cooldownSeconds;
        _now = now ?? (static () => DateTime.UtcNow);
    }

    public bool IsSuspect(IPAddress a) =>
        _suspectUntil.TryGetValue(a.ToString(), out var until) && _now() < until;

    public void MarkSuspect(IPAddress a) => _suspectUntil[a.ToString()] = _now().AddSeconds(_cooldownSeconds);

    public void Clear(IPAddress a) => _suspectUntil.TryRemove(a.ToString(), out _);

    /// <summary>Boons primeiro, na ordem do DNS; suspeitos depois, também na ordem do DNS.</summary>
    public IPAddress[] Order(IEnumerable<IPAddress> addrs) =>
        addrs.OrderBy(a => IsSuspect(a) ? 1 : 0).ToArray();   // OrderBy é estável: é o que dá para prometer
}

public sealed record AddressStats(long FundedSats, long SpentSats, int FundedCount, int SpentCount, int TxCount)
{
    public long UnspentSats => FundedSats - SpentSats;
    public double UnspentBtc => UnspentSats / 1e8;
}

public sealed record Utxo(string Txid, int Vout, long ValueSats, int BlockHeight, long BlockTime);

/// <summary>
/// O endpoint respondeu, e a resposta foi "esta lista eu não te dou" (teto de 500 UTXOs por
/// endereço no Esplora). Não é falha de rede - retry não muda nada - e não é "a saída foi
/// gasta": é o oráculo sem leitura para aquela consulta. Quem consulta <c>address/&lt;a&gt;/utxo</c>
/// tem que tratar isso como terceiro caso, porque as duas leituras erradas possíveis são
/// caras: "então não está parado" (afirma gasto sem prova) e "rede fora" (esconde o teto).
/// </summary>
public sealed class UtxoListRefusedException : Exception
{
    public string Path { get; }
    public UtxoListRefusedException(string path, string body)
        : base($"o endpoint recusa a lista de UTXOs de {path} (>{500} saídas): {Trunc(body)}")
        => Path = path;

    private static string Trunc(string s) => s.Length <= 90 ? s : s[..90] + "...";
}

/// <summary>
/// O veredito de um outpoint, com a honestidade embutida no tipo. As três linhas existem porque
/// "não está na lista do endpoint" só significa "gasta" se a lista PODE conter aquela saída -
/// e o índice de endereço deste deployment não contém P2PK (medido 2026-11-08: o coinbase do
/// bloco 33 tem scriptpubkey_type "p2pk", não vem com scriptpubkey_address, e os 9 UTXOs do
/// endereço derivado dele são poeira de 2019, com spent_txo_count = 0). Chamar isso de "gasta"
/// é transformar um buraco do índice em conclusão sobre a moeda de outra pessoa.
/// </summary>
public enum Spentness { Intacta, Gasta, NaoConferivel }

public static class UtxoSet
{
    /// <summary>
    /// O predicado de "esta saída ainda está aí?". Ele decide sozinho se o laboratório escreve
    /// AINDA NO LUGAR ou "já foi movida", então as duas coisas que ele precisa garantir são
    /// chatas e são o ponto: comparar txid sem depender de qual caixa o servidor resolveu usar,
    /// e comparar vout como número (não como string, não por ordem de lista). Um txid que
    /// batesse em 66 dos 64 caracteres por causa de maiúscula viraria "não está" para tudo - e o
    /// erro seria silencioso, porque a frase errada é a mais plausível de todas.
    /// </summary>
    public static bool Contains(IEnumerable<Utxo> utxos, string txid, int vout)
    {
        if (string.IsNullOrEmpty(txid)) return false;
        foreach (var u in utxos)
            if (u.Vout == vout && string.Equals(u.Txid, txid, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    /// <summary>
    /// Os dois sinais juntos: estar na lista (ou estar em lista de terceiros, o que também é
    /// prova de que o outpoint existe ali) = Intacta; não estar numa lista que PODE conter a
    /// saída = Gasta; não estar numa lista que não contém esse tipo de script = NaoConferivel.
    /// Separado em função porque é aqui, e só aqui, que a palavra "gasta" é autorizada a existir.
    /// </summary>
    public static Spentness Verdict(bool presentInUtxoList, bool oracleCanSeeThisOutput) =>
        presentInUtxoList ? Spentness.Intacta
        : oracleCanSeeThisOutput ? Spentness.Gasta
        : Spentness.NaoConferivel;

    /// <summary>
    /// A segunda régua, para quando a LISTA de UTXOs não veio (o endpoint recusou, teto de 500).
    /// Os contadores agregados de `address/<a>` continuam respondendo 200, e em dois casos eles
    /// respondem a nossa pergunta sem lista nenhuma:
    ///   spent_txo_count == 0            -> nenhuma saída JÁ FOI CONSUMIDA deste endereço, então
    ///                                      a nossa, que existe, está no lugar;
    ///   funded_txo_count == 1 && spent>0 -> só houve UMA saída para este endereço na história e
    ///                                      ela foi gasta; como a nossa existe, é ela.
    /// Nos outros casos (endereço com muitas saídas e gastos parciais) o agregado não identifica
    /// QUAL saiu, e a resposta continua SEM VEREDITO. Medido 2026-11-08: o endereço da gênesis
    /// tem funded_txo_count 83.441 / spent_txo_count 0 - /utxo recusa (>500) e os contadores
    /// dizem, com certeza, que nunca saiu um satoshi dali.
    ///
    /// O `fundedSats >= outSats` não é decorativo: é o que impede a régua de falar de uma saída
    /// que o índice daquele endereço nem contém. O agregado de `address/<a>` é soma sobre o que
    /// AQUELE deployment indexa; se ele não comporta o valor da nossa saída, ele não está falando
    /// dela, e responder "0 gastos => intacta" seria a mesma categoria de erro que chamar ausência
    /// de P2PK de gasto. No coinbase da gênesis o corte passa com folga: funded_txo_sum
    /// 57,70718386 BTC >= 50 BTC da saída (medido no mesmo `address/<a>`), ou seja, os 50 BTC
    /// estão dentro do que o endpoint somou.
    /// </summary>
    public static Spentness VerdictFromCounters(int fundedCount, int spentCount, long fundedSats, long outSats) =>
        fundedCount == 0 ? Spentness.NaoConferivel          // nada recebido: o agregado não fala de nada
        : fundedSats < outSats ? Spentness.NaoConferivel    // a soma nem comporta esta saída
        : spentCount == 0 ? Spentness.Intacta               // nada jamais saiu deste endereço
        : fundedCount == 1 ? Spentness.Gasta                // a única que existiu aqui foi consumida
        : Spentness.NaoConferivel;                          // parcial: não se sabe QUAL saída saiu
}

public sealed record TxOut(string? Address, long Value, int Index, string Type, bool ApiAddress, string? Decoded)
{
    /// <summary>
    /// O endpoint devolveu um endereço para esta saída? Se sim, ela vive no índice de endereço
    /// dele e a lista de UTXOs daquele endereço é um oráculo válido. Se não (P2PK), o endereço
    /// que usamos aqui veio do NOSSO decoder de script - certo ou errado, ele não é a chave do
    /// índice alheio, então ausência na lista não prova gasto nenhum.
    /// </summary>
    public bool Indexed => ApiAddress && Address is not null;
}

public sealed record BlockTx(string Txid, bool IsCoinbase, List<TxOut> Outputs, long BlockTime);

/// <summary>Uma transação confirmada vista do lado de um endereço: o que entrou e o que saiu.</summary>
public sealed record AddrTx(string Txid, long BlockTime, int BlockHeight, long InSats, long OutSats)
{
    public string BlockDate => BlockTime == 0 ? "-" : DateTimeOffset.FromUnixTimeSeconds(BlockTime).ToString("yyyy-MM-dd");
}

/// <summary>
/// Janela de histórico lida de um endereço, com a contabilidade da leitura: quantas linhas a
/// API devolveu, quantas eram a mesma tx outra vez, e quantas txs de verdade ficaram. É o que
/// permite escrever "li as N mais novas de M" em vez de "este é o histórico".
/// </summary>
public sealed record AddressHistory(List<AddrTx> Txs, int RawRows, int DuplicateRows)
{
    public override string ToString() =>
        $"{Txs.Count} txs distintas ({RawRows} linhas lidas, {DuplicateRows} duplicata(s) de paginação cortada(s))";
}

/// <summary>
/// Read-only mempool.space REST client. It can look, never touch: there is no
/// transaction construction, signing or broadcasting anywhere in this lab, and the
/// base URL is plain public chain data.
///
/// The endpoint is shared public infrastructure, and it does throttle: a first
/// parallel `dormant` run (4 workers x 0,15 s de pausa *por worker* = ~26 pedidos/s)
/// encheu a saída de "HTTP 429" e depois de conexão cortada. Então o limite mora
/// aqui, não no chamador: um *token bucket* global (um pedido a cada
/// <paramref name="minIntervalSeconds"/> × o ritmo adaptativo, independente de quantos
/// workers pedem em paralelo) mais backoff exponencial em 429/5xx/timeout. `--par` muda
/// quantos blocos estão em voo, nunca a velocidade com que o servidor é consultado.
///
/// Medido nesta máquina (2026-11-08, `docs/rate-probe.txt`): 20 GETs sequenciais a 1,0s de
/// intervalo, 20 a 0,4s, 40 a 0,25s e 48 conexões SIMULTÂNEAS em `block-height/H` deram
/// HTTP 200 em todos, com ~0,5s cada, sem um único 429. Na mesma tarde, o scan de 120 blocos
/// (360 GETs em 346s, que além de `block-height` bate em `block/<hash>/txs` e
/// `address/*`) levou 9 x HTTP 429, um a cada ~38s (linha "traffic do servidor" em
/// `docs/dormant.txt`). Ou seja: o 429 não é uma função do nosso
/// ritmo em um endpoint barato — é estado do servidor, e ele não avisa qual é a taxa "certa".
/// Daí o default de 0,8s (piso global) + AIMD: se aparecer 429, o processo inteiro dobra o
/// intervalo em vez de insistir. O que a medição sustenta é a escolha de piso + AIMD, não um
/// número mágico de pedidos/s.
/// </summary>
public sealed class Mempool : IAsyncDisposable
{
    private readonly HttpClient _http;
    private readonly SemaphoreSlim _turn = new(1, 1);
    private readonly double _minIntervalSeconds;
    private DateTime _nextAllowed = DateTime.MinValue;

    private int _requests;
    private int _retries;
    private int _throttled;
    private int _failures;
    private int _refusals;

    /// <summary>Multiplicador de ritmo (AIMD): ×2 a cada 429/falha consecutiva, ÷1,05 quando dá bom.</summary>
    private double _pace = 1.0;

    /// <summary>Pedios atendidos (200) / retry / 429 / falha definitiva / recusa de lista / ritmo atual.</summary>
    public (int Requests, int Retries, int Throttled, int Failed, int Refusals, double Pace) Stats =>
        (Volatile.Read(ref _requests), Volatile.Read(ref _retries), Volatile.Read(ref _throttled),
         Volatile.Read(ref _failures), Volatile.Read(ref _refusals), Volatile.Read(ref _pace));

    /// <summary>
    /// A assinatura da recusa do Esplora. Fato separado do `throw` para o selftest poder
    /// conferir o reconhecimento da frase sem rede: o que está em jogo é uma palavra que
    /// aparece no corpo, e uma regressão aqui transforma "não sei" em "foi gasta".
    /// </summary>
    public static bool IsUtxoListRefusal(string? body) =>
        body is not null && body.Contains("Too many unspent transaction outputs", StringComparison.OrdinalIgnoreCase);

    public Mempool(string baseUrl = "https://mempool.space/api", double minIntervalSeconds = 0.8)
    {
        _minIntervalSeconds = Math.Max(minIntervalSeconds, 0);

        // KONAET_LAB_PLAIN_HTTP=1 volta ao HttpClient default, sem SocketsHttpHandler - serve
        // para separar "o servidor nos cortou" de "a nossa configuração de conexão está errada"
        // (ver README, seção do rate limit: os dois sintomas aparecem iguais na saída).
        // Medido 2026-11-08: NEM UM NEM OUTRO - era um IP morto no pool de DNS (ver ConnectHealth).
        var plain = Environment.GetEnvironmentVariable("KONAET_LAB_PLAIN_HTTP") == "1";
        var handler = plain
            ? null
            : new SocketsHttpHandler
            {
                PooledConnectionLifetime = TimeSpan.FromSeconds(30),
                PooledConnectionIdleTimeout = TimeSpan.FromSeconds(15),
                // Sem ConnectTimeout: o orçamento passa a ser POR ENDEREÇO (PerAddressConnectSeconds
                // abaixo), porque com um orçamento por operação os ~0,5s de um endereço bom ficam
                // atrás dos 10s de espera de um endereço que só engole SYN - e o pedido morre antes
                // de a vez dele chegar. Foi exatamente o que quebrou o scan desta máquina.
                ConnectCallback = ConnectAsync,
            };
        _http = handler is null
            ? new HttpClient { BaseAddress = new Uri(baseUrl + "/"), Timeout = TimeSpan.FromSeconds(15) }
            : new HttpClient(handler, disposeHandler: true) { BaseAddress = new Uri(baseUrl + "/"), Timeout = TimeSpan.FromSeconds(15) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("konaet-btc-lab/1.0 (read-only research)");
        _http.DefaultRequestHeaders.Accept.ParseAdd("application/json");
    }

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Orçamento de conexão POR endereço do DNS: o bastante para um RTT bom (~0,5s medido)
    /// e curto o suficiente para um SYN engolido não custar o pedido inteiro.</summary>
    internal const double PerAddressConnectSeconds = 4.0;

    private static readonly ConnectHealth Health = new();

    /// <summary>
    /// Connects to the endpoint one DNS address at a time, each with its own budget, and keeps a
    /// notebook of which addresses just stalled. This exists because on 2026-11-08 the scan here
    /// started failing every request with a bare TaskCanceledException (0 GETs counted, so no
    /// server answer at all) while plain `curl` kept returning 200 in 0,5 s - and the difference
    /// was not the server, the UA or TLS: three of the nine IPs that `mempool.space` resolves to
    /// (…200, …203, …206) drop SYN to :443 instead of refusing it, and the framework's
    /// per-operation ConnectTimeout expired inside the dead one before the live ones were tried.
    /// </summary>
    private static async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext ctx, CancellationToken ct)
    {
        string host = ctx.DnsEndPoint.Host;
        IPAddress[] addrs;
        try
        {
            addrs = Health.Order(await Dns.GetHostAddressesAsync(host, ct));
        }
        catch (Exception ex)
        {
            throw new HttpRequestException($"nao resolvi {host}: {ex.GetType().Name}: {ex.Message}", ex);
        }
        if (addrs.Length == 0) throw new HttpRequestException($"nenhum endereco de IP para {host}");

        var why = new List<string>();
        foreach (var a in addrs)
        {
            ct.ThrowIfCancellationRequested();
            var sock = new Socket(a.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            using var one = CancellationTokenSource.CreateLinkedTokenSource(ct);
            one.CancelAfter(TimeSpan.FromSeconds(PerAddressConnectSeconds));
            try
            {
                await sock.ConnectAsync(a, ctx.DnsEndPoint.Port, one.Token);
                Health.Clear(a);
                return new NetworkStream(sock, ownsSocket: true);
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException)
            {
                if (ct.IsCancellationRequested) { sock.Dispose(); throw; }   // foram NÓS que cancelamos
                Health.MarkSuspect(a);
                why.Add($"{a}={(ex is OperationCanceledException ? "sem-resposta" : ((SocketException)ex).SocketErrorCode.ToString())}");
                sock.Dispose();
            }
        }
        throw new HttpRequestException($"conexao falhou nos {addrs.Length} endereco(s) de {host}: {string.Join(" ", why)}");
    }

    private const int MaxRetries = 4;

    /// <summary>Só o que dá para tentar de novo: o servidor ocupado, nos cortando, ou o timeout.</summary>
    private static bool Transient(Exception ex, CancellationToken ct) =>
        ex is HttpRequestException || (ex is TaskCanceledException && !ct.IsCancellationRequested);

    private static TimeSpan Backoff(int attempt, double? retryAfterSeconds) =>
        retryAfterSeconds is { } s
            ? TimeSpan.FromSeconds(Math.Clamp(s, 1, 60))
            : TimeSpan.FromSeconds(2.0 * Math.Pow(2, attempt));   // 2s, 4s, 8s, 16s

    /// <summary>Fila global: segura o slot até a próxima janela, então quem chega em paralelo espera.</summary>
    private async Task WaitForMyTurnAsync(CancellationToken ct)
    {
        await _turn.WaitAsync(ct);
        try
        {
            var wait = _nextAllowed - DateTime.UtcNow;
            if (wait > TimeSpan.Zero) await Task.Delay(wait, ct);
            _nextAllowed = DateTime.UtcNow.AddSeconds(_minIntervalSeconds * Volatile.Read(ref _pace));
        }
        finally { _turn.Release(); }
    }

    /// <summary>
    /// AIMD, o mesmo truque do TCP: se o endpoint devolveu 429 (ou cortou a conexão), o
    /// ritmo do processo inteiro dobra de intervalo - `--par` nenhum consegue ignorar isso.
    /// Em resposta boa o ritmo volta devagar (÷1,05), para não ficar oscilando na borda.
    /// </summary>
    private void SlowDown()
    {
        var newPace = Math.Min(Volatile.Read(ref _pace) * 2, 32);
        Volatile.Write(ref _pace, newPace);
    }

    private void SpeedUp()
    {
        var p = Volatile.Read(ref _pace);
        if (p > 1.0) Volatile.Write(ref _pace, Math.Max(1.0, p / 1.05));
    }

    private async Task<HttpResponseMessage> SendAsync(string path, CancellationToken ct)
    {
        for (int attempt = 0; ; attempt++)
        {
            await WaitForMyTurnAsync(ct);

            HttpResponseMessage resp;
            try
            {
                resp = await _http.GetAsync(path, HttpCompletionOption.ResponseHeadersRead, ct);
            }
            catch (Exception ex) when (Transient(ex, ct))
            {
                if (attempt == MaxRetries)
                {
                    Interlocked.Increment(ref _failures);
                    // "TaskCanceledException" sozinho não diz nada; o inner diz se foi TLS, RST
                    // ou o cronômetro. Sem isso a gente passa a noite adivinhando (adivinhamos).
                    var why = ex.InnerException is { } inner ? $"{ex.GetType().Name}: {ex.Message} | inner {inner.GetType().Name}: {inner.Message}"
                                                             : $"{ex.GetType().Name}: {ex.Message}";
                    throw new HttpRequestException($"falha de rede em {path} apos {attempt + 1} tentativa(s): {why}", ex);
                }
                Interlocked.Increment(ref _retries);
                SlowDown();
                await Task.Delay(Backoff(attempt, null), ct);
                continue;
            }

            if (resp.IsSuccessStatusCode)
            {
                Interlocked.Increment(ref _requests);
                SpeedUp();
                return resp;
            }

            int code = (int)resp.StatusCode;
            double? retryAfter = resp.Headers.RetryAfter is { } ra && ra.Delta is { } d ? d.TotalSeconds : null;
            // O corpo diz mais que o código. Um HTTP 400 aqui pode ser "endereço que não
            // existe" (aí a consulta não tem leitura nenhuma) ou o Esplora dizendo que a lista
            // daquela consulta estourou o teto dele - e essa segunda frase é o ORÁCULO dizendo
            // "não te dou esta resposta", não "esta saída foi gasta". Medido 2026-11-08 em
            // address/3Eif1JfqeMERRsQHtvGEacNN9hhuvnsfe9/utxo: 400 + corpo
            // "Too many unspent transaction outputs (>500). Contact support to raise limits."
            // (o mesmo endereço responde 200 em address/<a> com funded_txo_count 4.929).
            string? body = null;
            try { body = await resp.Content.ReadAsStringAsync(ct); } catch { /* corpo é diagnóstico */ }
            resp.Dispose();
            if (code == 400 && IsUtxoListRefusal(body))
            {
                Interlocked.Increment(ref _refusals);
                throw new UtxoListRefusedException(path, body!);
            }
            if (code == 429) Interlocked.Increment(ref _throttled);
            if (attempt == MaxRetries || (code != 429 && code < 500))
            {
                Interlocked.Increment(ref _failures);
                throw new HttpRequestException($"HTTP {code} em {path}" +
                    (attempt > 0 ? $" (apos {attempt} retry(s))" : ""));
            }
            Interlocked.Increment(ref _retries);
            SlowDown();
            await Task.Delay(Backoff(attempt, retryAfter), ct);
        }
    }

    private async Task<T> GetJsonAsync<T>(string path, CancellationToken ct)
    {
        using var resp = await SendAsync(path, ct);
        var stream = await resp.Content.ReadAsStreamAsync(ct);
        return (await JsonSerializer.DeserializeAsync<T>(stream, Json, ct))!;
    }

    private async Task<string> GetStringAsync(string path, CancellationToken ct)
    {
        using var resp = await SendAsync(path, ct);
        return await resp.Content.ReadAsStringAsync(ct);
    }

    public async Task<AddressStats> AddressAsync(string address, CancellationToken ct = default)
    {
        var doc = JsonDocument.Parse(await GetStringAsync($"address/{address}", ct));
        var chain = doc.RootElement.GetProperty("chain_stats");
        return new AddressStats(
            chain.GetProperty("funded_txo_sum").GetInt64(),
            chain.GetProperty("spent_txo_sum").GetInt64(),
            chain.GetProperty("funded_txo_count").GetInt32(),
            chain.GetProperty("spent_txo_count").GetInt32(),
            chain.GetProperty("tx_count").GetInt32());
    }

    public async Task<List<Utxo>> UtxosAsync(string address, CancellationToken ct = default)
    {
        var raw = await GetJsonAsync<List<RawUtxo>>($"address/{address}/utxo", ct);
        return raw.Select(u => new Utxo(u.Txid!, u.Vout, u.Value, u.Status?.BlockHeight ?? 0, u.Status?.BlockTime ?? 0))
                  .OrderByDescending(u => u.ValueSats).ToList();
    }

    public async Task<string> BlockHashAtHeightAsync(int height, CancellationToken ct = default) =>
        (await GetStringAsync($"block-height/{height}", ct)).Trim();


    /// <summary>Timestamp (unix seconds) and size of a block, by hash.</summary>
    public async Task<(long Timestamp, int TxCount)> BlockInfoAsync(string hash, CancellationToken ct = default)
    {
        var info = await GetJsonAsync<RawBlock>($"block/{hash}", ct);
        return (info.Timestamp ?? 0, info.TxCount ?? 0);
    }

    /// <summary>
    /// Transactions of a block. mempool.space does not send an address for P2PK outputs
    /// (Satoshi-era coinbases are raw 65-byte public keys), so the address is rebuilt
    /// here from the scriptPubKey with the lab's own hash160 + Base58Check code.
    ///
    /// A reconstrução é nossa e o índice é deles: quando o endpoint não mandou
    /// `scriptpubkey_address`, o endereço que sai daqui serve para mostrar a linha, mas NÃO
    /// serve de chave para perguntar "gastou?". É por isso que `ApiAddress` via junto - sem
    /// esse bit, todo coinbase P2PK da era Satoshi vira "já foi movida" por construção.
    /// </summary>
    public async Task<List<BlockTx>> BlockTxsAsync(string hash, CancellationToken ct = default)
    {
        var raw = await GetJsonAsync<List<RawTx>>($"block/{hash}/txs", ct);
        return raw.Select(t => new BlockTx(
            t.Txid!,
            t.Vin?.Any(v => v.IsCoinbase ?? (v.Txid == null || v.Vout == 4294967295L)) ?? true,
            (t.Vout ?? new List<RawVout>())
                .Select((o, index) =>
                {
                    var (addr, kind) = Scripts.Decode(o.ScriptPubKey ?? "");
                    return new TxOut(o.Address ?? addr, o.Value, index, o.ScriptType ?? kind, o.Address is not null, addr);
                })
                .ToList(),
            t.Status?.BlockTime ?? 0))
            .ToList();
    }

    /// <summary>Altura e hora do bloco que incluiu a txid (0/0 se ainda não confirmada).</summary>
    public async Task<(int Height, long Time)> TxStatusAsync(string txid, CancellationToken ct = default)
    {
        var raw = await GetJsonAsync<RawTx>($"tx/{txid}", ct);
        return (raw.Status?.BlockHeight ?? 0, raw.Status?.BlockTime ?? 0);
    }

    /// <summary>
    /// Histórico confirmado de um endereço: quanto entrou, quanto saiu e em que bloco.
    /// É isto que separa "conta abandonada" de "conta quieta": a data em que o saldo se
    /// mexeu pela última vez está na chain, e não em lista de terceiros.
    /// Paginação por `after`: cada chamada devolve as 25 transações mais novas.
    ///
    /// A fronteira do `after=<txid>` pode sobrepor páginas, e um endereço reusado pode gastar
    /// moedas que voltou a receber. Somado sem cuidado, o "total saído" de um endereço passa do
    /// que ele nunca recebeu - que é o artefato que fazia `docs/moves.txt` antigo listar mais
    /// saídas do que o prêmio. Então: dedupa por txid, e devolve a contabilidade nua (linhas
    /// cruas, duplicatas cortadas) para o chamador poder dizer "li X de Y, a janela é um corte"
    /// em vez de fingir histórico completo. O que a sobreposição realmente foi fica no número,
    /// não na hipótese.
    /// </summary>
    public async Task<AddressHistory> AddressTxsAsync(string address, int pages = 1, CancellationToken ct = default)
    {
        var all = new List<AddrTx>();
        var seen = new HashSet<string>();
        int raw = 0, dup = 0;
        string? after = null;
        for (int p = 0; p < pages; p++)
        {
            var rows = await GetJsonAsync<List<RawTx>>($"address/{address}/txs" + (after is null ? "" : $"?after={after}"), ct);
            if (rows.Count == 0) break;
            raw += rows.Count;
            foreach (var t in rows)
            {
                if (!seen.Add(t.Txid ?? "")) { dup++; continue; }
                long inn = (t.Vout ?? new List<RawVout>()).Where(o => o.Address == address).Sum(o => o.Value);
                long outt = (t.Vin ?? new List<RawVin>()).Where(v => v.Prevout?.Address == address).Sum(v => v.Prevout!.Value);
                all.Add(new AddrTx(t.Txid!, t.Status?.BlockTime ?? 0, t.Status?.BlockHeight ?? 0, inn, outt));
            }
            after = rows[^1].Txid;
            if (rows.Count < 25) break;
        }
        return new AddressHistory(all, raw, dup);
    }

    /// <summary>Preço spot em USD do agregador público (mempool.space), com o carimbo de tempo dele.</summary>
    public async Task<(long Time, double Usd)> PriceUsdAsync(CancellationToken ct = default)
    {
        var p = await GetJsonAsync<RawPrices>("v1/prices", ct);
        return (p.Time ?? 0, p.Usd ?? 0);
    }

    public ValueTask DisposeAsync()
    {
        _http.Dispose();
        _turn.Dispose();
        return default;
    }

    // ---- wire types ----

    private sealed class RawBlock
    {
        public long? Timestamp { get; set; }
        [JsonPropertyName("tx_count")] public int? TxCount { get; set; }
    }

    private sealed class RawPrices
    {
        public long? Time { get; set; }
        public double? Usd { get; set; }
    }

    private sealed class RawUtxo
    {
        public string? Txid { get; set; }
        public int Vout { get; set; }
        public long Value { get; set; }
        public RawStatus? Status { get; set; }
    }

    private sealed class RawStatus
    {
        // os nomes vêm com snake_case da API: sem [JsonPropertyName] o binding silencioso
        // deixa tudo em 0 (foi o "utxo em 1970-01-01" que apareceu no puzzles --live).
        [JsonPropertyName("block_height")] public int? BlockHeight { get; set; }
        [JsonPropertyName("block_time")] public long? BlockTime { get; set; }
        [JsonPropertyName("confirmed")] public bool? Confirmed { get; set; }
    }

    private sealed class RawVin
    {
        public string? Txid { get; set; }
        public long Vout { get; set; }          // coinbase usa 4294967295: não cabe em int
        [JsonPropertyName("is_coinbase")] public bool? IsCoinbase { get; set; }
        public RawPrevout? Prevout { get; set; }
    }

    /// <summary>O que estava sendo gasto: mempool.space repete o scriptPubKey do output de origem.</summary>
    private sealed class RawPrevout
    {
        [JsonPropertyName("scriptpubkey_address")] public string? Address { get; set; }
        public long Value { get; set; }
    }

    private sealed class RawVout
    {
        public long Value { get; set; }
        // o campo se chama scriptpubkey_address, e ele NÃO vem para P2PK (era esse o
        // "0 saídas" do dormant nos blocos do Satoshi) - daí o decoder local no Scripts.
        [JsonPropertyName("scriptpubkey_address")] public string? Address { get; set; }
        [JsonPropertyName("scriptpubkey")] public string? ScriptPubKey { get; set; }
        [JsonPropertyName("scriptpubkey_type")] public string? ScriptType { get; set; }
    }

    private sealed class RawTx
    {
        public string? Txid { get; set; }
        public RawStatus? Status { get; set; }
        public List<RawVin>? Vin { get; set; }
        public List<RawVout>? Vout { get; set; }
    }
}
