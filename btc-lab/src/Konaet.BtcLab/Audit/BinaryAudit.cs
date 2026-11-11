using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;

namespace Konaet.BtcLab.Audit;

/// <summary>
/// Binary-level red-line audit.
///
/// Everything else in this repository proves the read-only promise by READING SOURCE.
/// Source is not what runs. This class proves the same promise at the artifact: it parses
/// the compiled PE (MS-DOS header -> PE header -> section table -> CLI header -> metadata
/// root -> stream directory -> #Strings / #US heaps and the ECMA-335 tables) and asks the
/// only question that can decide a claim like "this tool cannot move coins":
///
///     which external members does the compiled code reference, at all?
///
/// ECMA-335 makes that decidable without disassembling: a call into another assembly MUST
/// go through a MemberRef row, so the MemberRef table is the complete external call
/// surface of the module. The two ways around it are covered explicitly: P/Invoke
/// (MethodAttributes.PinvokeImpl + ModuleRef) and late binding (Type.GetType,
/// MethodBase.Invoke, Assembly.Load, Activator.CreateInstance) which is reported as a
/// warning rather than a pass, because reflection is exactly the hole an auditor should
/// not paper over.
///
/// It is also a general tool: `audit --exe <path>` runs the same rules over somebody
/// else's binary - including native ones, where the managed tables do not exist and the
/// honest surface is the PE import table. Parsing does not execute: nothing here loads the
/// target as an assembly, so auditing a stranger's DLL cannot run its module initializer.
/// </summary>
public static class BinaryAudit
{
    // ---------------------------------------------------------------- regras

    /// <summary>Padrão com '*' em qualquer ponta, comparação sem diferenciar maiúscula.</summary>
    private static bool Like(string s, string pat)
    {
        if (pat == "*") return true;
        if (pat.Length > 1 && pat[0] == '*' && pat[^1] == '*')
            return s.Contains(pat[1..^1], StringComparison.OrdinalIgnoreCase);
        if (pat.Length > 1 && pat[^1] == '*') return s.StartsWith(pat[..^1], StringComparison.OrdinalIgnoreCase);
        if (pat.Length > 1 && pat[0] == '*') return s.EndsWith(pat[1..], StringComparison.OrdinalIgnoreCase);
        return string.Equals(s, pat, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Uma regra = uma capacidade que daria ao binário o poder de mover fundos de terceiro.
    /// <c>Types</c> casa com "Namespace.NomeTipo"; <c>Members</c> casa com o nome do membro
    /// referenciado ("*" = a simples menção ao tipo já é a capacidade).
    /// </summary>
    public sealed record Rule(string Id, string Capability, string[] Types, string[] Members, bool WarnOnly = false);

    /// <summary>
    /// Casa (tipo, membro) contra uma regra do mesmo jeito que <see cref="Inspect"/> faz -
    /// exposto porque o selftest precisa rodar o controle NEGATIVO. Uma regra que pega
    /// <c>GetAsync</c> não é linha vermelha, é ruído: transformaria o "0 violações" do
    /// <c>audit</c> num 0 por construção, que é exatamente a mentira que a bandeira promete
    /// não contar.
    /// </summary>
    public static bool Matches(Rule rule, string type, string member) =>
        rule.Types.Any(t => Like(type, t)) && rule.Members.Any(m => Like(member, m));

    public static readonly Rule[] Rules =
    {
        new("corpo", "anexar corpo a um pedido HTTP - é assim que uma transação montada sai",
            new[] { "System.Net.Http.StringContent", "System.Net.Http.ByteArrayContent",
                    "System.Net.Http.StreamContent", "System.Net.Http.FormUrlEncodedContent",
                    "System.Net.Http.Multipart*" }, new[] { "*" }),

        new("verbo", "usar verbo HTTP que escreve (POST/PUT/PATCH/DELETE/Send)",
            new[] { "System.Net.Http.HttpClient" },
            new[] { "Post*", "Put*", "Patch*", "Delete*", "Send*" }),

        new("pedido", "construir pedido não-GET ou com corpo (set_Method / set_Content)",
            new[] { "System.Net.Http.HttpRequestMessage" }, new[] { "set_Content", "set_Method" }),

        new("metodo", "referenciar o tipo HttpMethod em si - só existe se houver verbo além de GET",
            new[] { "System.Net.Http.HttpMethod" }, new[] { "*" }),

        new("socket", "enviar bytes por soquete (transmitir tx, ou falar com outro serviço)",
            new[] { "System.Net.Sockets.Socket" },
            new[] { "Send", "SendAsync", "BeginSend", "EndSend", "SendTo", "SendToAsync", "Shutdown", "Disconnect" }),

        new("escrita-tls", "escrever num stream TLS (mesma coisa, um degrau acima do soquete)",
            new[] { "System.Net.Security.SslStream" }, new[] { "Write*", "AuthenticateAsClient*" }),

        new("assinar", "assinar com EC/DSA/RSA - ou seja, usar chave privada que não é a nossa",
            new[] { "System.Security.Cryptography.ECDsa", "System.Security.Cryptography.DSA",
                    "System.Security.Cryptography.ECDiffieHellman", "System.Security.Cryptography.RSA" },
            new[] { "Sign*", "ImportEC*", "ImportFromEncrypted*", "ExportParameters", "ExportEncrypted*" }),

        new("disco", "escrever em disco (chave, segredo, qualquer artefato que o projeto não produz)",
            new[] { "System.IO.File" },
            new[] { "Write*", "Append*", "Create*", "Move*", "Copy*", "Delete*", "Replace*" }),

        new("escrita-stream", "stream de escrita / abrir arquivo num modo que não é leitura",
            new[] { "System.IO.StreamWriter", "System.IO.BinaryWriter", "System.IO.FileStream",
                    "System.IO.FileInfo", "System.IO.UnmanagedMemoryStream" }, new[] { "*" }),

        new("processo", "executar outro programa (node, bitcoind, python, script de outra pessoa)",
            new[] { "System.Diagnostics.Process", "System.Diagnostics.ProcessStartInfo" }, new[] { "*" }),

        new("carteira", "biblioteca pronta de carteira/PSBT/BIP32 - o atalho para gastar",
            new[] { "NBitcoin*", "*PSBT*", "*BIP32*", "*Mnemonic*", "*Wallet*" }, new[] { "*" }),

        new("reflexao", "late binding: chama o que não está no MemberRef (fuga do grafo, não uso comprovado)",
            new[] { "System.Type", "System.Reflection.MethodBase", "System.Reflection.MethodInfo",
                    "System.Reflection.Assembly", "System.Activator" },
            new[] { "GetType", "Invoke", "InvokeMember", "Load", "LoadFrom", "CreateInstance*" }, WarnOnly: true),
    };

    /// <summary>
    /// Vocabulário de quem gasta bitcoin, procurado nos heaps de nome (#Strings) e de
    /// literais (#US). Ocorrência no #US pode ser a própria lista abaixo - o código marca
    /// esse caso em vez de fingir que é limpo.
    /// </summary>
    public static readonly string[] DenyWords =
    {
        "sendrawtransaction", "signrawtransaction", "walletpassphrase", "dumpwallet", "backupwallet",
        "importprivkey", "importaddress", "signpsbt", "walletcreatefundedpsbt", "upgradewallet",
        "sendmany", "sendtoaddress", "getrawchangeaddress", "listunspent", "descriptor", "multipath",
        "mnemonic", "seedphrase", "wallet.dat", "privkey", "bitcoind", "electrum", "pkh(", "sh(wpkh",
    };

    // ---------------------------------------------------------------- o que se extrai

    public sealed record Hit(string Type, string Member, string RuleId);

    public sealed class Summary
    {
        public string Path = "";
        public long Bytes;
        public string Sha256 = "";
        public bool HasMetadata;
        public string Machine = "", Subsystem = "", MetadataVersion = "", CorFlags = "", TargetFramework = "";
        public bool Authenticode, StrongName;
        public Guid Mvid;
        public string ModuleName = "", AssemblyName = "", AssemblyVersion = "";
        public int TimeDateStamp;
        public readonly List<string> AssemblyRefs = new();
        public readonly List<string> Attributes = new();
        public int TypeDefs, MethodDefs, MemberRefRows, TypeRefRows, ILBytes, StringHeapBytes, UserHeapBytes;
        public int NoBody, BadBodies, Bodies;
        public readonly List<string> PInvokes = new();
        public readonly List<string> NativeModules = new();
        public readonly List<string> NativeImports = new();
        public readonly List<Hit> Forbidden = new();
        public readonly List<Hit> Warnings = new();
        public readonly List<(string Heap, string Text, string Word)> WordHits = new();
        public List<string> SocketSurface = new();
        public List<string> HttpSurface = new();
        public List<string> IoSurface = new();
        public List<string> CryptoSurface = new();
        public List<(string Type, int Members)> TopTypes = new();

        /// <summary>Zero referência proibida no grafo. É isto que a linha vermelha virou.</summary>
        public bool Clean => Forbidden.Count == 0;

        public DateTime BuiltAt =>
            TimeDateStamp == 0 ? DateTime.UnixEpoch : DateTime.UnixEpoch.AddSeconds(TimeDateStamp);
    }

    /// <summary>Lê o arquivo e analisa. Não carrega o alvo como assembly, não executa nada.</summary>
    public static Summary Inspect(string path)
    {
        var s = new Summary { Path = path };
        var bytes = File.ReadAllBytes(path);
        s.Bytes = bytes.Length;
        s.Sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

        using var ms = new MemoryStream(bytes, writable: false);
        using var pe = new PEReader(ms);
        var headers = pe.PEHeaders;
        var coff = headers.CoffHeader;
        var peh = headers.PEHeader!;
        s.Machine = coff.Machine.ToString();
        s.Subsystem = peh.Subsystem.ToString();
        s.TimeDateStamp = unchecked((int)coff.TimeDateStamp);
        s.Authenticode = peh.CertificateTableDirectory.Size > 0;
        bool pe32Plus = peh.Magic == PEMagic.PE32Plus;

        Func<int, int> rva2off = rva =>
        {
            foreach (var sh in headers.SectionHeaders)
            {
                int size = Math.Max(sh.VirtualSize, sh.SizeOfRawData);
                if (rva >= sh.VirtualAddress && rva < sh.VirtualAddress + size)
                    return sh.PointerToRawData + (rva - sh.VirtualAddress);
            }
            return -1;
        };

        // ---- import table NATIVA: a superfície real de um PE sem metadata gerenciada
        var impDir = peh.ImportTableDirectory;
        if (impDir.Size > 0 && rva2off(impDir.RelativeVirtualAddress) >= 0)
        {
            int stride = pe32Plus ? 8 : 4;
            for (int desc = rva2off(impDir.RelativeVirtualAddress); desc + 20 <= bytes.Length; desc += 20)
            {
                int ilt = ReadI32(bytes, desc), nameRva = ReadI32(bytes, desc + 12), thunk = ReadI32(bytes, desc + 16);
                if (ilt == 0 && nameRva == 0 && thunk == 0) break;
                string dll = ReadZ(bytes, rva2off(nameRva));
                if (dll.Length == 0) break;
                int first = ilt != 0 ? ilt : thunk;
                int fo = rva2off(first);
                for (int n = 0; fo >= 0 && n < 4096; fo += stride, n++)
                {
                    long val = pe32Plus ? (uint)ReadI32(bytes, fo) | ((long)(uint)ReadI32(bytes, fo + 4) << 32)
                                        : (uint)ReadI32(bytes, fo);
                    // bit de ordem: 63 num PE32+, 31 num PE32
                    bool ordinal = pe32Plus ? val < 0 : (val & 0x8000_0000L) != 0;
                    if (ordinal) { s.NativeImports.Add($"{dll}#!ordinal{val & 0xFFFF}"); continue; }
                    int nrva = (int)(val & 0x7FFF_FFFF);
                    if (nrva == 0) break;
                    int noff = rva2off(nrva);
                    if (noff < 0) break;
                    s.NativeImports.Add($"{dll}!{ReadZ(bytes, noff + 2)}");
                }
            }
        }

        if (!pe.HasMetadata) return s;

        var cor = pe.PEHeaders.CorHeader!;
        s.CorFlags = cor.Flags.ToString();
        s.StrongName = cor.StrongNameSignatureDirectory.Size > 0;

        // ---- metadata root: assinatura "BSJB", versão, e o diretório de heaps
        int metaOff = rva2off(cor.MetadataDirectory.RelativeVirtualAddress);
        int streamsStart = -1, heapCount = 0;
        if (metaOff >= 0 && ReadI32(bytes, metaOff) == 0x424A5342)
        {
            int vl = ReadI32(bytes, metaOff + 12);
            streamsStart = metaOff + 16 + vl;
            heapCount = ReadU16(bytes, streamsStart + 2);
        }
        (int off, int size) FindHeap(string name)
        {
            if (streamsStart < 0) return (-1, 0);
            int p = streamsStart + 4;
            for (int i = 0; i < heapCount; i++)
            {
                int ho = ReadI32(bytes, p), hs = ReadI32(bytes, p + 4);
                p += 8;
                var sb = new StringBuilder();
                while (p < bytes.Length && bytes[p] != 0) sb.Append((char)bytes[p++]);
                p++;
                while ((p - streamsStart) % 4 != 0) p++;
                if (sb.ToString() == name) return (metaOff + ho, hs);
            }
            return (-1, 0);
        }
        var (strHeap, strSize) = FindHeap("#Strings");
        var (usHeap, usSize) = FindHeap("#US");
        s.StringHeapBytes = Math.Max(strSize, 0);
        s.UserHeapBytes = Math.Max(usSize, 0);

        var r = pe.GetMetadataReader();
        s.HasMetadata = true;
        s.MetadataVersion = r.MetadataVersion;
        var mod = r.GetModuleDefinition();
        s.Mvid = r.GetGuid(mod.Mvid);
        s.ModuleName = r.GetString(mod.Name);
        var asm = r.GetAssemblyDefinition();
        s.AssemblyName = r.GetString(asm.Name);
        s.AssemblyVersion = asm.Version.ToString();
        foreach (var arh in r.AssemblyReferences)
        {
            var ar = r.GetAssemblyReference(arh);
            s.AssemblyRefs.Add($"{r.GetString(ar.Name)} {ar.Version}");
        }
        foreach (var cah in asm.GetCustomAttributes())
        {
            var ca = r.GetCustomAttribute(cah);
            string ctor = DescribeParent(r, ca.Constructor);
            // o valor é um blob [prolog | tipo | SerString]; em vez de assumir o layout,
            // recorto as sequências imprimíveis - é o que quebra a cabeça de quem faz RE de
            // attribute binário pela primeira vez, então mostro as duas coisas no --attrs.
            var frags = PrintableFragments(r.GetBlobBytes(ca.Value));
            s.Attributes.Add($"{ctor,-52} :: {string.Join(" | ", frags.Take(3))}");
            if (!ctor.Contains("TargetFrameworkAttribute", StringComparison.OrdinalIgnoreCase)) continue;
            s.TargetFramework = frags.FirstOrDefault(f => f.Contains(",Version=", StringComparison.OrdinalIgnoreCase))
                              ?? frags.FirstOrDefault(f => f.Contains("Version", StringComparison.OrdinalIgnoreCase)) ?? "";
        }

        // ---- tamanho do grafo
        s.TypeDefs = r.TypeDefinitions.Count;
        s.TypeRefRows = r.TypeReferences.Count;
        s.MemberRefRows = r.MemberReferences.Count;
        s.MethodDefs = r.MethodDefinitions.Count;
        foreach (var mdh in r.MethodDefinitions)
        {
            var m = r.GetMethodDefinition(mdh);
            // P/Invoke é a única forma de o módulo chamar código nativo: ImplAttributes
            // carrega a flag e GetImport() diz o dll + a função. A tabela ModuleRef não é
            // exposta pelo MetadataReader, então contamos as entradas e juntamos os dlls.
            if ((m.Attributes & MethodAttributes.PinvokeImpl) != 0)
            {
                var imp = m.GetImport();
                s.PInvokes.Add(r.GetString(imp.Name));
                s.NativeModules.Add(r.GetString(r.GetModuleReference(imp.Module).Name));
            }
            // O RVA do MethodDef traz nos 2 bits baixos a codificação do corpo, e o
            // PEReader espera o RVA CRU (ele mesmo faz a máscara). Medido neste dll:
            // passando `rva & ~3` sobram 71 "Invalid method header" em 721 métodos;
            // passando o RVA cru, 0. O erro aparece porque a contagem de corpos é
            // impressa - ela existe para denunciar exatamente isso.
            int rva = m.RelativeVirtualAddress;
            if (rva == 0) { s.NoBody++; continue; }
            try
            {
                var body = pe.GetMethodBody(rva);
                if (body is not null)
                {
                    s.Bodies++;
                    s.ILBytes += body.GetILReader().Length;
                }
                else s.NoBody++;
            }
            catch (BadImageFormatException) { s.BadBodies++; }
        }

        // ---- o grafo externo completo
        var memberCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var memberHits = new List<(string type, string member)>();
        var typeMentions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var mrh in r.MemberReferences)
        {
            var mr = r.GetMemberReference(mrh);
            string type = DescribeParent(r, mr.Parent);
            string member = r.GetString(mr.Name);
            memberHits.Add((type, member));
            memberCounts[type] = memberCounts.GetValueOrDefault(type) + 1;
        }
        foreach (var trh in r.TypeReferences) typeMentions.Add(ShortTypeName(r, r.GetTypeReference(trh)));

        s.TopTypes = memberCounts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key, StringComparer.Ordinal)
                                .Select(kv => (kv.Key, kv.Value)).ToList();

        foreach (var (type, member) in memberHits)
        {
            foreach (var rule in Rules)
            {
                if (!Matches(rule, type, member)) continue;
                (rule.WarnOnly ? s.Warnings : s.Forbidden).Add(new Hit(type, member, rule.Id));
            }
            // superfície transparente: o que toca rede, disco e cripto, mesmo quando passa
            if (type.StartsWith("System.Net.Sockets", StringComparison.OrdinalIgnoreCase))
                s.SocketSurface.Add($"{type}::{member}");
            else if (type.StartsWith("System.Net", StringComparison.OrdinalIgnoreCase))
                s.HttpSurface.Add($"{type}::{member}");
            if (type.StartsWith("System.IO", StringComparison.OrdinalIgnoreCase)) s.IoSurface.Add($"{type}::{member}");
            if (type.StartsWith("System.Security", StringComparison.OrdinalIgnoreCase)) s.CryptoSurface.Add($"{type}::{member}");
        }
        // regra de tipo-nível (Members == "*") também vale para menção sem membro
        foreach (var type in typeMentions)
            foreach (var rule in Rules.Where(x => !x.WarnOnly && x.Members.Contains("*")))
                if (rule.Types.Any(t => Like(type, t)))
                    s.Forbidden.Add(new Hit(type, "(menção ao tipo, sem membro)", rule.Id));

        s.SocketSurface = Distinct(s.SocketSurface);
        s.HttpSurface = Distinct(s.HttpSurface);
        s.IoSurface = Distinct(s.IoSurface);
        s.CryptoSurface = Distinct(s.CryptoSurface);

        // ---- vocabulário de carteira nos dois heaps
        if (strHeap >= 0)
            foreach (var name in SplitZ(bytes, strHeap, strSize))
                foreach (var w in DenyWords.Where(w => name.Contains(w, StringComparison.OrdinalIgnoreCase)))
                    s.WordHits.Add(("#Strings", name, w));
        if (usHeap >= 0)
        {
            int p = usHeap + 2, end = Math.Min(usHeap + usSize, bytes.Length);
            while (p + 1 < end)
            {
                int b0 = bytes[p], len;
                if ((b0 & 0x80) == 0) { len = b0; p += 1; }
                else { len = ((b0 & 0x3F) << 8) | bytes[p + 1]; p += 2; }
                if (len < 2 || p + len > end) break;
                string lit = Encoding.Unicode.GetString(bytes, p, len - 1);
                p += len;
                foreach (var w in DenyWords.Where(w => lit.Contains(w, StringComparison.OrdinalIgnoreCase)))
                    s.WordHits.Add(("#US", lit, w));
            }
        }
        return s;
    }

    private static List<string> Distinct(List<string> x) => x.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(s => s, StringComparer.Ordinal).ToList();

    private static string DescribeParent(MetadataReader r, EntityHandle parent) => parent.Kind switch
    {
        HandleKind.TypeReference => ShortTypeName(r, r.GetTypeReference((TypeReferenceHandle)parent)),
        HandleKind.TypeDefinition => r.GetString(r.GetTypeDefinition((TypeDefinitionHandle)parent).Name),
        // o construtor de um custom attribute É um MemberRef: quem importa é o pai dele.
        // Sem este caso, --attrs mostraria "memberreference" para tudo e a auditoria não
        // distinguiria TargetFrameworkAttribute de DebuggableAttribute - que é o erro que
        // fez o campo "alvo" nascer vazio.
        HandleKind.MemberReference => DescribeParent(r, r.GetMemberReference((MemberReferenceHandle)parent).Parent),
        HandleKind.MethodDefinition => r.GetString(r.GetMethodDefinition((MethodDefinitionHandle)parent).Name),
        HandleKind.ModuleReference => "module:" + r.GetString(r.GetModuleReference((ModuleReferenceHandle)parent).Name),
        HandleKind.TypeSpecification => TypeSpecName(r, (TypeSpecificationHandle)parent),
        _ => parent.Kind.ToString().ToLowerInvariant(),
    };

    /// <summary>
    /// Um MemberRef pode ter como pai um TypeSpec (instantiação genérica: List&lt;byte&gt;,
    /// Task&lt;X&gt;...). Deixar isso como "(typespec)" seria um buraco no grafo: a chamada
    /// existe, mas ficaria cega para as regras. O blob de assinatura começa com
    /// ELEMENT_TYPE_GENERICINST (0x15) e o container vem como TYPEDEF/TYPEREF + token.
    /// </summary>
    private static string TypeSpecName(MetadataReader r, TypeSpecificationHandle h)
    {
        try
        {
            var br = r.GetBlobReader(r.GetTypeSpecification(h).Signature);
            if (br.ReadByte() != 0x15) return "(typespec não-genérico)";   // ELEMENT_TYPE_GENERICINST
            byte inner = br.ReadByte();
            if (inner is not (0x11 or 0x12)) return "(typespec)";           // VALUE_TYPE | CLASS
            // o que vem é um TypeDefOrRefEncoded: valor = (linha << 2) | tabela
            // 0=TypeDef, 1=TypeRef, 2=TypeSpec. Tratar o número como linha direta foi o
            // bug que fazia 555 referências genéricas ficarem cegas no grafo.
            int encoded = br.ReadCompressedInteger();
            int row = encoded >> 2;
            return (encoded & 3) switch
            {
                0 => r.GetString(r.GetTypeDefinition(MetadataTokens.TypeDefinitionHandle(row)).Name),
                1 => ShortTypeName(r, r.GetTypeReference(MetadataTokens.TypeReferenceHandle(row))),
                2 => "(instantiação de typespec)",
                _ => "(typespec)",
            };
        }
        catch { return "(typespec)"; }
    }

    private static string ShortTypeName(MetadataReader r, TypeReference tr)
    {
        string ns = r.GetString(tr.Namespace), nm = r.GetString(tr.Name);
        return ns.Length == 0 ? nm : $"{ns}.{nm}";
    }

    private static int ReadI32(byte[] b, int i) => i >= 0 && i + 4 <= b.Length ? BitConverter.ToInt32(b, i) : 0;
    private static int ReadU16(byte[] b, int i) => i >= 0 && i + 2 <= b.Length ? BitConverter.ToUInt16(b, i) : 0;

    private static string ReadZ(byte[] b, int off)
    {
        if (off < 0 || off >= b.Length) return "";
        int e = off;
        while (e < b.Length && b[e] != 0) e++;
        return Encoding.ASCII.GetString(b, off, e - off);
    }

    private static IEnumerable<string> SplitZ(byte[] b, int off, int size)
    {
        int end = Math.Min(off + size, b.Length), start = off + 1;   // byte 0 reservado no início
        for (int i = start; i < end; i++)
            if (b[i] == 0)
            {
                if (i > start) yield return Encoding.UTF8.GetString(b, start, i - start);
                start = i + 1;
            }
    }

    private static List<string> PrintableFragments(byte[] blob)
    {
        var list = new List<string>();
        var cur = new StringBuilder();
        foreach (byte b in blob)
        {
            if (b >= 0x20 && b < 0x7F) cur.Append((char)b);
            else { if (cur.Length > 3) list.Add(cur.ToString()); cur.Clear(); }
        }
        if (cur.Length > 3) list.Add(cur.ToString());
        return list;
    }

    private static string Clip(string s, int n) => s.Length <= n ? s : s[..n] + "...";

    // ---------------------------------------------------------------- impressão

    public static void Run(Dictionary<string, string> opt)
    {
        string target = opt.TryGetValue("exe", out var e) ? e : typeof(BinaryAudit).Assembly.Location;
        if (!File.Exists(target))
        {
            Console.WriteLine($"  não achei o arquivo: {target}");
            Console.WriteLine("  o default é o NOSSO dll compilado - build primeiro:");
            Console.WriteLine("      dotnet build -c Release src/Konaet.BtcLab");
            Console.WriteLine("  binário de outra pessoa:");
            Console.WriteLine("      audit --exe <caminho do .dll ou .exe> [--surface N]");
            return;
        }
        Print(Inspect(target), opt.TryGetValue("surface", out var sv) ? OptInt(sv) : 14,
              opt.ContainsKey("attrs"));
    }

    public static void Print(Summary s, int surface, bool showAttrs = false)
    {
        Console.WriteLine($"arquivo   : {s.Path}");
        Console.WriteLine($"tamanho   : {s.Bytes:N0} bytes   sha256 {s.Sha256}");
        Console.WriteLine($"PE        : {s.Machine}, {s.Subsystem}, TimeDateStamp 0x{unchecked((uint)s.TimeDateStamp):X8} " +
                          $"= lido como relógio daria {s.BuiltAt:yyyy-MM-dd HH:mm:ss} UTC");
        if (!s.HasMetadata)
        {
            // O apphost é um template PRÉ-COMPILADO que o SDK só copia e assina com o
            // caminho do assembly: aqui o carimbo é do template (medido: 2023-11-30),
            // não do nosso fonte. É o caso em que a frase do bloco de cima seria mentira.
            Console.WriteLine("            (PE sem código gerenciado: este carimbo é o do template do SDK,");
            Console.WriteLine("             copiado para o lado do dll. Nem relógio do fonte, nem hash dele.)");
        }
        else if (Math.Abs((DateTime.UtcNow - s.BuiltAt).TotalDays) > 400)
        {
            Console.WriteLine("            (não leia isso como data: num assembly do SDK o TimeDateStamp vem");
            Console.WriteLine("             do build determinístico, e é derivado do conteúdo, não do relógio.");
            Console.WriteLine("             Medido neste projeto: `--no-incremental` sobre o mesmo fonte deu o");
            Console.WriteLine("             mesmo sha256. A identidade de qualquer artefato abaixo é o sha256.)");
        }
        Console.WriteLine($"assinatura: Authenticode {(s.Authenticode ? "PRESENTE" : "AUSENTE")}, " +
                          $"nome forte {(s.StrongName ? "presente" : "ausente")} - " +
                          (s.Authenticode
                              ? "uma chave de editor prova QUEM assinou, não O QUE roda: o que vale aqui é o sha256"
                              : "a identidade deste artefato é o sha256 acima, não uma chave de editor"));
        if (s.HasMetadata)
        {
            Console.WriteLine($"metadata  : {s.MetadataVersion} [{s.CorFlags}]");
            Console.WriteLine($"modulo    : {s.ModuleName}  MVID {s.Mvid}");
            Console.WriteLine($"assembly  : {s.AssemblyName} {s.AssemblyVersion}   alvo: {s.TargetFramework}");
        }
        else
        {
            Console.WriteLine("metadata  : AUSENTE - este PE não carrega código gerenciado (é a casca do");
            Console.WriteLine("            apphost). O .NET dele está no .dll ao lado; aqui só resta a");
            Console.WriteLine("            superfície nativa, logo abaixo.");
        }
        Console.WriteLine();

        Console.WriteLine($"== import table nativa: {s.NativeImports.Count} função(ões)");
        if (s.NativeImports.Count == 0) Console.WriteLine("  0 - nenhuma dll nativa importada");
        else
        {
            foreach (var g in s.NativeImports.GroupBy(x => x.Split('!')[0]).OrderByDescending(g => g.Count()))
                Console.WriteLine($"  {g.Key,-36} {g.Count(),4}");
            Console.WriteLine($"  primeiras: {string.Join(", ", s.NativeImports.Take(4))}");
        }
        Console.WriteLine();

        if (!s.HasMetadata) { Verdict(s); return; }

        Console.WriteLine("== assemblies que este binário pode carregar");
        foreach (var a in s.AssemblyRefs.OrderBy(x => x, StringComparer.Ordinal)) Console.WriteLine($"  {a}");
        if (showAttrs)
        {
            Console.WriteLine("  -- attrs: custom attributes do assembly (o valor vem do blob #Blob; abaixo os");
            Console.WriteLine("     fragmentos imprimíveis recortados dele, que é como se acha o alvo real):");
            foreach (var a in s.Attributes) Console.WriteLine($"     {a}");
        }
        Console.WriteLine();

        Console.WriteLine("== grafo de imports gerenciado (ECMA-335: chamar fora EXIGE linha no MemberRef)");
        Console.WriteLine($"  TypeDef {s.TypeDefs,6}   MethodDef {s.MethodDefs,6}   IL {s.ILBytes,8:N0} bytes   " +
                          $"#Strings {s.StringHeapBytes,7:N0}   #US {s.UserHeapBytes,7:N0}");
        Console.WriteLine($"  TypeRef {s.TypeRefRows,6}   MemberRef {s.MemberRefRows,6}   P/Invoke {s.PInvokes.Count,4}");
        Console.WriteLine(s.PInvokes.Count == 0
            ? "  -> nenhuma porta nativa (0 P/Invoke): o que roda é gerenciado e está listado abaixo"
            : "  -> ATENÇÃO: há P/Invoke; o grafo gerenciado NÃO diz o que essas funções fazem");
        Console.WriteLine($"  corpos: {s.Bodies} com IL lida, {s.NoBody} sem corpo (RVA 0), {s.BadBodies} ilegível(is)" +
                          (s.BadBodies == 0 ? "  -> o grafo abaixo é fechado: cada linha é uma linha de tabela, não uma inferência" : ""));
        if (s.NativeModules.Count > 0)
            Console.WriteLine($"     dlls nativas invocadas: {string.Join(", ", s.NativeModules.Distinct())}");
        foreach (var p in s.PInvokes.Take(8)) Console.WriteLine($"     {p}");
        Console.WriteLine();

        Console.WriteLine($"== linha vermelha, regra por regra  ({s.Forbidden.Count} violação(ões), " +
                          $"{s.Warnings.Count} aviso(s))");
        foreach (var rule in Rules)
        {
            var hits = s.Forbidden.Concat(s.Warnings).Where(h => h.RuleId == rule.Id).ToList();
            string tag = rule.WarnOnly ? (hits.Count > 0 ? "AVISO " : "ok    ")
                                       : (hits.Count > 0 ? "VIOLA " : "ok    ");
            Console.WriteLine($"  [{tag}] {rule.Id,-15} {Clip(rule.Capability, 60),-60} {hits.Count,4}");
            foreach (var h in hits.Take(4)) Console.WriteLine($"            -> {h.Type}::{h.Member}");
        }
        Console.WriteLine();

        Console.WriteLine("== superfície por área (o que o grafo menciona de verdade, incluindo o que passa)");
        PrintGroup("soquete         ", s.SocketSurface);
        PrintGroup("http            ", s.HttpSurface);
        PrintGroup("arquivo/stream  ", s.IoSurface);
        PrintGroup("criptografia    ", s.CryptoSurface);
        Console.WriteLine("  leitura: as linhas acima são a superfície CRUA. Ela inclui o que a auditoria usa");
        Console.WriteLine("  para existir (PEReader/MetadataReader, FileStream, SHA256). Hash não assina:");
        Console.WriteLine("  SHA256 amassa bytes em mão única; o que assina é ECDsa/Sign*, e essas duas");
        Console.WriteLine("  linhas estão em 0 na tabela de regras. Seria isto, e não o hash, que precisaria");
        Console.WriteLine("  estar zerado para dizer que o binário não encosta em chave privada de ninguém.");
        Console.WriteLine();

        Console.WriteLine($"== os tipos mais chamados (membros referenciados por tipo; --surface N amplia; N={surface})");
        foreach (var (t, n) in s.TopTypes.Take(surface)) Console.WriteLine($"  {n,4}  {t}");
        Console.WriteLine();

        Console.WriteLine($"== vocabulário de carteira nos heaps de string: {s.WordHits.Count} ocorrência(s)");
        foreach (var g in s.WordHits.GroupBy(x => (x.Heap, x.Text, x.Word)).Take(16))
        {
            // texto IDÊNTICO a um padrão = a auditoria se encontrando a si mesma no #US.
            // qualquer outro texto é um achado, e é ele que teria que ser explicado.
            bool selfRef = DenyWords.Contains(g.Key.Text.Trim(), StringComparer.OrdinalIgnoreCase);
            Console.WriteLine($"  {g.Key.Heap,-9} \"{Clip(g.Key.Text, 54)}\"  [{g.Key.Word}]" +
                              (selfRef ? "   <- é um dos PADRÕES desta auditoria" : "   <- FORA da lista: explicar"));
        }
        if (s.WordHits.Count == 0)
            Console.WriteLine("  0 - nenhuma string do binário usa o vocabulário de quem gasta bitcoin");
        else
        {
            Console.WriteLine("  (o #US deste binário contém a própria lista de padrões da auditoria, então");
            Console.WriteLine("   ocorrência marcada como padrão é esperada. O que preocuparia seria uma");
            Console.WriteLine("   marcada FORA da lista - aí o vocabulário de carteira existiria de fato.)");
        }
        Console.WriteLine();

        Verdict(s);
    }

    private static void PrintGroup(string label, List<string> items)
    {
        Console.WriteLine($"  {label}{items.Count,3} distinta(s)");
        foreach (var i in items.Take(12)) Console.WriteLine($"        {i}");
        if (items.Count > 12) Console.WriteLine($"        ... {items.Count - 12} mais");
    }

    private static void Verdict(Summary s)
    {
        Console.WriteLine("== veredito");
        if (s.HasMetadata && s.Clean)
        {
            Console.WriteLine($"  {Path.GetFileName(s.Path)} não referencia NENHUMA primitiva que moveria fundos");
            Console.WriteLine("  de terceiro. Não é adjetivo nem intenção: são 0 linhas no MemberRef, e o");
            Console.WriteLine("  MemberRef é a única porta de saída legal de um módulo ECMA-335.");
        }
        else if (s.HasMetadata)
        {
            Console.WriteLine($"  VIOLAÇÃO: {s.Forbidden.Count} referência(s) proibida(s) no grafo de imports.");
            foreach (var h in s.Forbidden.Take(12)) Console.WriteLine($"    {h.RuleId}: {h.Type}::{h.Member}");
        }
        else Console.WriteLine("  sem metadata gerenciado: o veredito só alcança a casca nativa deste arquivo.");
        if (s.Warnings.Count > 0)
        {
            Console.WriteLine($"  ressalva: {s.Warnings.Count} referência(s) de late binding. Com reflexão o");
            Console.WriteLine("  grafo deixa de ser fechamento completo - ver as linhas AVISO acima.");
        }
        Console.WriteLine();
        Console.WriteLine("  o que isto PROVA: dado este arquivo, o que ele pode chamar. Sem executar nada -");
        Console.WriteLine("  por isso mesmo serve para auditar o binário DE OUTRA pessoa antes de roda-lo:");
        Console.WriteLine("  `audit --exe <caminho>`.");
        Console.WriteLine("  o que NÃO prova: (a) o que o SERVIDOR faz com o que a gente pede; (b) um assembly");
        Console.WriteLine("  carregado por nome em tempo de execução; (c) o que um binário NATIVO faz além das");
        Console.WriteLine("  suas imports; (d) o seu sistema operacional, nem o node, nem o python do vizinho.");
        Console.WriteLine("  e nada disto é caminho para chave de terceiro: engenharia reversa de binário não");
        Console.WriteLine("  recupera chave privada. O piso é aritmético, está em `bench` e em");
        Console.WriteLine("  tools/ecdlp_floor.awk - e é exatamente por isso que os puzzles publicam intervalos.");
    }

    private static int OptInt(string s) =>
        (int)long.Parse(s.Trim().Replace(",", ""), System.Globalization.CultureInfo.InvariantCulture);
}
