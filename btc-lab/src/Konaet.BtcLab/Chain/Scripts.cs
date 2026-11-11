using Konaet.BtcLab.Core;

namespace Konaet.BtcLab.Chain;

/// <summary>
/// Decodes the scriptPubKey shapes the early chain actually used. The mempool.space
/// block endpoints hand back raw hex for P2PK outputs (Satoshi-era coinbases), so the
/// address has to be computed here - which is also a nice end-to-end exercise of the
/// lab's own Hash160/Base58Check code.
///
/// Bech32 (P2WPKH/P2WSH) and Pay-to-Taproot are recognised but not converted to an
/// address string: none of them existed in the blocks this lab samples, and adding a
/// bech32 encoder is a separate, unrelated chunk of work.
/// </summary>
public static class Scripts
{
    public static (string? Address, string Kind) Decode(string scriptPubKeyHex)
    {
        if (scriptPubKeyHex.Length == 0) return (null, "vazio");
        byte[] s;
        try { s = Convert.FromHexString(scriptPubKeyHex); }
        catch (FormatException) { return (null, "hex inválido"); }

        // P2PKH: 76 a9 14 <20 bytes> 88 ac
        if (s.Length == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 && s[23] == 0x88 && s[24] == 0xac)
            return (BtcHash.Base58CheckEncode(0x00, s.AsSpan(3, 20)), "p2pkh");

        // P2PK: <push 33 ou 65> <pubkey> ac
        if (s.Length >= 2 && s[0] is 0x21 or 0x41 && s[^1] == 0xac && s.Length == s[0] + 2)
            return (BtcHash.AddressFromPublicKey(s.AsSpan(1, s[0])), "p2pk");

        return (null, Classify(s));
    }

    private static string Classify(byte[] s)
    {
        if (s.Length == 22 && s[0] == 0x00 && s[1] == 0x14) return "p2wpkh (nada decodificado)";
        if (s.Length == 34 && s[0] == 0x00 && s[1] == 0x20) return "p2wsh (nada decodificado)";
        if (s.Length == 34 && s[0] == 0x51 && s[1] == 0x20) return "p2tr (nada decodificado)";
        if (s.Length == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[^1] == 0x87) return "p2sh";
        if (s.Length > 0 && s[0] == 0x6a) return "op_return";
        if (s.Length > 0 && s[^1] == 0xae) return "multisig";
        return $"outro ({s.Length} B)";
    }
}
