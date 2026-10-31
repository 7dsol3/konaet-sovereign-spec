// Copyright 2026 Adilson Oliveira / 7dsol3. ISC license.
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

static bool LowerHex(string text) => text.Length % 2 == 0 && text.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
try
{
    using var input = Console.OpenStandardInput();
    var bytes = new byte[32901];
    int used = 0, count;
    while (used < bytes.Length && (count = input.Read(bytes, used, bytes.Length - used)) > 0) used += count;
    if (used > 32900 || bytes.AsSpan(0, used).ContainsAnyInRange((byte)128, (byte)255)) throw new FormatException();
    var lines = Encoding.ASCII.GetString(bytes, 0, used).Split('\n');
    if (lines.Length != 4 || lines[3] != "") throw new FormatException();
    var salt = lines[0]; var document = lines[1]; var expected = lines[2];
    if (salt.Length != 64 || !LowerHex(salt) || document.Length < 4 || document.Length > 32768 || !LowerHex(document)
        || expected != "-" && (expected.Length != 64 || !LowerHex(expected))) throw new FormatException();
    using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    hash.AppendData(Encoding.ASCII.GetBytes("KONAET/SOCIAL-RECEIPT/v1\0"));
    hash.AppendData(Convert.FromHexString(salt)); hash.AppendData(Convert.FromHexString(document));
    var digest = hash.GetHashAndReset();
    var value = Convert.ToHexString(digest).ToLowerInvariant();
    bool? matches = expected == "-" ? null : CryptographicOperations.FixedTimeEquals(digest, Convert.FromHexString(expected));
    var args128 = new[] { new BigInteger(digest.AsSpan(0, 16), isUnsigned: true, isBigEndian: true).ToString(CultureInfo.InvariantCulture),
        new BigInteger(digest.AsSpan(16, 16), isUnsigned: true, isBigEndian: true).ToString(CultureInfo.InvariantCulture) };
    Console.WriteLine(JsonSerializer.Serialize(new { commitment = value, args = args128, matches }));
    return matches == false ? 1 : 0;
}
catch (Exception error) when (error is FormatException or IOException or ArgumentException)
{
    Console.Error.WriteLine("KONAET_INPUT_INVALID"); return 2;
}
