// Copyright 2026 Adilson Oliveira / 7dsol3. ISC license.
#include <openssl/evp.h>
#include <array>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace konaet {
std::vector<unsigned char> decode(std::string_view text) {
    if (text.size() % 2) throw std::invalid_argument("hex");
    auto digit = [](char c) -> unsigned char {
        if (c >= '0' && c <= '9') return static_cast<unsigned char>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned char>(c - 'a' + 10);
        throw std::invalid_argument("hex");
    };
    std::vector<unsigned char> bytes;
    for (std::size_t i = 0; i < text.size(); i += 2) bytes.push_back(static_cast<unsigned char>(digit(text[i]) * 16 + digit(text[i + 1])));
    return bytes;
}
std::string decimal(const unsigned char *bytes) {
    std::string number = "0";
    for (int i = 0; i < 16; ++i) {
        unsigned int carry = bytes[i];
        for (auto it = number.rbegin(); it != number.rend(); ++it) {
            carry += static_cast<unsigned int>(*it - '0') * 256;
            *it = static_cast<char>('0' + carry % 10); carry /= 10;
        }
        while (carry) { number.insert(number.begin(), static_cast<char>('0' + carry % 10)); carry /= 10; }
    }
    return number;
}
std::array<unsigned char, 32> commitment(const std::vector<unsigned char>& salt, const std::vector<unsigned char>& document) {
    if (salt.size() != 32 || document.size() < 2 || document.size() > 16384) throw std::invalid_argument("length");
    const char domain[] = "KONAET/SOCIAL-RECEIPT/v1";
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    std::array<unsigned char, 32> digest{}; unsigned int size = 0;
    if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1
        || EVP_DigestUpdate(ctx.get(), domain, sizeof(domain)) != 1
        || EVP_DigestUpdate(ctx.get(), salt.data(), salt.size()) != 1
        || EVP_DigestUpdate(ctx.get(), document.data(), document.size()) != 1
        || EVP_DigestFinal_ex(ctx.get(), digest.data(), &size) != 1 || size != digest.size()) throw std::runtime_error("digest");
    return digest;
}
}
int main() {
    try {
        std::string frame; char byte;
        while (frame.size() < 32901 && std::cin.get(byte)) frame.push_back(byte);
        if (frame.size() > 32900 || std::cin.bad()) throw std::invalid_argument("input");
        std::vector<std::string> lines; std::size_t begin = 0;
        for (std::size_t i = 0; i < frame.size(); ++i) if (frame[i] == '\n') { lines.push_back(frame.substr(begin, i - begin)); begin = i + 1; }
        if (lines.size() != 3 || begin != frame.size() || lines[0].size() != 64 || lines[1].size() < 4 || lines[1].size() > 32768) throw std::invalid_argument("frame");
        const auto digest = konaet::commitment(konaet::decode(lines[0]), konaet::decode(lines[1]));
        bool checked = lines[2] != "-"; unsigned char different = 0;
        if (checked) {
            if (lines[2].size() != 64) throw std::invalid_argument("expected");
            const auto expected = konaet::decode(lines[2]);
            for (std::size_t i = 0; i < digest.size(); ++i) different |= digest[i] ^ expected[i];
        }
        const char hex[] = "0123456789abcdef"; std::string value;
        for (auto item : digest) { value.push_back(hex[item >> 4]); value.push_back(hex[item & 15]); }
        std::cout << "{\"commitment\":\"" << value << "\",\"args\":[\"" << konaet::decimal(digest.data()) << "\",\""
                  << konaet::decimal(digest.data() + 16) << "\"],\"matches\":" << (checked ? (different ? "false" : "true") : "null") << "}\n";
        return checked && different ? 1 : 0;
    } catch (const std::exception&) { std::cerr << "KONAET_INPUT_INVALID\n"; return 2; }
}
