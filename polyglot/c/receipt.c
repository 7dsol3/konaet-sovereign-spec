/* Copyright 2026 Adilson Oliveira / 7dsol3. ISC license. */
#include "receipt.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

int konaet_commitment(const unsigned char salt[32], const unsigned char *document,
                      size_t length, unsigned char output[32]) {
    static const unsigned char domain[] = "KONAET/SOCIAL-RECEIPT/v1";
    EVP_MD_CTX *context;
    unsigned int size = 0;
    int ok;
    if (!salt || !document || !output || length < 2 || length > 16384) return 0;
    context = EVP_MD_CTX_new();
    if (!context) return 0;
    ok = EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1
      && EVP_DigestUpdate(context, domain, sizeof(domain)) == 1
      && EVP_DigestUpdate(context, salt, 32) == 1
      && EVP_DigestUpdate(context, document, length) == 1
      && EVP_DigestFinal_ex(context, output, &size) == 1 && size == 32;
    EVP_MD_CTX_free(context);
    return ok;
}
void konaet_u128_decimal(const unsigned char input[16], char output[40]) {
    unsigned char digits[39] = {0};
    size_t used = 1, i, j;
    for (i = 0; i < 16; i++) {
        unsigned int carry = input[i];
        for (j = 0; j < used; j++) { carry += (unsigned int)digits[j] * 256; digits[j] = (unsigned char)(carry % 10); carry /= 10; }
        while (carry) { digits[used++] = (unsigned char)(carry % 10); carry /= 10; }
    }
    for (i = 0; i < used; i++) output[i] = (char)('0' + digits[used - 1 - i]);
    output[used] = '\0';
}

#ifndef KONAET_NO_MAIN
static int nibble(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}
static int decode(const char *text, size_t length, unsigned char *output) {
    size_t i;
    if (length % 2) return 0;
    for (i = 0; i < length; i += 2) {
        int high = nibble((unsigned char)text[i]), low = nibble((unsigned char)text[i + 1]);
        if (high < 0 || low < 0) return 0;
        output[i / 2] = (unsigned char)(high * 16 + low);
    }
    return 1;
}
int main(void) {
    char frame[32902], *lines[4], value[65], high[40], low[40];
    unsigned char salt[32], document[16384], expected[32], digest[32];
    size_t size = fread(frame, 1, 32901, stdin), index, count = 1, length;
    int difference = 0, checked;
    if (ferror(stdin) || size > 32900 || memchr(frame, '\0', size)) goto invalid;
    frame[size] = '\0'; lines[0] = frame;
    for (index = 0; index < size; index++) if (frame[index] == '\n') {
        frame[index] = '\0'; if (count >= 4) goto invalid; lines[count++] = frame + index + 1;
    }
    if (count != 4 || lines[3][0] != '\0' || strlen(lines[0]) != 64 || !decode(lines[0], 64, salt)) goto invalid;
    length = strlen(lines[1]);
    if (length < 4 || length > 32768 || !decode(lines[1], length, document)) goto invalid;
    checked = strcmp(lines[2], "-") != 0;
    if (checked && (strlen(lines[2]) != 64 || !decode(lines[2], 64, expected))) goto invalid;
    if (!konaet_commitment(salt, document, length / 2, digest)) goto invalid;
    for (index = 0; index < 32; index++) {
        static const char hex[] = "0123456789abcdef";
        value[2 * index] = hex[digest[index] >> 4]; value[2 * index + 1] = hex[digest[index] & 15];
        if (checked) difference |= digest[index] ^ expected[index];
    }
    value[64] = '\0'; konaet_u128_decimal(digest, high); konaet_u128_decimal(digest + 16, low);
    if (printf("{\"commitment\":\"%s\",\"args\":[\"%s\",\"%s\"],\"matches\":%s}\n", value, high, low,
               checked ? (difference ? "false" : "true") : "null") < 0) return 2;
    return checked && difference ? 1 : 0;
invalid:
    fputs("KONAET_INPUT_INVALID\n", stderr); return 2;
}
#endif
