/* Copyright 2026 Adilson Oliveira / 7dsol3. ISC license. */
#ifndef KONAET_RECEIPT_H
#define KONAET_RECEIPT_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Opaque canonical document bytes; no parsing, signing, network or key access. */
int konaet_commitment(const unsigned char salt[32], const unsigned char *document,
                      size_t length, unsigned char output[32]);
void konaet_u128_decimal(const unsigned char input[16], char output[40]);
#ifdef __cplusplus
}
#endif
#endif
