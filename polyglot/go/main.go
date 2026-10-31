// Copyright 2026 Adilson Oliveira / 7dsol3. ISC license.
package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
)

func invalid() { fmt.Fprintln(os.Stderr, "KONAET_INPUT_INVALID"); os.Exit(2) }
func lowerHex(s string) bool {
	for _, c := range []byte(s) { if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') { return false } }
	return len(s)%2 == 0
}
func main() {
	frame, err := io.ReadAll(io.LimitReader(os.Stdin, 32901))
	if err != nil || len(frame) > 32900 { invalid() }
	lines := strings.Split(string(frame), "\n")
	if len(lines) != 4 || lines[3] != "" { invalid() }
	salt, document, expected := lines[0], lines[1], lines[2]
	if len(salt) != 64 || !lowerHex(salt) || len(document) < 4 || len(document) > 32768 || !lowerHex(document) || (expected != "-" && (len(expected) != 64 || !lowerHex(expected))) { invalid() }
	saltBytes, _ := hex.DecodeString(salt); docBytes, _ := hex.DecodeString(document)
	h := sha256.New(); h.Write([]byte("KONAET/SOCIAL-RECEIPT/v1\x00")); h.Write(saltBytes); h.Write(docBytes)
	digest := h.Sum(nil); value := hex.EncodeToString(digest)
	var matches *bool
	if expected != "-" { decoded, _ := hex.DecodeString(expected); ok := subtle.ConstantTimeCompare(digest, decoded) == 1; matches = &ok }
	result := struct { Commitment string `json:"commitment"`; Args []string `json:"args"`; Matches *bool `json:"matches"` }{
		value, []string{new(big.Int).SetBytes(digest[:16]).String(), new(big.Int).SetBytes(digest[16:]).String()}, matches,
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil { os.Exit(2) }
	if matches != nil && !*matches { os.Exit(1) }
}
