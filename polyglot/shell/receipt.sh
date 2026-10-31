#!/bin/sh
# Copyright 2026 Adilson Oliveira / 7dsol3. ISC license.
# Shell entry point for the compiled C implementation. No eval, network or keys.
set -eu
if [ "$#" -ne 1 ] || [ ! -f "$1" ] || [ ! -x "$1" ]; then
  printf '%s\n' 'Usage: sh polyglot/shell/receipt.sh /absolute/path/to/konaet-receipt-c' >&2
  exit 2
fi
case "$1" in /*) exec "$1" ;; *) printf '%s\n' 'An absolute executable path is required' >&2; exit 2 ;; esac
