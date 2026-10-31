#!/usr/bin/env perl
# Copyright 2026 Adilson Oliveira / 7dsol3. ISC license.
use strict;
use warnings;
use Digest::SHA qw(sha256_hex);
use JSON::PP;
use Math::BigInt;

binmode STDIN;
my $frame = '';
while (length($frame) < 32901) {
    my $n = read(STDIN, my $part, 32901 - length($frame));
    if (!defined $n) { print STDERR "KONAET_INPUT_INVALID\n"; exit 2; }
    last if $n == 0;
    $frame .= $part;
}
my @lines = split /\n/, $frame, -1;
if (length($frame) > 32900 || @lines != 4 || $lines[3] ne ''
    || $lines[0] !~ /\A[0-9a-f]{64}\z/
    || length($lines[1]) < 4 || length($lines[1]) > 32768 || length($lines[1]) % 2
    || $lines[1] !~ /\A[0-9a-f]+\z/
    || ($lines[2] ne '-' && $lines[2] !~ /\A[0-9a-f]{64}\z/)) {
    print STDERR "KONAET_INPUT_INVALID\n"; exit 2;
}
my $value = sha256_hex("KONAET/SOCIAL-RECEIPT/v1\0" . pack('H*', $lines[0]) . pack('H*', $lines[1]));
my $matches;
if ($lines[2] ne '-') {
    my $difference = 0;
    for my $i (0 .. 63) { $difference |= ord(substr($value, $i, 1)) ^ ord(substr($lines[2], $i, 1)); }
    $matches = $difference == 0 ? JSON::PP::true : JSON::PP::false;
}
my @args = map { my $number = Math::BigInt->from_hex('0x' . $_)->bstr(); "$number" } (substr($value, 0, 32), substr($value, 32));
print JSON::PP->new->canonical->encode({ commitment => $value, args => \@args, matches => $matches }) . "\n";
exit(defined($matches) && !$matches ? 1 : 0);
