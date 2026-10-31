// Copyright 2026 Adilson Oliveira / 7dsol3. ISC license.
use sha2::{Digest, Sha256};
use std::io::{self, Read};

fn hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}
fn process() -> Option<i32> {
    let mut bytes = Vec::new();
    io::stdin().take(32901).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 32900 { return None; }
    let text = std::str::from_utf8(&bytes).ok()?;
    let lines: Vec<&str> = text.split('\n').collect();
    if lines.len() != 4 || !lines[3].is_empty() || lines[0].len() != 64 || !(4..=32768).contains(&lines[1].len()) { return None; }
    let salt = hex(lines[0])?; let document = hex(lines[1])?;
    let expected = if lines[2] == "-" { None } else { if lines[2].len() != 64 { return None; } Some(hex(lines[2])?) };
    let mut hash = Sha256::new(); hash.update(b"KONAET/SOCIAL-RECEIPT/v1\0"); hash.update(salt); hash.update(document);
    let digest = hash.finalize();
    let value: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    let high = u128::from_be_bytes(digest[..16].try_into().ok()?);
    let low = u128::from_be_bytes(digest[16..].try_into().ok()?);
    let matches = expected.map(|other| digest.iter().zip(other).fold(0u8, |different, (a, b)| different | (a ^ b)) == 0);
    let printed = match matches { Some(true) => "true", Some(false) => "false", None => "null" };
    println!("{{\"commitment\":\"{value}\",\"args\":[\"{high}\",\"{low}\"],\"matches\":{printed}}}");
    Some(if matches == Some(false) { 1 } else { 0 })
}
fn main() {
    match process() { Some(code) => std::process::exit(code), None => { eprintln!("KONAET_INPUT_INVALID"); std::process::exit(2); } }
}
