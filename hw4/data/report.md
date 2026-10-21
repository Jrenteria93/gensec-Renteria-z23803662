# Credential Analysis Report

This report documents the identification and analysis of various hashes and plaintext passwords extracted from `hashes.txt`.

## 1. Hash Analysis

| Value | Identified Type | Hashcat Mode | Example Command |
| :--- | :--- | :--- | :--- |
| `5d41402abc4b2a76b9719d911017c592` | MD5 or NTLM (same length and format; NTLM is common in Windows credential dumps, MD5 elsewhere) | `-m 0` | `hashcat -m 0 -a 0 hashes.txt wordlist.txt` |
| `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d` | SHA1 | `-m 100` | `hashcat -m 100 -a 0 hashes.txt wordlist.txt` |
| `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824` | SHA256 | `-m 1400` | `hashcat -m 1400 -a 0 hashes.txt wordlist.txt` |
| `9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043` | SHA512 | `-m 1700` | `hashcat -m 1700 -a 0 hashes.txt wordlist.txt` |
| `8846f7eaee8fb117ad06bdd830b7586c` | MD5 or NTLM (same length and format; NTLM is common in Windows credential dumps, MD5 elsewhere) | `-m 1000` | `hashcat -m 1000 -a 0 hashes.txt wordlist.txt` |
| `$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW` | bcrypt (cost factor 12) | `-m 3200` | `hashcat -m 3200 -a 0 hashes.txt wordlist.txt` |

## 2. Password Strength Analysis

| Value | Rating | Explanation |
| :--- | :--- | :--- |
| `password123` | **weak** | This is a commonly used/breached password and would be cracked almost instantly regardless of its other properties. |
| `Tr0ub4dour&3xplore!` | **strong** | Length 19; 4 character class(es): lowercase, uppercase, digits, symbols. |
