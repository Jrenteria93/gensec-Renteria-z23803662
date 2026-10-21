# Credential Security Report

This report analyzes the provided cryptographic hashes and plaintext passwords from `hashes.txt`.

## 1. Hashes Analysis

The following table lists each hash value, its identified type, the corresponding Hashcat mode number, and an example Hashcat command.

| Hash Value | Identified Type | Hashcat Mode | Example Command |
| :--- | :--- | :--- | :--- |
| `5d41402abc4b2a76b9719d911017c592` | MD5 or NTLM (MD5 labeled) | `-m 0` | `hashcat -m 0 -a 0 hashes.txt wordlist.txt` |
| `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d` | SHA1 | `-m 100` | `hashcat -m 100 -a 0 hashes.txt wordlist.txt` |
| `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824` | SHA256 | `-m 1400` | `hashcat -m 1400 -a 0 hashes.txt wordlist.txt` |
| `9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043` | SHA512 | `-m 1700` | `hashcat -m 1700 -a 0 hashes.txt wordlist.txt` |
| `8846f7eaee8fb117ad06bdd830b7586c` | MD5 or NTLM (NTLM labeled) | `-m 1000` | `hashcat -m 1000 -a 0 hashes.txt wordlist.txt` |
| `$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW` | bcrypt (cost factor 12) | `-m 3200` | `hashcat -m 3200 -a 0 hashes.txt wordlist.txt` |

---

## 2. Password Strength Analysis

The following section evaluates the strength and complexity of the sample plaintext passwords.

| Password Value | Strength Rating | Explanation / Reasons |
| :--- | :--- | :--- |
| `password123` | **weak** | This is a commonly used/breached password and would be cracked almost instantly regardless of its other properties. |
| `Tr0ub4dour&3xplore!` | **strong** | Length is 19 characters; includes 4 character classes (lowercase, uppercase, digits, symbols). |
