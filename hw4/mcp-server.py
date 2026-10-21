"""MCP server exposing hash and password analysis tools over stdio.

The server is built with FastMCP and provides three tools:
``identify_hash`` guesses the algorithm that produced a hash from its
length and format, ``check_password_strength`` rates a password, and
``suggest_hashcat_mode`` maps a hash type to its hashcat mode number.
No API keys are required.
"""

import re

# A small sample of widely leaked passwords, lowercased for comparison.
# Not exhaustive -- a real check would use a large breach wordlist.
COMMON_PASSWORDS = {
    "password",
    "password1",
    "password123",
    "123456",
    "123456789",
    "qwerty",
    "abc123",
    "letmein",
    "iloveyou",
    "admin",
    "welcome",
    "monkey",
    "dragon",
}

# Hash type (lowercased) -> (hashcat mode number, human-readable name).
HASHCAT_MODES = {
    "md5": (0, "MD5"),
    "sha1": (100, "SHA1"),
    "sha256": (1400, "SHA2-256"),
    "sha512": (1700, "SHA2-512"),
    "bcrypt": (3200, "bcrypt $2*$, Blowfish (Unix)"),
    "ntlm": (1000, "NTLM"),
}

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hash-identifier")

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
BCRYPT_RE = re.compile(r"^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$")

# Hex digest length -> candidate algorithms, most likely first.
HEX_LENGTHS = {
    32: ["MD5", "NTLM"],
    40: ["SHA1"],
    64: ["SHA256"],
    128: ["SHA512"],
}


@mcp.tool()
def identify_hash(hash: str) -> str:
    """Guess the hash type from its length and format.

    Recognizes MD5, SHA1, SHA256, SHA512, bcrypt, and NTLM. MD5 and NTLM
    are both 32 hex characters, so both are reported as candidates.

    Args:
        hash: The hash string to identify.

    Returns:
        A human-readable description of the likely hash type(s).
    """
    value = hash.strip()
    if not value:
        return "No hash provided."

    if BCRYPT_RE.match(value):
        cost = value.split("$")[2]
        return f"bcrypt (cost factor {cost})"

    if HEX_RE.match(value):
        candidates = HEX_LENGTHS.get(len(value))
        if candidates:
            guess = " or ".join(candidates)
            note = ""
            if len(candidates) > 1:
                note = (
                    " (same length and format; NTLM is common in Windows "
                    "credential dumps, MD5 elsewhere)"
                )
            return f"{guess}{note}"
        return f"Unknown: {len(value)} hex characters does not match a supported type."

    return (
        f"Unknown: {len(value)} characters, not hexadecimal or bcrypt format. "
        "Supported types: MD5, SHA1, SHA256, SHA512, bcrypt, NTLM."
    )


@mcp.tool()
def check_password_strength(password: str) -> str:
    """Rate a password as weak, medium, or strong and explain why.

    The rating considers length, whether the password mixes character
    classes (lowercase, uppercase, digits, symbols), and whether it
    appears in a short list of commonly leaked passwords. A password
    that matches a common password is always rated weak.

    Args:
        password: The password to evaluate.

    Returns:
        A rating ("weak", "medium", or "strong") followed by the
        reasons behind it.
    """
    if not password:
        return "weak: empty password."

    reasons = []

    if password.lower() in COMMON_PASSWORDS:
        return (
            "weak: this is a commonly used/breached password and would be "
            "cracked almost instantly regardless of its other properties."
        )

    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", password))
    classes = sum([has_lower, has_upper, has_digit, has_symbol])

    class_names = [
        name
        for present, name in [
            (has_lower, "lowercase"),
            (has_upper, "uppercase"),
            (has_digit, "digits"),
            (has_symbol, "symbols"),
        ]
        if present
    ]
    reasons.append(f"length {length}")
    reasons.append(f"{classes} character class(es): {', '.join(class_names)}")

    # Score: longer and more varied passwords score higher.
    if length >= 12 and classes >= 3:
        rating = "strong"
    elif length >= 8 and classes >= 2:
        rating = "medium"
    else:
        rating = "weak"

    if rating != "strong":
        tips = []
        if length < 12:
            tips.append("use at least 12 characters")
        if classes < 3:
            tips.append("mix letters, numbers, and symbols")
        if tips:
            reasons.append("to improve: " + "; ".join(tips))

    return f"{rating}: " + "; ".join(reasons) + "."


@mcp.tool()
def suggest_hashcat_mode(hash_type: str) -> str:
    """Suggest the hashcat ``-m`` mode number for a hash type.

    Supports MD5, SHA1, SHA256, SHA512, bcrypt, and NTLM. The reply
    includes the mode number and an example dictionary-attack command.

    Args:
        hash_type: The hash algorithm name (case-insensitive), e.g.
            "md5", "sha256", "bcrypt", or "ntlm".

    Returns:
        The hashcat mode number with an example command, or a message
        listing the supported types if the input is not recognized.
    """
    key = hash_type.strip().lower().replace("-", "")
    entry = HASHCAT_MODES.get(key)
    if entry is None:
        supported = ", ".join(name for _, name in HASHCAT_MODES.values())
        return (
            f"Unknown hash type '{hash_type}'. Supported types: {supported}."
        )

    mode, name = entry
    example = f"hashcat -m {mode} -a 0 hashes.txt wordlist.txt"
    return f"{name}: hashcat mode -m {mode}. Example: {example}"


def main() -> None:
    """Run the MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
