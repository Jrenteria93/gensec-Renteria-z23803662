"""MCP server exposing a hash identification tool over stdio.

The server is built with FastMCP and provides a single tool,
``identify_hash``, which guesses the algorithm that produced a hash
based on its length and character format. No API keys are required.
"""

import re

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


def main() -> None:
    """Run the MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
