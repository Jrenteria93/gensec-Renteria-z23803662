"""fast-agent client for the hw4 MCP homework.

Defines a single agent that connects to two MCP servers declared in
``fastagent.config.yaml``:

* ``hashtools`` -- the local FastMCP server in ``mcp-server.py`` providing
  ``identify_hash``, ``check_password_strength`` and
  ``suggest_hashcat_mode``.
* ``filesystem`` -- the official Model Context Protocol filesystem server,
  scoped to the ``data`` directory, used to read ``hashes.txt`` and write
  ``report.md``.

The model (``google.gemini-3.6-flash``) and its API key are configured in
the YAML file; the key is read from the ``GOOGLE_API_KEY`` environment
variable, so no secrets live in this code. Run with ``uv run agent.py``
after exporting ``GOOGLE_API_KEY``.
"""

import asyncio
import os

from fast_agent import FastAgent

fast = FastAgent("hw4-hash-analyst")

# Model is read from the GOOGLE_MODEL environment variable so it can be
# swapped without editing code (e.g. when one model is overloaded). The
# value is a full fast-agent model string, including the provider prefix.
# Falls back to google.gemini-3.6-flash when the variable is not set.
MODEL = os.environ.get("GOOGLE_MODEL", "google.gemini-3.6-flash")

# The task the agent performs end to end, using the two MCP servers.
# The filesystem server is rooted at the data/ folder, so file paths given
# to it are relative to that folder (use "hashes.txt", not "data/hashes.txt").
TASK = (
    "Read the file hashes.txt using the filesystem server. Its paths are "
    "relative to the server's root directory, so use plain names like "
    "'hashes.txt' and 'report.md' with no 'data/' prefix. The file contains "
    "lines with a type label and a value: hash lines (md5, sha1, sha256, "
    "sha512, ntlm, bcrypt) and a few 'password' lines with plaintext "
    "passwords. Ignore blank lines and lines starting with '#'.\n\n"
    "For every hash value:\n"
    "  1. Call identify_hash to confirm its type.\n"
    "  2. Call suggest_hashcat_mode to get the hashcat -m number and example "
    "command.\n"
    "For every password value, call check_password_strength and report the "
    "rating and reasons.\n\n"
    "Then write a well-structured Markdown report to report.md using the "
    "filesystem server. Include a section for the hashes (a table with the "
    "value, identified type, hashcat mode, and example command) and a section "
    "for the passwords (value, rating, and explanation). Confirm when the "
    "file has been written."
)


@fast.agent(
    name="hash-analyst",
    instruction=(
        "You are a security analyst assistant. Use the available MCP tools to "
        "identify hashes, suggest hashcat modes, and rate passwords, then save "
        "a Markdown report. Always use the tools rather than guessing, and "
        "only read and write files through the filesystem server."
    ),
    servers=["hashtools", "filesystem"],
    model=MODEL,
    default=True,
)
async def main() -> None:
    """Run the agent and have it produce data/report.md."""
    async with fast.run() as agent:
        await agent(TASK)


if __name__ == "__main__":
    asyncio.run(main())
