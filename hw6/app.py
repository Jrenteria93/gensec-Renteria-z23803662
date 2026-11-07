"""Simple web fuzzer: swaps FUZZ in a URL for each word in a wordlist.

Usage:
    uv run app.py --demo-server
    uv run app.py "http://127.0.0.1:8000/FUZZ" wordlist.txt --hide-code 404
    uv run app.py "http://127.0.0.1:8000/page?id=FUZZ" wordlist.txt --hide-size 0,10

    uv run app.py "http://127.0.0.1:8000/FUZZ" wordlist.txt --threads 5 --delay 0.05

Only localhost can be fuzzed unless you pass --i-have-permission.
--delay is shared by all threads, so it limits the total request rate.

The server and the wordlist are both treated as untrusted: their data is only
ever compared, counted or printed after clean(). It never reaches eval or a shell.
"""

import argparse
import concurrent.futures
import http.server
import ipaddress
import os
import re
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

DEMO_HOST = "127.0.0.1"
DEMO_PORT = 8000
DEFAULT_PORTS = {"http": 80, "https": 443}
REQUEST_TIMEOUT = 10  # seconds allowed for one whole request, redirects included
MAX_BODY = 1024 * 1024  # bytes read from one response
MAX_PRINT = 200  # characters shown from one untrusted string, so it can't flood the screen
MAX_WORD_BYTES = 1024  # longer wordlist lines are skipped
MAX_THREADS = 20
MAX_DELAY = 3600
DEFAULT_DELAY = 0.1  # seconds between requests, about 10 per second at most

ANSI_ESCAPES = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"  # colors, cursor moves, clear screen
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"  # window title and similar
    r"|\x1b[ -/]*[0-~]?"  # other short escapes
)


def clean(text):
    """Make untrusted text safe to print: no escape codes or control characters."""
    text = ANSI_ESCAPES.sub("", str(text))
    # C* covers control, invisible and bidi characters. Zl/Zp are Unicode line breaks.
    text = "".join(
        "?" if unicodedata.category(char) in ("Zl", "Zp") or unicodedata.category(char)[0] == "C"
        else char
        for char in text
    )
    return text if len(text) <= MAX_PRINT else text[:MAX_PRINT] + "..."


def site_of(url):
    """Return (scheme, host, port) for a URL, or raise ValueError if it isn't allowed."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in DEFAULT_PORTS:
        raise ValueError(f"only http and https urls are allowed, got {parts.scheme!r}")
    # "http://127.0.0.1@evil.com" really goes to evil.com, so refuse these outright.
    if "@" in parts.netloc or "\\" in parts.netloc:
        raise ValueError("urls with a username or backslash in the host are not allowed")
    if not parts.hostname:
        raise ValueError("url has no host")
    # urllib decodes the host before connecting, so encoded hosts can't be checked here.
    if "%" in parts.hostname:
        raise ValueError("encoded characters in the host are not allowed")
    return parts.scheme, parts.hostname, parts.port or DEFAULT_PORTS[parts.scheme]


def is_localhost(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_target(url, have_permission):
    """Raise ValueError if this URL is not one we are allowed to send a request to."""
    _, host, _ = site_of(url)
    if not have_permission and not is_localhost(host):
        raise ValueError(
            f"{host!r} is not localhost. Only pass --i-have-permission "
            "for a site you own or are authorized to test"
        )


class SameSiteRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Only follow redirects that stay on the same scheme, host and port."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            same_site = site_of(newurl) == site_of(req.full_url)
        except ValueError:
            same_site = False
        if not same_site:
            return None  # urllib then hands back the 3xx as an HTTPError
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# ProxyHandler({}) ignores system proxies, so requests go to the host we checked.
OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), SameSiteRedirectHandler
)


class DemoHandler(http.server.BaseHTTPRequestHandler):
    """Small test site: /page?id= echoes the id, /admin exists, the rest is 404."""

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/page":
            query = urllib.parse.parse_qs(parsed.query)
            self.reply(200, query.get("id", [""])[0])
        elif parsed.path == "/admin":
            self.reply(200, "Admin page\n")
        else:
            self.reply(404, "Not found\n")

    def reply(self, status, text):
        # Plain text so an echoed id can't run as HTML in a browser.
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_demo_server():
    """Serve the demo site on localhost until Ctrl+C."""
    with http.server.ThreadingHTTPServer((DEMO_HOST, DEMO_PORT), DemoHandler) as server:
        print(f"Demo server running at http://{DEMO_HOST}:{DEMO_PORT} (Ctrl+C to stop)")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nDemo server stopped")


def fetch(url):
    """Send a GET and return (status, body bytes, seconds taken, list of notes)."""
    start = time.perf_counter()
    notes = []
    try:
        with OPENER.open(url, timeout=REQUEST_TIMEOUT) as response:
            status = response.status
            body = response.read(MAX_BODY + 1)
    except urllib.error.HTTPError as error:
        # urllib raises on 4xx/5xx, but those are still valid fuzzing results.
        status = error.code
        with error:
            body = error.read(MAX_BODY + 1)
        if 300 <= status < 400 and "Location" in error.headers:
            notes.append("REDIRECT NOT FOLLOWED")
    if len(body) > MAX_BODY:
        body = body[:MAX_BODY]
        notes.append("TRUNCATED")
    return status, body, time.perf_counter() - start, notes


def fetch_with_deadline(url):
    """Run fetch() with a hard time limit.

    The socket timeout only covers a single read, so a server sending one byte
    every few seconds would never trip it. Running in a daemon thread means we
    can walk away from a stuck request, and it can't keep the program open.
    """
    outcome = []

    def worker():
        try:
            outcome.append((fetch(url), None))
        except Exception as error:
            outcome.append((None, error))

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(REQUEST_TIMEOUT)
    if not outcome:
        raise TimeoutError(f"no complete response within {REQUEST_TIMEOUT}s")

    result, error = outcome[0]
    if error:
        raise error
    return result


def int_list(value):
    """Parse a comma-separated option value like 404,403 into a list of ints."""
    try:
        return [int(part) for part in value.split(",")]
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected numbers like 404,403, got {value!r}")


def thread_count(value):
    try:
        count = int(value)
    except ValueError:
        count = 0
    if not 1 <= count <= MAX_THREADS:
        raise argparse.ArgumentTypeError(f"must be a whole number from 1 to {MAX_THREADS}")
    return count


def delay_seconds(value):
    try:
        seconds = float(value)
    except ValueError:
        seconds = -1
    if not 0 <= seconds <= MAX_DELAY:  # also false for nan
        raise argparse.ArgumentTypeError(f"must be a number of seconds from 0 to {MAX_DELAY}")
    return seconds


def load_words(path):
    """Return (words, number of lines skipped for being too long).

    The file is read in small pieces so one giant line can't fill memory.
    surrogateescape keeps invalid UTF-8 bytes, so they are still sent as they are.
    """
    words = []
    skipped = 0
    with open(path, "rb") as file:
        while line := file.readline(MAX_WORD_BYTES + 1):
            if len(line.rstrip(b"\r\n")) > MAX_WORD_BYTES:
                skipped += 1
                while line and not line.endswith(b"\n"):
                    line = file.readline(64 * 1024)
                continue
            line = line.removeprefix(b"\xef\xbb\xbf")  # BOM added by Windows editors
            word = line.decode("utf-8", "surrogateescape").strip()
            if word:
                words.append(word)
    return words, skipped


class RateLimiter:
    """Spaces out request starts. One limiter is shared by all threads."""

    def __init__(self, delay):
        self.delay = delay
        self.lock = threading.Lock()
        self.next_start = 0.0

    def wait(self):
        with self.lock:
            now = time.monotonic()
            start = max(now, self.next_start)
            self.next_start = start + self.delay
        time.sleep(start - now)


def wait_for(future):
    """Wait for a result in short steps. On Windows a long wait ignores Ctrl+C."""
    while True:
        try:
            return future.result(timeout=0.2)
        except concurrent.futures.TimeoutError:
            pass


def run_fuzz(args, words):
    limiter = RateLimiter(args.delay)

    def send(word):
        encoded = urllib.parse.quote(word, safe="", errors="surrogateescape")
        url = args.url.replace("FUZZ", encoded)
        try:
            # A word can change the URL, so check the final URL every time.
            check_target(url, args.i_have_permission)
            limiter.wait()
            status, body, elapsed, notes = fetch_with_deadline(url)
        except Exception as error:
            # One failed request shouldn't stop the rest of the run.
            return word, None, error

        # Results can queue up behind a slow word, so never keep the body past
        # this point. A server could otherwise use that queue to fill memory.
        if word.encode("utf-8", "surrogateescape") in body:
            notes.insert(0, "REFLECTED")
        return word, (status, len(body), elapsed, notes), None

    hits = hidden = errors = 0
    interrupted = False

    print(f"{'WORD':<30} {'STATUS':>6} {'SIZE':>10} {'TIME':>9}")
    executor = concurrent.futures.ThreadPoolExecutor(args.threads)
    try:
        futures = [executor.submit(send, word) for word in words]
        # Going through futures in order prints results in wordlist order,
        # whichever thread finishes first.
        for future in futures:
            word, result, error = wait_for(future)
            shown_word = clean(word)
            if error:
                errors += 1
                print(f"{shown_word:<30} ERROR: {clean(error)}")
                continue

            status, size, elapsed, notes = result
            if status in args.hide_code or size in args.hide_size:
                hidden += 1
                continue

            hits += 1
            marks = "".join(f"  [{note}]" for note in notes)
            print(f"{shown_word:<30} {status:>6} {size:>10} {elapsed:>8.3f}s{marks}")
    except KeyboardInterrupt:
        interrupted = True
        print("\nStopped early")
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    total = hits + hidden + errors
    print(f"\nTotal requests: {total}  Hits: {hits}  Hidden: {hidden}  Errors: {errors}")

    if interrupted:
        # A normal exit would wait for threads stuck on a request or a long delay.
        sys.stdout.flush()
        os._exit(130)


def main():
    # A character the terminal can't encode shouldn't crash the run.
    sys.stdout.reconfigure(errors="replace")

    parser = argparse.ArgumentParser(description="Simple web fuzzer")
    parser.add_argument("url", nargs="?", help="target URL containing the word FUZZ")
    parser.add_argument("wordlist", nargs="?", help="file with one word per line")
    parser.add_argument(
        "--demo-server",
        action="store_true",
        help=f"run a local test site on {DEMO_HOST}:{DEMO_PORT} instead of fuzzing",
    )
    parser.add_argument(
        "--hide-code",
        type=int_list,
        action="extend",
        default=[],
        help="hide these status codes, comma-separated or repeated (e.g. 404,403)",
    )
    parser.add_argument(
        "--hide-size",
        type=int_list,
        action="extend",
        default=[],
        help="hide responses of these sizes in bytes, comma-separated or repeated",
    )
    parser.add_argument(
        "--i-have-permission",
        action="store_true",
        help="allow non-localhost targets you own or are authorized to test",
    )
    parser.add_argument(
        "--threads",
        type=thread_count,
        default=1,
        help=f"requests sent at the same time, 1 to {MAX_THREADS} (default: 1)",
    )
    parser.add_argument(
        "--delay",
        type=delay_seconds,
        default=DEFAULT_DELAY,
        help=f"seconds between requests across all threads (default: {DEFAULT_DELAY})",
    )
    args = parser.parse_args()

    if args.demo_server:
        run_demo_server()
        return

    if not args.url or not args.wordlist:
        parser.error("url and wordlist are required unless using --demo-server")

    try:
        check_target(args.url, args.i_have_permission)
    except ValueError as error:
        parser.error(clean(error))

    if "FUZZ" not in args.url:
        parser.error("url must contain the word FUZZ")

    try:
        words, skipped = load_words(args.wordlist)
    except OSError as error:
        reason = clean(error.strerror or error)
        sys.exit(f"error: can't read wordlist {clean(args.wordlist)}: {reason}")

    if not words:
        sys.exit(f"error: no usable words in {clean(args.wordlist)}")
    if skipped:
        print(f"Skipped {skipped} line(s) longer than {MAX_WORD_BYTES} bytes")

    run_fuzz(args, words)
    sys.stdout.flush()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        sys.stderr.close()  # output was piped into something that quit, like head
    except Exception as error:
        sys.exit(f"error: {clean(error)}")
