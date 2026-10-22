"""The small pieces the live-measurement scripts share: a JSON-RPC call that
backs off on a rate limit instead of hammering a public endpoint, base58, and
the first signature of a serialized transaction.

Standard library only, like tools/mainnet-sample: the workflows run these on a
fresh runner without installing anything.
"""
import http.client
import json
import time
import urllib.error
import urllib.request

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class RateLimited(Exception):
    """The endpoint kept answering 429 after every backoff. Not a defect in
    Graphite: the run records what it could not measure and says why."""


class RpcError(Exception):
    """The endpoint could not be reached, or answered with an error."""


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = []
    while n:
        n, r = divmod(n, 58)
        out.append(ALPHABET[r])
    pad = len(raw) - len(raw.lstrip(b"\0"))
    return "1" * pad + "".join(reversed(out))


def b58decode(text: str) -> bytes:
    n = 0
    for ch in text:
        idx = ALPHABET.find(ch)
        if idx < 0:
            raise ValueError(f"not base58: {ch!r}")
        n = n * 58 + idx
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(text) - len(text.lstrip("1"))
    return b"\0" * pad + body


def shortvec(data: bytes, at: int = 0):
    """Decode a compact-u16 at `at` -> (value, next offset)."""
    value = shift = 0
    for i in range(3):
        if at + i >= len(data):
            raise ValueError("truncated compact-u16")
        b = data[at + i]
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, at + i + 1
        shift += 7
    raise ValueError("compact-u16 longer than three bytes")


def first_signature(tx: bytes) -> str:
    """The transaction's id: its first signature slot, base58."""
    count, at = shortvec(tx)
    if count == 0 or len(tx) < at + 64:
        raise ValueError("transaction carries no signature")
    return b58encode(tx[at : at + 64])


def call(url, method, params, *, timeout=60, attempts=6, base_pause=2.0, sleep=time.sleep):
    """One JSON-RPC call. A 429 (HTTP or JSON-RPC -32429) and transient
    network errors back off exponentially; after `attempts` the call raises
    RateLimited or RpcError rather than retrying forever."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    last = None
    for attempt in range(attempts):
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                doc = json.loads(r.read().decode())
            err = doc.get("error")
            if isinstance(err, dict) and err.get("code") in (429, -32429):
                last = RateLimited(f"{method}: {err.get('message', '429')}")
            else:
                return doc
        except urllib.error.HTTPError as e:
            if e.code == 429:
                last = RateLimited(f"{method}: HTTP 429")
            elif e.code >= 500:
                last = RpcError(f"{method}: HTTP {e.code}")
            else:
                raise RpcError(f"{method}: HTTP {e.code}") from None
        except (http.client.IncompleteRead, ConnectionError, TimeoutError, urllib.error.URLError) as e:
            last = RpcError(f"{method}: {type(e).__name__}: {e}")
        if attempt < attempts - 1:
            sleep(base_pause * (2**attempt))
    raise last


def host_of(url: str) -> str:
    """The host only, for logs: a provider URL can carry its key in the path
    or the query."""
    from urllib.parse import urlsplit

    return urlsplit(url).hostname or "?"
