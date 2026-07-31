"""mitmproxy addon: logs decrypted host/path/body per request as JSON-lines to
/scratch/mitm.log, and logs bare SNI hostnames for connections whose TLS
handshake mitmproxy couldn't complete (e.g. a cert-pinning client) — so a
scan still reports *something* for that flow instead of silently dropping it.

Run via: mitmdump -s mitmproxy-addon.py
"""

from __future__ import annotations

import base64
import json
import time

LOG_PATH = "/scratch/mitm.log"
MAX_BODY_BYTES = 8192


def _write(record: dict) -> None:
    record.setdefault("timestamp", time.time())
    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def _encode_body(data: bytes | None) -> tuple[str, bool]:
    if not data:
        return "", False
    truncated = len(data) > MAX_BODY_BYTES
    return base64.b64encode(data[:MAX_BODY_BYTES]).decode("ascii"), truncated


def request(flow) -> None:
    body_b64, truncated = _encode_body(flow.request.raw_content)
    _write(
        {
            "kind": "http_request",
            "host": flow.request.pretty_host,
            "port": flow.request.port,
            "method": flow.request.method,
            "path": flow.request.path,
            "headers": dict(flow.request.headers),
            "body_base64": body_b64,
            "body_truncated": truncated,
        }
    )


def response(flow) -> None:
    body_b64, truncated = _encode_body(flow.response.raw_content if flow.response else None)
    _write(
        {
            "kind": "http_response",
            "host": flow.request.pretty_host,
            "status_code": flow.response.status_code if flow.response else None,
            "body_base64": body_b64,
            "body_truncated": truncated,
        }
    )


def tls_failed_client(data) -> None:
    """A client refused mitmproxy's cert (e.g. certificate pinning) — the flow
    never becomes readable HTTP, but the attempted SNI hostname is still signal."""
    sni = getattr(data.conn, "sni", None)
    _write(
        {
            "kind": "tls_handshake_failed",
            "sni": sni,
            "reason": str(getattr(data, "conn", "")),
        }
    )
