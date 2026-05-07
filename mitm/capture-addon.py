"""
mitmproxy addon: stream every HTTP(S) flow to the proxy-checker backend.

Env vars (set by mitmproxy@.service):
  GW_NAME       — gateway name (e.g. "aaa")
  CAPTURE_URL   — backend ingest URL (default http://127.0.0.1:3000/api/_internal/capture)
  CAPTURE_TOKEN — shared secret (must match server.js INTERNAL_TOKEN)
  MAX_BODY      — max bytes of body to forward (default 65536)

Each request/response pair is POSTed once on `response` (or `error`) to keep ordering.
Body is base64-encoded; UI decodes for display.
"""

import base64
import json
import os
import time
import uuid
import urllib.request
import urllib.error
from mitmproxy import http, ctx

GW_NAME       = os.environ.get("GW_NAME", "unknown")
CAPTURE_URL   = os.environ.get("CAPTURE_URL", "http://127.0.0.1:3000/api/_internal/capture")
CAPTURE_TOKEN = os.environ.get("CAPTURE_TOKEN", "")
MAX_BODY      = int(os.environ.get("MAX_BODY", "65536"))


def _truncate(b: bytes):
    if b is None:
        return ("", 0, False)
    n = len(b)
    if n <= MAX_BODY:
        return (base64.b64encode(b).decode("ascii"), n, False)
    return (base64.b64encode(b[:MAX_BODY]).decode("ascii"), n, True)


def _post(payload: dict):
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            CAPTURE_URL,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Capture-Token": CAPTURE_TOKEN,
            },
        )
        urllib.request.urlopen(req, timeout=2).read()
    except urllib.error.URLError as e:
        ctx.log.warn(f"[capture] post failed: {e}")
    except Exception as e:
        ctx.log.warn(f"[capture] post err: {e}")


def _flow_to_payload(flow: http.HTTPFlow, kind: str):
    req = flow.request
    res = flow.response
    # Use .content (decompressed: gzip/br/deflate stripped) so UI sees readable text.
    # Fall back to raw_content if .content blows up for any reason.
    try:
        req_bytes = req.content if req.content is not None else (req.raw_content or b"")
    except Exception:
        req_bytes = req.raw_content or b""
    req_b64, req_size, req_truncated = _truncate(req_bytes)
    if res is not None:
        try:
            res_bytes = res.content if res.content is not None else (res.raw_content or b"")
        except Exception:
            res_bytes = res.raw_content or b""
        res_b64, res_size, res_truncated = _truncate(res_bytes)
        status = res.status_code
        res_headers = dict(res.headers.items())
        # Strip Content-Encoding header so the UI doesn't think the (now-decoded) body is still encoded
        res_headers.pop("content-encoding", None)
        res_headers.pop("Content-Encoding", None)
        elapsed_ms = int(((res.timestamp_end or time.time()) - (req.timestamp_start or time.time())) * 1000)
    else:
        res_b64, res_size, res_truncated = ("", 0, False)
        status = 0
        res_headers = {}
        elapsed_ms = 0

    return {
        "id": flow.id or str(uuid.uuid4()),
        "kind": kind,                       # "response" | "error"
        "gateway": GW_NAME,
        "ts": int((req.timestamp_start or time.time()) * 1000),
        "method": req.method,
        "scheme": req.scheme,
        "host": req.pretty_host,
        "port": req.port,
        "path": req.path,
        "url": req.pretty_url,
        "http_version": req.http_version,
        "client_ip": flow.client_conn.peername[0] if flow.client_conn.peername else "",
        "req_headers": dict(req.headers.items()),
        "req_body_b64": req_b64,
        "req_size": req_size,
        "req_truncated": req_truncated,
        "status": status,
        "res_headers": res_headers,
        "res_body_b64": res_b64,
        "res_size": res_size,
        "res_truncated": res_truncated,
        "elapsed_ms": elapsed_ms,
        "error": getattr(flow.error, "msg", None) if getattr(flow, "error", None) else None,
    }


class CaptureAddon:
    def response(self, flow: http.HTTPFlow):
        _post(_flow_to_payload(flow, "response"))

    def error(self, flow: http.HTTPFlow):
        if flow.request is None:
            return
        _post(_flow_to_payload(flow, "error"))


addons = [CaptureAddon()]
