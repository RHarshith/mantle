"""
mitmproxy addon: capture OpenAI API chat-completion requests & responses.

Usage:
    mitmdump -s mitm_capture.py --set capture_file=/path/to/output.mitm.jsonl

Each intercepted chat completion is written as a single JSONL line containing:
    - ts:                 UNIX timestamp
    - direction:          "request" | "response"
    - url:                full request URL
    - method:             HTTP method
    - status_code:        HTTP status (response only)
    - request_body:       parsed JSON body of the request
    - response_body:      parsed JSON body of the response
    - model:              model name (if available)
    - duration_ms:        round-trip duration (response only)
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from mitmproxy import http, ctx

_CAPTURE_PATTERNS = [
    "/chat/completions",
    "/v1/chat/completions",
    "/api/chat/completions",
]

# Track in-flight requests for timing
_request_times: dict[str, float] = {}


def _is_chat_completion(url: str) -> bool:
    return any(pat in url for pat in _CAPTURE_PATTERNS)


def _get_capture_file() -> Path:
    path = os.environ.get("MITM_CAPTURE_FILE", "")
    if not path:
        try:
            path = ctx.options.capture_file
        except AttributeError:
            path = "/tmp/mitm_capture.jsonl"
    return Path(path)


def _write_record(record: dict):
    fpath = _get_capture_file()
    fpath.parent.mkdir(parents=True, exist_ok=True)
    with open(fpath, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


class ChatCompletionCapture:
    def load(self, loader):
        loader.add_option(
            name="capture_file",
            typespec=str,
            default="/tmp/mitm_capture.jsonl",
            help="Path to write captured API call JSONL",
        )

    def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        if not _is_chat_completion(url):
            return

        _request_times[flow.id] = time.time()

        # Parse request body
        body = {}
        try:
            raw = flow.request.get_text()
            if raw:
                body = json.loads(raw)
        except Exception:
            body = {"_raw": flow.request.get_text() or ""}

        record = {
            "ts": time.time(),
            "direction": "request",
            "url": url,
            "method": flow.request.method,
            "model": body.get("model", ""),
            "request_body": body,
        }
        _write_record(record)

    def response(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        if not _is_chat_completion(url):
            return

        start_time = _request_times.pop(flow.id, None)
        duration_ms = int((time.time() - start_time) * 1000) if start_time else None

        # Parse response body
        body = {}
        try:
            raw = flow.response.get_text()
            if raw:
                body = json.loads(raw)
        except Exception:
            body = {"_raw": flow.response.get_text() or ""}

        # Parse request body too for context
        req_body = {}
        try:
            raw_req = flow.request.get_text()
            if raw_req:
                req_body = json.loads(raw_req)
        except Exception:
            pass

        record = {
            "ts": time.time(),
            "direction": "response",
            "url": url,
            "method": flow.request.method,
            "status_code": flow.response.status_code,
            "model": body.get("model", req_body.get("model", "")),
            "duration_ms": duration_ms,
            "request_body": req_body,
            "response_body": body,
        }
        _write_record(record)


addons = [ChatCompletionCapture()]
