#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any


class Scenario:
    def __init__(self, file_path: Path, loop: bool = False):
        self.file_path = file_path
        self.loop = loop
        self._responses = self._load(file_path)
        self._index = 0

    def _load(self, file_path: Path) -> list[dict[str, Any]]:
        data = json.loads(file_path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("responses"), list):
            responses = data["responses"]
        elif isinstance(data, list):
            responses = data
        else:
            raise ValueError("Scenario must be a list or a {'responses': [...]} object")
        if not responses:
            raise ValueError("Scenario responses list is empty")
        out: list[dict[str, Any]] = []
        for item in responses:
            if not isinstance(item, dict):
                raise ValueError("Each response must be an object")
            out.append(self._normalize_response(item))
        return out

    def _normalize_response(self, obj: dict[str, Any]) -> dict[str, Any]:
        if isinstance(obj.get("choices"), list):
            resp = dict(obj)
            resp.setdefault("id", f"chatcmpl-mock-{int(time.time() * 1000)}")
            resp.setdefault("object", "chat.completion")
            resp.setdefault("created", int(time.time()))
            resp.setdefault("model", "mock-model")
            return resp

        message = obj.get("message")
        if not isinstance(message, dict):
            raise ValueError("Response object must include 'choices' or 'message'")

        return {
            "id": f"chatcmpl-mock-{int(time.time() * 1000)}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": str(obj.get("model") or "mock-model"),
            "choices": [
                {
                    "index": 0,
                    "message": message,
                    "finish_reason": str(obj.get("finish_reason") or "stop"),
                }
            ],
            "usage": obj.get("usage") or {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }

    def next_response(self) -> dict[str, Any]:
        if self._index >= len(self._responses):
            if not self.loop:
                raise RuntimeError("Scenario exhausted")
            self._index = 0
        resp = self._responses[self._index]
        self._index += 1
        return resp


class MockHandler(BaseHTTPRequestHandler):
    scenario: Scenario

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/chat/completions":
            self._send_json(404, {"error": {"message": "Not found"}})
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length) if content_length > 0 else b"{}"
        try:
            _ = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self._send_json(400, {"error": {"message": "Invalid JSON request"}})
            return

        try:
            payload = self.scenario.next_response()
        except RuntimeError as exc:
            self._send_json(429, {"error": {"message": str(exc)}})
            return

        self._send_json(200, payload)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock OpenAI-compatible chat completion server")
    parser.add_argument("--script", required=True, help="Path to scenario JSON file")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=4010, help="Bind port")
    parser.add_argument("--loop", action="store_true", help="Loop scenario responses when exhausted")
    args = parser.parse_args()

    scenario = Scenario(Path(args.script), loop=args.loop)
    MockHandler.scenario = scenario

    server = HTTPServer((args.host, args.port), MockHandler)
    print(f"mock_llm_server listening on http://{args.host}:{args.port} using {args.script}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
