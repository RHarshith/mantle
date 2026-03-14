#!/usr/bin/env python3
import argparse
import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class ScenarioHandler(BaseHTTPRequestHandler):
    state_file = ""

    def _load_state(self):
        if not os.path.exists(self.state_file):
            return {"force_unhealthy": True}
        with open(self.state_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_state(self, state):
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(state, f)

    def _write_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        parsed = urlparse(self.path)
        state = self._load_state()

        if parsed.path == "/":
            self._write_json(HTTPStatus.OK, {
                "service": "faulty_api",
                "health_endpoint": "/health",
                "state_endpoint": "/admin/state"
            })
            return

        if parsed.path == "/health":
            if state.get("force_unhealthy", True):
                self._write_json(HTTPStatus.INTERNAL_SERVER_ERROR, {
                    "status": "unhealthy",
                    "reason": "forced_fault_mode"
                })
            else:
                self._write_json(HTTPStatus.OK, {"status": "ok"})
            return

        if parsed.path == "/admin/state":
            self._write_json(HTTPStatus.OK, state)
            return

        self._write_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/admin/toggle-health":
            self._write_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return

        state = self._load_state()
        params = parse_qs(parsed.query)
        healthy = params.get("healthy", ["0"])[0]
        state["force_unhealthy"] = healthy not in ("1", "true", "True", "yes")
        self._save_state(state)
        self._write_json(HTTPStatus.OK, state)


def main():
    parser = argparse.ArgumentParser(description="Fault-injectable API service for strace test scenarios")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--state-file", required=True)
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.state_file), exist_ok=True)
    if not os.path.exists(args.state_file):
        with open(args.state_file, "w", encoding="utf-8") as f:
            json.dump({"force_unhealthy": True}, f)

    ScenarioHandler.state_file = args.state_file
    server = HTTPServer((args.host, args.port), ScenarioHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
