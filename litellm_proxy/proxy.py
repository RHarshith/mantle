import contextvars
import json
import os
import threading
from typing import Any, Dict, Optional
from urllib.parse import urlparse
from fastapi import Request
from pydantic import BaseModel
import litellm
from litellm.integrations.custom_logger import CustomLogger

# Set LiteLLM config path before importing the proxy app.
# This LiteLLM build reads CONFIG_FILE_PATH / WORKER_CONFIG.
_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
os.environ["CONFIG_FILE_PATH"] = _CONFIG_PATH
os.environ["WORKER_CONFIG"] = _CONFIG_PATH

from litellm.proxy.proxy_server import app 


_ACTIVE_TRACE_LOCK = threading.RLock()
_ACTIVE_TRACE_FILE: str | None = None


class ActiveTracePayload(BaseModel):
    trace_file: str | None = None


def _normalize_trace_file_name(name: str | None) -> str | None:
    if name is None:
        return None
    candidate = str(name).strip()
    if not candidate:
        return None

    # Keep writes constrained to the configured log directory.
    if os.path.basename(candidate) != candidate:
        raise ValueError("trace_file must be a basename without path separators")
    if candidate in {".", ".."}:
        raise ValueError("trace_file must be a valid file name")
    return candidate


def _set_active_trace_file(name: str | None) -> str | None:
    normalized = _normalize_trace_file_name(name)
    global _ACTIVE_TRACE_FILE
    with _ACTIVE_TRACE_LOCK:
        _ACTIVE_TRACE_FILE = normalized
        return _ACTIVE_TRACE_FILE


def _get_active_trace_file() -> str | None:
    with _ACTIVE_TRACE_LOCK:
        return _ACTIVE_TRACE_FILE


@app.post("/mantle/active-trace")
async def set_active_trace(payload: ActiveTracePayload) -> dict[str, Any]:
    active = _set_active_trace_file(payload.trace_file)
    return {"active_trace_file": active}


@app.get("/mantle/active-trace")
async def get_active_trace() -> dict[str, Any]:
    return {"active_trace_file": _get_active_trace_file()}

# 1. Create a Context Variable to hold the ephemeral port natively in the async thread
client_port_var = contextvars.ContextVar("client_port", default="unknown_port")

# 2. FastAPI Middleware: Catch the port BEFORE the request hits the LLM
@app.middleware("http")
async def capture_port_middleware(request: Request, call_next):
    # Extract the source port and save it to the context variable
    if request.client and request.client.port:
        port = str(request.client.port)
        client_port_var.set(port)

        # Inject source port into headers so it survives async callback boundaries.
        scope_headers = request.scope.get("headers")
        if isinstance(scope_headers, list):
            scope_headers.append((b"x-client-src-port", port.encode("ascii")))
    
    # Pass the request down the chain
    response = await call_next(request)
    return response

# 3. LiteLLM Custom Logger: Safely grab the request and reconstructed response
class PortBasedFileLogger(CustomLogger):
    def __init__(self, log_dir="./bpf_logs"):
        if os.path.isabs(log_dir):
            self.log_dir = log_dir
        else:
            # Resolve relative path against this file so logs do not depend on cwd.
            self.log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), log_dir)
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

    def _extract_port(self, kwargs: Dict[str, Any]) -> str:
        if not isinstance(kwargs, dict):
            return client_port_var.get()

        candidates = []

        metadata = kwargs.get("metadata")
        if isinstance(metadata, dict):
            candidates.append(metadata.get("headers"))

        litellm_params = kwargs.get("litellm_params")
        if isinstance(litellm_params, dict):
            litellm_metadata = litellm_params.get("metadata")
            if isinstance(litellm_metadata, dict):
                candidates.append(litellm_metadata.get("headers"))

        proxy_request = kwargs.get("proxy_server_request")
        if isinstance(proxy_request, dict):
            candidates.append(proxy_request.get("headers"))

        candidates.append(kwargs.get("headers"))

        for headers in candidates:
            if not isinstance(headers, dict):
                continue

            # Request headers are normalized lower-case in liteLLM internals.
            for key in ("x-client-src-port", "x-forwarded-port", "x-client-port"):
                raw = headers.get(key)
                if raw is None:
                    continue
                raw_str = str(raw).strip()
                if raw_str.isdigit():
                    return raw_str

        return client_port_var.get()

    def _to_jsonable(self, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, (str, int, float, bool, list, dict)):
            return value

        try:
            if hasattr(value, "model_dump_json"):
                return json.loads(value.model_dump_json())
        except Exception:
            pass

        try:
            if hasattr(value, "model_dump"):
                dumped = value.model_dump()
                json.dumps(dumped)
                return dumped
        except Exception:
            pass

        try:
            json.dumps(value)
            return value
        except Exception:
            return {"_raw": str(value)}

    def _request_url(self, kwargs: Dict[str, Any], has_messages: bool) -> str:
        raw_base = ""
        if isinstance(kwargs, dict):
            maybe_base = kwargs.get("api_base") or kwargs.get("base_url")
            if isinstance(maybe_base, str):
                raw_base = maybe_base.strip()

        default_base = "https://api.openai.com"
        endpoint_path = "/v1/chat/completions" if has_messages else "/v1/responses"
        if not raw_base:
            return f"{default_base}{endpoint_path}"

        parsed = urlparse(raw_base)
        if not parsed.scheme or not parsed.netloc:
            return f"{default_base}{endpoint_path}"

        root = f"{parsed.scheme}://{parsed.netloc}"
        return f"{root}{endpoint_path}"

    def _write_event(
        self,
        *,
        status: str,
        kwargs: Dict[str, Any],
        response_obj: Any,
        start_time: Any,
        end_time: Any,
        exception: Optional[str] = None,
    ) -> None:
        port = self._extract_port(kwargs)
        active_trace_file = _get_active_trace_file()
        if active_trace_file:
            log_file_path = os.path.join(self.log_dir, active_trace_file)
        else:
            log_file_path = os.path.join(self.log_dir, f"{port}.log")

        log_data: Dict[str, Any] = {
            "status": status,
            "client_port": port,
            "model": kwargs.get("model") if isinstance(kwargs, dict) else None,
        }

        if status == "success":
            prompt_input = kwargs.get("input") if isinstance(kwargs, dict) else None
            prompt_messages = kwargs.get("messages") if isinstance(kwargs, dict) else None
            has_messages = isinstance(prompt_messages, list) and len(prompt_messages) > 0
            request_body: Dict[str, Any] = {
                "model": kwargs.get("model") if isinstance(kwargs, dict) else None,
            }
            if prompt_messages is not None:
                request_body["messages"] = self._to_jsonable(prompt_messages)
            if prompt_input is not None:
                request_body["input"] = self._to_jsonable(prompt_input)

            if isinstance(kwargs, dict):
                for key in ("tools", "instructions", "reasoning"):
                    if kwargs.get(key) is not None:
                        request_body[key] = self._to_jsonable(kwargs.get(key))

            response_body = self._to_jsonable(response_obj)
            if not isinstance(response_body, dict):
                response_body = {"_raw": str(response_body)}

            ts = end_time.timestamp() if hasattr(end_time, "timestamp") else None
            duration_ms = None
            if start_time is not None and end_time is not None:
                duration_ms = (end_time - start_time).total_seconds() * 1000

            log_data.update(
                {
                    # Fallback securely: 'messages' for Chat API, 'input' for Responses API
                    "prompt": (
                        prompt_input or prompt_messages
                        if isinstance(kwargs, dict)
                        else None
                    ),
                    # Store string representation to avoid json serialization failures.
                    "response": str(response_obj),
                    "duration_ms": duration_ms,
                    # Compatibility payload for existing MITM-based ingestion pipeline.
                    "direction": "response",
                    "ts": ts,
                    "url": self._request_url(kwargs, has_messages),
                    "method": "POST",
                    "status_code": 200,
                    "request_body": request_body,
                    "response_body": response_body,
                }
            )
        else:
            log_data["exception"] = exception

        with open(log_file_path, "a") as f:
            f.write(json.dumps(log_data) + "\n")

    def log_success_event(self, kwargs, response_obj, start_time, end_time):
        self._write_event(
            status="success",
            kwargs=kwargs,
            response_obj=response_obj,
            start_time=start_time,
            end_time=end_time,
        )

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        self._write_event(
            status="success",
            kwargs=kwargs,
            response_obj=response_obj,
            start_time=start_time,
            end_time=end_time,
        )
            
    def log_failure_event(self, kwargs, response_obj, start_time, end_time):
        self._write_event(
            status="failed",
            kwargs=kwargs,
            response_obj=response_obj,
            start_time=start_time,
            end_time=end_time,
            exception=str(kwargs.get("exception")) if isinstance(kwargs, dict) else None,
        )

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        self._write_event(
            status="failed",
            kwargs=kwargs,
            response_obj=response_obj,
            start_time=start_time,
            end_time=end_time,
            exception=str(kwargs.get("exception")) if isinstance(kwargs, dict) else None,
        )

# 4. Register the logger with LiteLLM
litellm.callbacks = [PortBasedFileLogger()]

# (The app is automatically exposed via the litellm.proxy.proxy_server import)