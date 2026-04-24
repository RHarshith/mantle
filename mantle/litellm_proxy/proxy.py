import contextvars
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
from typing import Any, Dict, Optional
from urllib.parse import urlparse
from fastapi import Request
from fastapi.responses import JSONResponse, Response
import httpx
from pydantic import BaseModel
import litellm
from litellm.integrations.custom_logger import CustomLogger

from mantle.runtime.bootstrap import bootstrap_runtime
from mantle.runtime.logging import get_component_logger


_, _RUNTIME_LAYOUT = bootstrap_runtime("proxy")
PROXY_LOGGER = get_component_logger("proxy", layout=_RUNTIME_LAYOUT)

# Set LiteLLM config path before importing the proxy app.
# LiteLLM 1.9.x expects WORKER_CONFIG to match the initialize() schema,
# while newer builds can load CONFIG_FILE_PATH directly.
if not _RUNTIME_LAYOUT.proxy_config_path.exists():
    raise RuntimeError(
        f"Missing LiteLLM proxy config after runtime bootstrap: {_RUNTIME_LAYOUT.proxy_config_path}"
    )
PROXY_LOGGER.info("using proxy config", extra={"config_path": str(_RUNTIME_LAYOUT.proxy_config_path)})

_CONFIG_PATH = str(_RUNTIME_LAYOUT.proxy_config_path)
os.environ["CONFIG_FILE_PATH"] = _CONFIG_PATH
try:
    import yaml
except Exception as exc:  # pragma: no cover - fail-fast for broken runtime deps
    raise RuntimeError("PyYAML is required to prepare LiteLLM WORKER_CONFIG") from exc

try:
    with open(_CONFIG_PATH, "r", encoding="utf-8") as cfg_file:
        parsed_config = yaml.safe_load(cfg_file) or {}
except Exception as exc:
    raise RuntimeError(f"Failed to parse LiteLLM config at {_CONFIG_PATH}") from exc

default_model = "gpt-3.5-turbo"
if isinstance(parsed_config, dict):
    model_list = parsed_config.get("model_list")
    if isinstance(model_list, list):
        for entry in model_list:
            if not isinstance(entry, dict):
                continue
            model_name = entry.get("model_name")
            if isinstance(model_name, str) and model_name.strip():
                default_model = model_name.strip()
                break

worker_config = {
    "model": default_model,
    "alias": None,
    "api_base": None,
    "api_version": None,
    "debug": False,
    "temperature": None,
    "max_tokens": None,
    "request_timeout": None,
    "max_budget": None,
    "telemetry": False,
    "drop_params": False,
    "add_function_to_prompt": False,
    "headers": None,
    "save": False,
    "config": _CONFIG_PATH,
    "use_queue": False,
}
os.environ["WORKER_CONFIG"] = json.dumps(worker_config)

from litellm.proxy.proxy_server import app 


_ACTIVE_TRACE_LOCK = threading.RLock()
_ACTIVE_TRACE_FILE: str | None = None
_ACTIVE_PROCESS_NAME: str | None = None


def _oracle_server_base_url() -> str:
    """Resolve the Mantle server base URL used to fetch oracle status."""
    return os.getenv("MANTLE_SERVER_URL", "http://127.0.0.1:8099").rstrip("/")


def _oracle_path() -> str:
    """Resolve the oracle command/path to present to the agent.

    Default to the command name (host PATH lookup) because agents usually run
    on the host, not inside the proxy container filesystem.
    """
    env_path = os.getenv("MANTLE_ORACLE_PATH", "").strip()
    if env_path:
        return env_path
    return "mantle-oracle"


def _format_oracle_status(payload: dict[str, Any], *, process_name: str, trace_id: str | None) -> str:
    """Format oracle JSON into a short prompt-safe status block."""
    lines = ["[Mantle oracle status]"]
    if process_name:
        lines.append(f"process: {process_name}")
    if trace_id:
        lines.append(f"trace: {trace_id}")

    if "progress" in payload or "score" in payload:
        if "progress" in payload:
            lines.append(f"progress: {payload.get('progress')}")
        if "score" in payload:
            lines.append(f"score: {payload.get('score')}")
        satisfied = payload.get("satisfied") or []
        pending = payload.get("pending") or []
        checkpoints = payload.get("checkpoints") or []

        def _join(items: list[Any]) -> str:
            if not items:
                return "-"
            return "; ".join(str(item) for item in items)

        lines.append(f"satisfied: {_join(list(satisfied))}")
        lines.append(f"pending: {_join(list(pending))}")

        if checkpoints:
            checkpoint_names: list[str] = []
            for cp in checkpoints:
                if isinstance(cp, dict):
                    name = str(cp.get("name") or "").strip()
                    desc = str(cp.get("description") or "").strip()
                    checkpoint_names.append(f"{name} ({desc})" if name and desc else name or desc)
                else:
                    checkpoint_names.append(str(cp))
            lines.append(f"checkpoints: {_join([name for name in checkpoint_names if name])}")
        else:
            lines.append("checkpoints: -")
    else:
        checkpoints = payload.get("checkpoints") or []
        if checkpoints:
            rendered: list[str] = []
            for cp in checkpoints:
                if isinstance(cp, dict):
                    name = str(cp.get("name") or "").strip()
                    desc = str(cp.get("description") or "").strip()
                    rendered.append(f"{name} ({desc})" if name and desc else name or desc)
                else:
                    text = str(cp).strip()
                    if text:
                        rendered.append(text)
            lines.append(f"checkpoints: {'; '.join(item for item in rendered if item) or '-'}")
        else:
            lines.append("checkpoints: -")

    next_hint = str(payload.get("next_hint") or "").strip()
    if next_hint:
        lines.append(f"next_hint: {next_hint}")

    return "\n".join(lines)


async def _build_oracle_user_directive() -> str | None:
    """Fetch oracle status for the active process and trace, if available."""
    with _ACTIVE_TRACE_LOCK:
        pname = _ACTIVE_PROCESS_NAME
        tfile = _ACTIVE_TRACE_FILE
    if not pname:
        return None

    server_url = _oracle_server_base_url()
    if tfile:
        endpoint = f"{server_url}/api/traces/{tfile}/reward-status"
    else:
        endpoint = f"{server_url}/api/processes/{pname}/checkpoint-details"

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=5.0)) as client:
            response = await client.get(endpoint)
            response.raise_for_status()
            payload = response.json()
    except Exception:
        PROXY_LOGGER.exception(
            "failed to fetch oracle status",
            extra={"process_name": pname, "trace_id": tfile, "endpoint": endpoint},
        )
        return None

    if not isinstance(payload, dict):
        return None

    if payload.get("error") in {"no_guide_trace", "trace_not_in_process", "trace_not_registered"}:
        return None

    return _format_oracle_status(payload, process_name=pname, trace_id=tfile)


def _responses_upstream_url(request: Request) -> str:
    """Resolve upstream OpenAI responses endpoint, preserving query params."""
    raw_base = os.getenv("MANTLE_OPENAI_UPSTREAM_BASE_URL", "https://api.openai.com").rstrip("/")
    if raw_base.endswith("/v1"):
        url = f"{raw_base}/responses"
    else:
        url = f"{raw_base}/v1/responses"
    if request.url.query:
        url = f"{url}?{request.url.query}"
    return url


def _build_upstream_headers(request: Request) -> dict[str, str]:
    headers: dict[str, str] = {}
    allowed = {
        "authorization",
        "content-type",
        "accept",
        "openai-organization",
        "openai-project",
        "openai-beta",
        "idempotency-key",
        "user-agent",
        "x-stainless-lang",
        "x-stainless-package-version",
        "x-stainless-os",
        "x-stainless-arch",
        "x-stainless-runtime",
        "x-stainless-runtime-version",
        "x-stainless-async",
        "x-stainless-retry-count",
        "x-stainless-timeout",
    }

    for key, value in request.headers.items():
        lowered = key.lower()
        if lowered not in allowed:
            continue
        headers[key] = value

    # Prefer server-side key when configured, else forward client auth.
    env_key = os.getenv("OPENAI_API_KEY", "").strip()
    if env_key:
        headers["Authorization"] = f"Bearer {env_key}"
    elif "authorization" not in {k.lower() for k in headers}:
        # Keep upstream error semantics explicit if neither key source is available.
        pass

    return headers


def _filter_upstream_headers(upstream_headers: httpx.Headers) -> dict[str, str]:
    filtered: dict[str, str] = {}
    for key, value in upstream_headers.items():
        lowered = key.lower()
        if lowered in {"content-length", "connection", "transfer-encoding", "content-encoding"}:
            continue
        filtered[key] = value
    return filtered


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


class ActiveProcessPayload(BaseModel):
    process_name: str | None = None


@app.post("/mantle/active-process")
async def set_active_process(payload: ActiveProcessPayload) -> dict[str, Any]:
    global _ACTIVE_PROCESS_NAME
    with _ACTIVE_TRACE_LOCK:
        _ACTIVE_PROCESS_NAME = payload.process_name
    return {"process_name": payload.process_name}


@app.get("/mantle/active-process")
async def get_active_process() -> dict[str, Any]:
    with _ACTIVE_TRACE_LOCK:
        return {"process_name": _ACTIVE_PROCESS_NAME}


@app.post("/v1/responses")
@app.post("/responses")
async def proxy_responses_passthrough(request: Request) -> Response:
    """Compatibility route for clients using OpenAI Responses API."""
    start_time = datetime.now(timezone.utc)
    request_body = await request.body()

    request_payload: dict[str, Any] = {}
    if request_body:
        try:
            parsed = json.loads(request_body.decode("utf-8"))
            if isinstance(parsed, dict):
                request_payload = parsed
        except Exception:
            request_payload = {}

    # ── Oracle status injection (Responses API) ──────────────────────
    oracle_user_directive = await _build_oracle_user_directive()
    modified_body = request_body
    if oracle_user_directive and request_payload:
        # Add oracle status for explicit prompt-side visibility.
        if isinstance(request_payload.get("messages"), list):
            request_payload["messages"].append(
                {"role": "user", "content": oracle_user_directive}
            )
        else:
            response_input = request_payload.get("input")
            if isinstance(response_input, list):
                response_input.append(
                    {
                        "role": "user",
                        "content": [{"type": "input_text", "text": oracle_user_directive}],
                    }
                )
            elif isinstance(response_input, str):
                request_payload["input"] = f"{response_input}\n\n{oracle_user_directive}"

        modified_body = json.dumps(request_payload).encode("utf-8")

    upstream_url = _responses_upstream_url(request)
    upstream_headers = _build_upstream_headers(request)
    request_kwargs: Dict[str, Any] = {
        "model": request_payload.get("model"),
        "input": request_payload.get("input"),
        "messages": request_payload.get("messages"),
        "tools": request_payload.get("tools"),
        "instructions": request_payload.get("instructions"),
        "reasoning": request_payload.get("reasoning"),
        "headers": dict(request.headers),
        "base_url": upstream_url,
    }

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=30.0)) as client:
            upstream_response = await client.post(
                upstream_url,
                content=modified_body,
                headers=upstream_headers,
            )
    except httpx.HTTPError as exc:
        end_time = datetime.now(timezone.utc)
        _PROXY_EVENT_LOGGER._write_event(
            status="failed",
            kwargs=request_kwargs,
            response_obj=None,
            start_time=start_time,
            end_time=end_time,
            exception=f"responses passthrough failed: {exc}",
        )
        return JSONResponse(
            status_code=502,
            content={"error": {"message": f"upstream request failed: {exc}", "type": "proxy_error"}},
        )

    response_content_type = upstream_response.headers.get("content-type", "")
    response_obj: Any
    if "application/json" in response_content_type.lower():
        try:
            response_obj = upstream_response.json()
        except ValueError:
            response_obj = upstream_response.text
    else:
        response_obj = upstream_response.text

    end_time = datetime.now(timezone.utc)
    if upstream_response.is_success:
        _PROXY_EVENT_LOGGER._write_event(
            status="success",
            kwargs=request_kwargs,
            response_obj=response_obj,
            start_time=start_time,
            end_time=end_time,
        )
    else:
        status_code = upstream_response.status_code
        response_snippet = ""
        if isinstance(response_obj, dict):
            try:
                response_snippet = json.dumps(response_obj)[:800]
            except Exception:
                response_snippet = str(response_obj)[:800]
        else:
            response_snippet = str(response_obj)[:800]

        _PROXY_EVENT_LOGGER._write_event(
            status="failed",
            kwargs=request_kwargs,
            response_obj=response_obj,
            start_time=start_time,
            end_time=end_time,
            exception=(
                f"upstream status {status_code}; "
                f"response={response_snippet}"
            ),
        )

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=_filter_upstream_headers(upstream_response.headers),
    )

# 1. Create a Context Variable to hold the ephemeral port natively in the async thread
client_port_var = contextvars.ContextVar("client_port", default="unknown_port")

# 2. FastAPI Middleware: Catch the port and inject oracle status for Chat API
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

    # ── Oracle status injection (Chat Completions API) ──────────────
    # For Chat API requests routed through LiteLLM, inject the oracle
    # status into the messages list before LiteLLM processes them.
    path = request.url.path.rstrip("/")
    if path in {"/v1/chat/completions", "/chat/completions"}:
        oracle_user_directive = await _build_oracle_user_directive()
        if oracle_user_directive:
            try:
                body = await request.body()
                if body:
                    payload = json.loads(body.decode("utf-8"))
                    if isinstance(payload, dict) and isinstance(payload.get("messages"), list):
                        messages = payload["messages"]
                        # Append oracle status so the model can act on the result.
                        messages.append({"role": "user", "content": oracle_user_directive})

                        # Replace the request body in the ASGI scope.
                        modified_body = json.dumps(payload).encode("utf-8")

                        async def _receive():
                            return {"type": "http.request", "body": modified_body}

                        request._receive = _receive
            except Exception:
                pass  # Best-effort; don't break the request on injection failure.

    # Pass the request down the chain
    response = await call_next(request)
    return response

# 3. LiteLLM Custom Logger: Safely grab the request and reconstructed response
class PortBasedFileLogger(CustomLogger):
    def __init__(self, log_dir: str | None = None):
        configured_dir = log_dir or str(_RUNTIME_LAYOUT.proxy_obs_dir)
        if os.path.isabs(configured_dir):
            self.log_dir = configured_dir
        else:
            self.log_dir = str(Path(configured_dir).expanduser())
        os.makedirs(self.log_dir, exist_ok=True)
        PROXY_LOGGER.info("proxy payload log directory configured", extra={"proxy_log_dir": self.log_dir})

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
            PROXY_LOGGER.exception("Failed model_dump_json conversion in proxy serializer")

        try:
            if hasattr(value, "model_dump"):
                dumped = value.model_dump()
                json.dumps(dumped)
                return dumped
        except Exception:
            PROXY_LOGGER.exception("Failed model_dump conversion in proxy serializer")

        try:
            json.dumps(value)
            return value
        except Exception:
            PROXY_LOGGER.exception("Failed JSON serialization in proxy serializer; using string fallback")
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
_PROXY_EVENT_LOGGER = PortBasedFileLogger(log_dir=str(_RUNTIME_LAYOUT.proxy_obs_dir))
litellm.callbacks = [_PROXY_EVENT_LOGGER]

# (The app is automatically exposed via the litellm.proxy.proxy_server import)