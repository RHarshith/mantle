import argparse
import contextlib
import io
import json
import os
import time
import subprocess
import sys
import traceback

from openai import OpenAI
from agent_observability import build_event_sink
# try:
#     from langfuse.openai import OpenAI
# except ImportError:
#     print("Missing dependency: langfuse. Use your virtualenv interpreter or install with 'pip install langfuse'.")
#     sys.exit(1)


PYTHON_EXEC_TOOL = {
    "type": "function",
    "function": {
        "name": "python_exec",
        "description": "Execute Python code and return stdout/stderr.",
        "parameters": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Python code to execute",
                }
            },
            "required": ["code"],
        },
    },
}

COMMAND_EXEC_TOOL = {
    "type": "function",
    "function": {
        "name": "command_exec",
        "description": "Execute a shell command and return stdout/stderr. Use this for file system operations, installing packages, running scripts, git commands, and other CLI tasks.",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds (default: 60)",
                },
            },
            "required": ["command"],
        },
    },
}

ALL_TOOLS = [PYTHON_EXEC_TOOL, COMMAND_EXEC_TOOL]


def log_event(verbose: bool, message: str) -> None:
    if verbose:
        print(f"[agent] {message}")


def prompt_user_approval(tool_name: str, tool_args: dict, auto_approve: bool = False) -> bool:
    """Ask the user to approve a tool call before execution.
    Returns True if approved, False if denied."""
    if auto_approve:
        return True
    print(f"\n{'='*60}")
    print(f"  TOOL CALL APPROVAL REQUIRED")
    print(f"{'='*60}")
    print(f"  Tool:  {tool_name}")
    if tool_name == "python_exec":
        code = tool_args.get("code", "")
        print(f"  Code:\n")
        for line in code.splitlines():
            print(f"    {line}")
    elif tool_name == "command_exec":
        print(f"  Command: {tool_args.get('command', '')}")
        timeout = tool_args.get('timeout', 60)
        print(f"  Timeout: {timeout}s")
    else:
        print(f"  Args: {json.dumps(tool_args, indent=2)}")
    print(f"{'='*60}")

    while True:
        try:
            answer = input("  Approve? [y/n]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\n  Denied (interrupted).")
            return False
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("  Please enter 'y' or 'n'.")


def run_python_exec(code: str, shared_globals: dict) -> str:
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()

    try:
        with contextlib.redirect_stdout(stdout_buffer), contextlib.redirect_stderr(stderr_buffer):
            exec(code, shared_globals)
        result = {
            "ok": True,
            "stdout": stdout_buffer.getvalue(),
            "stderr": stderr_buffer.getvalue(),
        }
    except Exception:
        result = {
            "ok": False,
            "stdout": stdout_buffer.getvalue(),
            "stderr": stderr_buffer.getvalue(),
            "error": traceback.format_exc(),
        }

    return json.dumps(result)


def run_command_exec(command: str, timeout: int = 60) -> str:
    """Execute a shell command and return structured JSON result."""
    try:
        completed = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        result = {
            "ok": completed.returncode == 0,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    except subprocess.TimeoutExpired:
        result = {
            "ok": False,
            "error": f"Command timed out after {timeout} seconds.",
        }
    except Exception:
        result = {
            "ok": False,
            "error": traceback.format_exc(),
        }
    return json.dumps(result)


def extract_assistant_payload(response) -> tuple[str, list[dict]]:
    message_obj = None

    if hasattr(response, "choices"):
        choices = getattr(response, "choices", [])
        if choices:
            message_obj = choices[0].message

    if message_obj is not None:
        content = message_obj.content or ""
        tool_calls = []
        for tool_call in getattr(message_obj, "tool_calls", []) or []:
            tool_calls.append(
                {
                    "id": tool_call.id,
                    "name": tool_call.function.name,
                    "arguments": tool_call.function.arguments or "{}",
                }
            )
        return content, tool_calls

    if isinstance(response, str):
        raw_text = response.strip()
        if raw_text.startswith("data:"):
            payload = sse_text_to_completion_payload(raw_text)
        else:
            try:
                payload = json.loads(raw_text)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"Unexpected non-JSON response string: {response[:200]}") from exc
    elif isinstance(response, dict):
        payload = response
    elif hasattr(response, "model_dump"):
        payload = response.model_dump()
    else:
        raise RuntimeError(f"Unsupported response type: {type(response).__name__}")

    choices = payload.get("choices") or []
    if not choices:
        raise RuntimeError(f"Response payload missing choices: {payload}")

    message = choices[0].get("message") or {}
    content = message.get("content") or ""
    if isinstance(content, list):
        content = "\n".join(
            part.get("text", "") if isinstance(part, dict) else str(part) for part in content
        )

    tool_calls = []
    for tool_call in message.get("tool_calls") or []:
        function_data = tool_call.get("function") or {}
        tool_calls.append(
            {
                "id": tool_call.get("id", "tool_call_unknown"),
                "name": function_data.get("name", ""),
                "arguments": function_data.get("arguments", "{}"),
            }
        )

    return str(content), tool_calls


def sse_text_to_completion_payload(sse_text: str) -> dict:
    content_parts = []
    tool_calls_by_index = {}

    for raw_line in sse_text.splitlines():
        line = raw_line.strip()
        if not line.startswith("data:"):
            continue

        data = line[len("data:") :].strip()
        if not data or data == "[DONE]":
            continue

        try:
            chunk = json.loads(data)
        except json.JSONDecodeError:
            continue

        for choice in chunk.get("choices") or []:
            delta = choice.get("delta") or {}

            if delta.get("content"):
                content_parts.append(delta["content"])

            for tool_call_delta in delta.get("tool_calls") or []:
                idx = tool_call_delta.get("index", 0)
                current = tool_calls_by_index.setdefault(
                    idx,
                    {
                        "id": tool_call_delta.get("id") or f"tool_call_{idx}",
                        "type": "function",
                        "function": {"name": "", "arguments": ""},
                    },
                )

                if tool_call_delta.get("id"):
                    current["id"] = tool_call_delta["id"]

                function_delta = tool_call_delta.get("function") or {}
                if function_delta.get("name"):
                    current["function"]["name"] = function_delta["name"]

                if function_delta.get("arguments"):
                    current["function"]["arguments"] += function_delta["arguments"]

    message = {
        "content": "".join(content_parts),
        "tool_calls": [tool_calls_by_index[idx] for idx in sorted(tool_calls_by_index.keys())],
    }

    return {"choices": [{"message": message}]}


def run_single_turn(
    client: OpenAI,
    model: str,
    messages: list,
    shared_globals: dict,
    sink,
    verbose: bool = False,
    auto_approve: bool = False,
) -> str:
    while True:
        log_event(verbose, f"sending request to model='{model}' with {len(messages)} messages")
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=ALL_TOOLS,
            tool_choice="auto",
            stream=False,
        )

        assistant_content, tool_calls = extract_assistant_payload(response)
        log_event(verbose, f"received response; tool_calls={len(tool_calls)}")

        assistant_message = {
            "role": "assistant",
            "content": assistant_content,
        }

        if tool_calls:
            assistant_message["tool_calls"] = [
                {
                    "id": tool_call["id"],
                    "type": "function",
                    "function": {
                        "name": tool_call["name"],
                        "arguments": tool_call["arguments"],
                    },
                }
                for tool_call in tool_calls
            ]

        messages.append(assistant_message)

        if tool_calls:
            for tool_call in tool_calls:
                tool_name = tool_call["name"]
                tool_args_raw = tool_call.get("arguments", "{}")
                log_event(verbose, f"executing tool '{tool_name}'")

                try:
                    tool_args = json.loads(tool_args_raw or "{}")
                except json.JSONDecodeError:
                    sink.emit(
                        "tool_call_invalid_args",
                        {
                            "tool_call_id": tool_call["id"],
                            "tool_name": tool_name,
                            "arguments_raw": tool_args_raw,
                        },
                    )
                    tool_result = json.dumps(
                        {
                            "ok": False,
                            "error": "Invalid JSON in tool arguments.",
                        }
                    )
                else:
                    sink.emit(
                        "tool_call_started",
                        {
                            "tool_call_id": tool_call["id"],
                            "tool_name": tool_name,
                            "arguments": tool_args,
                        },
                    )

                    # Safety: require explicit user approval before execution
                    if not prompt_user_approval(tool_name, tool_args, auto_approve=auto_approve):
                        sink.emit(
                            "tool_call_denied",
                            {
                                "tool_call_id": tool_call["id"],
                                "tool_name": tool_name,
                            },
                        )
                        tool_result = json.dumps(
                            {
                                "ok": False,
                                "error": "Tool call denied by user.",
                            }
                        )
                    elif tool_name == "python_exec":
                        started_at = time.time()
                        tool_result = run_python_exec(tool_args.get("code", ""), shared_globals)
                        sink.emit(
                            "tool_call_finished",
                            {
                                "tool_call_id": tool_call["id"],
                                "tool_name": tool_name,
                                "duration_ms": int((time.time() - started_at) * 1000),
                                "result": json.loads(tool_result),
                            },
                        )
                    elif tool_name == "command_exec":
                        started_at = time.time()
                        tool_result = run_command_exec(
                            tool_args.get("command", ""),
                            tool_args.get("timeout", 60),
                        )
                        sink.emit(
                            "tool_call_finished",
                            {
                                "tool_call_id": tool_call["id"],
                                "tool_name": tool_name,
                                "duration_ms": int((time.time() - started_at) * 1000),
                                "result": json.loads(tool_result),
                            },
                        )
                    else:
                        sink.emit(
                            "tool_call_unknown",
                            {
                                "tool_call_id": tool_call["id"],
                                "tool_name": tool_name,
                            },
                        )
                        tool_result = json.dumps(
                            {
                                "ok": False,
                                "error": f"Unknown tool: {tool_name}",
                            }
                        )

                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call["id"],
                        "content": tool_result,
                    }
                )
                log_event(verbose, f"tool '{tool_name}' finished and result appended")
            continue

        log_event(verbose, "assistant response ready (no tool call)")
        return assistant_content


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple CLI LLM agent")
    parser.add_argument(
        "prompt",
        nargs="*",
        help="Optional prompt. If provided, runs one turn and exits.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show agent step logs (API calls, tool calls, and response flow).",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Auto-approve all tool calls (no manual approval prompts).",
    )
    parser.add_argument(
        "--task",
        type=str,
        default=None,
        help="Run agent in automated task mode: provide a task description and the agent loops until done.",
    )
    args = parser.parse_args()

    api_key = os.getenv("OAK1")
    base_url = os.getenv("OPENAI_BASE_URL", "https://chat-api.tamu.ai/api")
    model = os.getenv("OPENAI_MODEL", "protected.gpt-5.2")

    if not api_key:
        raise RuntimeError("Missing OAK1 environment variable.")

    client = OpenAI(api_key=api_key, base_url=base_url)
    sink = build_event_sink()

    messages = []
    shared_globals = {"__builtins__": __builtins__}
    verbose = args.verbose or os.getenv("AGENT_VERBOSE", "").strip().lower() in {"1", "true", "yes", "on"}
    auto_approve = args.auto or os.getenv("AGENT_AUTO_APPROVE", "").strip().lower() in {"1", "true", "yes", "on"}

    cli_prompt = " ".join(args.prompt).strip()
    task_prompt = args.task

    # ── Automated task mode ──────────────────────────────────────
    if task_prompt:
        log_event(verbose, "running automated task mode")
        sink.emit(
            "session_started",
            {
                "mode": "task",
                "model": model,
                "base_url": base_url,
            },
        )
        sink.emit("user_prompt", {"content": task_prompt})
        messages.append({"role": "user", "content": task_prompt})
        max_turns = int(os.getenv("AGENT_MAX_TURNS", "20"))
        for turn in range(max_turns):
            log_event(verbose, f"task turn {turn + 1}/{max_turns}")
            try:
                assistant_output = run_single_turn(
                    client, model, messages, shared_globals, sink,
                    verbose=verbose, auto_approve=auto_approve,
                )
            except Exception as exc:
                sink.emit("agent_error", {"error": str(exc)})
                print(f"assistant> Request failed: {exc}")
                break
            sink.emit("assistant_response", {"content": assistant_output.strip()})
            print(f"assistant> {assistant_output.strip()}")
            # If the last response had no tool calls, agent is done
            last_msg = messages[-1] if messages else {}
            if last_msg.get("role") == "assistant" and not last_msg.get("tool_calls"):
                log_event(verbose, "agent completed task (no more tool calls)")
                break
        sink.emit("session_ended", {"reason": "task_complete"})
        sink.close()
        return

    # ── One-shot mode ────────────────────────────────────────────
    if cli_prompt:
        log_event(verbose, "running one-shot mode from CLI prompt")
        sink.emit(
            "session_started",
            {
                "mode": "oneshot",
                "model": model,
                "base_url": base_url,
            },
        )
        sink.emit("user_prompt", {"content": cli_prompt})
        messages.append({"role": "user", "content": cli_prompt})
        try:
            assistant_output = run_single_turn(client, model, messages, shared_globals, sink, verbose=verbose, auto_approve=auto_approve)
        except Exception as exc:
            sink.emit("agent_error", {"error": str(exc)})
            print(f"assistant> Request failed: {exc}")
            sink.close()
            return
        sink.emit("assistant_response", {"content": assistant_output.strip()})
        sink.emit("session_ended", {"reason": "oneshot_complete"})
        sink.close()
        log_event(verbose, "printing assistant response")
        print(f"assistant> {assistant_output.strip()}")
        return

    print("CLI agent started. Press Ctrl+C or Ctrl+D to stop.")
    sink.emit(
        "session_started",
        {
            "mode": "interactive",
            "model": model,
            "base_url": base_url,
        },
    )

    while True:
        try:
            user_prompt = input("you> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            sink.emit("session_ended", {"reason": "user_exit"})
            sink.close()
            break

        if not user_prompt:
            continue

        sink.emit("user_prompt", {"content": user_prompt})
        messages.append({"role": "user", "content": user_prompt})

        try:
            assistant_output = run_single_turn(client, model, messages, shared_globals, sink, verbose=verbose, auto_approve=auto_approve)
        except Exception as exc:
            sink.emit("agent_error", {"error": str(exc)})
            print(f"assistant> Request failed: {exc}")
            continue

        sink.emit("assistant_response", {"content": assistant_output.strip()})
        log_event(verbose, "printing assistant response")
        print(f"assistant> {assistant_output.strip()}")


if __name__ == "__main__":
    main()
