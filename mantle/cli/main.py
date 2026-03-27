"""Entry point for mantle observability CLI."""

from __future__ import annotations

import argparse
import signal
import sys

from .interactive import InteractiveApp
from .pager import show_text
from .routes import execute_route
from .store import CliStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mantlecli",
        description="CLI observability explorer for trace view and replay view.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="help",
        help="URL-like route (example: <trace_id>/replay/<turn_id>/summary)",
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Open interactive arrow-key navigation mode.",
    )
    parser.add_argument(
        "--obs-root",
        default=None,
        help="Observability root containing traces/events/mitm directories.",
    )
    parser.add_argument(
        "--plain",
        action="store_true",
        help="Never open the pager automatically.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    parser = build_parser()
    args = parser.parse_args(argv)

    cli_store = CliStore(obs_root=args.obs_root)

    if args.interactive:
        app = InteractiveApp(cli_store)
        app.run()
        return 0

    try:
        result = execute_route(cli_store, args.path)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    use_pager = result.pager and not args.plain
    try:
        if use_pager:
            show_text(result.text, title=result.title)
        else:
            print(result.text)
    except BrokenPipeError:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
