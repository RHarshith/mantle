"""Interactive arrow-key TUI built on top of URL-style CLI routes."""

from __future__ import annotations

import curses
from typing import Sequence

from .pager import show_text
from .routes import RouteResult, execute_route
from .store import CliStore


class InteractiveApp:
    """Curses-based navigator that reuses non-interactive route handlers."""

    def __init__(self, cli_store: CliStore):
        self.cli_store = cli_store

    def run(self) -> None:
        curses.wrapper(self._run)

    def _run(self, stdscr: curses.window) -> None:
        curses.curs_set(0)
        while True:
            traces_result = execute_route(self.cli_store, "traces")
            trace_ids = [tid for tid in traces_result.meta.get("trace_ids", []) if tid]
            if not trace_ids:
                self._show_error(stdscr, "No traces available yet.")
                return

            idx = self._select_menu(
                stdscr,
                title="Select Trace",
                items=trace_ids,
                help_line="Arrow keys to move, Enter to select, q to quit",
            )
            if idx is None:
                return
            selected_trace = trace_ids[idx]
            if not self._trace_menu(stdscr, selected_trace):
                return

    def _trace_menu(self, stdscr: curses.window, trace_id: str) -> bool:
        items = ["Trace View", "Replay Trace", "Trace Summary", "Back"]
        while True:
            idx = self._select_menu(
                stdscr,
                title=f"Trace: {trace_id}",
                items=items,
                help_line="Arrow keys, Enter to select, q to quit",
            )
            if idx is None:
                return False
            choice = items[idx]
            if choice == "Back":
                return True
            if choice == "Trace Summary":
                self._open_route(stdscr, f"{trace_id}/summary", force_pager=True)
                continue
            if choice == "Trace View":
                if not self._turn_menu(stdscr, trace_id, mode="trace"):
                    return False
            if choice == "Replay Trace":
                if not self._turn_menu(stdscr, trace_id, mode="replay"):
                    return False

    def _turn_menu(self, stdscr: curses.window, trace_id: str, mode: str) -> bool:
        root_route = f"{trace_id}/{mode}"
        while True:
            listing = execute_route(self.cli_store, root_route)
            turn_ids = [tid for tid in listing.meta.get("turn_ids", []) if tid and tid != "setup"]
            if not turn_ids:
                self._show_error(stdscr, f"No turns found for {mode}.")
                return True
            idx = self._select_menu(
                stdscr,
                title=f"{trace_id} / {mode} / turns",
                items=turn_ids + ["Back"],
                help_line="Arrow keys, Enter to select, b to back, q to quit",
            )
            if idx is None:
                return False
            if idx == len(turn_ids):
                return True
            turn_id = turn_ids[idx]
            if mode == "trace":
                ok = self._trace_turn_menu(stdscr, trace_id, turn_id)
            else:
                ok = self._replay_turn_menu(stdscr, trace_id, turn_id)
            if not ok:
                return False

    def _trace_turn_menu(self, stdscr: curses.window, trace_id: str, turn_id: str) -> bool:
        items = [
            "Summary",
            "Prompt Sections",
            "Response Sections",
            "Timeline",
            "Process Subtrace (by PID)",
            "Back",
        ]
        while True:
            idx = self._select_menu(
                stdscr,
                title=f"{trace_id}/trace/{turn_id}",
                items=items,
                help_line="Arrow keys, Enter to select, b to back, q to quit",
            )
            if idx is None:
                return False
            choice = items[idx]
            if choice == "Back":
                return True
            if choice == "Summary":
                self._open_route(stdscr, f"{trace_id}/trace/{turn_id}/summary")
            elif choice == "Prompt Sections":
                if not self._section_menu(stdscr, f"{trace_id}/trace/{turn_id}/prompt"):
                    return False
            elif choice == "Response Sections":
                if not self._section_menu(stdscr, f"{trace_id}/trace/{turn_id}/response"):
                    return False
            elif choice == "Timeline":
                if not self._timeline_menu(stdscr, f"{trace_id}/trace/{turn_id}"):
                    return False
            elif choice == "Process Subtrace (by PID)":
                pid_value = self._prompt_value(stdscr, "Enter pid")
                if pid_value is None:
                    continue
                self._open_route(stdscr, f"{trace_id}/trace/{turn_id}/process/{pid_value}", force_pager=True)

    def _replay_turn_menu(self, stdscr: curses.window, trace_id: str, turn_id: str) -> bool:
        items = [
            "Summary",
            "Context Sections",
            "Action Sections",
            "Tool Calls",
            "Files",
            "Subprocesses",
            "Back",
        ]
        while True:
            idx = self._select_menu(
                stdscr,
                title=f"{trace_id}/replay/{turn_id}",
                items=items,
                help_line="Arrow keys, Enter to select, b to back, q to quit",
            )
            if idx is None:
                return False
            choice = items[idx]
            if choice == "Back":
                return True
            if choice == "Summary":
                self._open_route(stdscr, f"{trace_id}/replay/{turn_id}/summary")
            elif choice == "Context Sections":
                if not self._section_menu(stdscr, f"{trace_id}/replay/{turn_id}/context"):
                    return False
            elif choice == "Action Sections":
                if not self._section_menu(stdscr, f"{trace_id}/replay/{turn_id}/action"):
                    return False
            elif choice == "Tool Calls":
                self._open_route(stdscr, f"{trace_id}/replay/{turn_id}/tool-calls", force_pager=True)
            elif choice == "Files":
                self._open_route(stdscr, f"{trace_id}/replay/{turn_id}/files", force_pager=True)
            elif choice == "Subprocesses":
                self._open_route(stdscr, f"{trace_id}/replay/{turn_id}/subprocesses", force_pager=True)

    def _timeline_menu(self, stdscr: curses.window, base_turn_path: str) -> bool:
        listing = execute_route(self.cli_store, f"{base_turn_path}/timeline")
        lines = listing.text.splitlines()
        entries: list[str] = []
        for line in lines:
            if line.startswith("[") and "]" in line:
                entries.append(line)
        if not entries:
            self._show_error(stdscr, "No timeline entries available.")
            return True
        while True:
            idx = self._select_menu(
                stdscr,
                title=f"{base_turn_path}/timeline",
                items=entries + ["Back"],
                help_line="Arrow keys, Enter to open entry, b to back, q to quit",
            )
            if idx is None:
                return False
            if idx == len(entries):
                return True
            prefix = entries[idx].split("]", 1)[0].lstrip("[")
            self._open_route(stdscr, f"{base_turn_path}/timeline/{prefix}", force_pager=True)

    def _section_menu(self, stdscr: curses.window, section_route: str) -> bool:
        sections = execute_route(self.cli_store, section_route)
        section_ids = [sid for sid in sections.meta.get("section_ids", []) if sid]
        if not section_ids:
            self._show_error(stdscr, "No sections available.")
            return True

        while True:
            idx = self._select_menu(
                stdscr,
                title=section_route,
                items=section_ids + ["Back"],
                help_line="Arrow keys, Enter to select section, b to back, q to quit",
            )
            if idx is None:
                return False
            if idx == len(section_ids):
                return True

            section_id = section_ids[idx]
            section_path = f"{section_route}/{section_id}"
            details = execute_route(self.cli_store, section_path)
            msg_indices = details.meta.get("message_indices", [])
            if not msg_indices:
                self._open_result(stdscr, details, force_pager=False)
                continue

            msg_items = [f"message[{i}]" for i in msg_indices]
            inner_idx = self._select_menu(
                stdscr,
                title=section_path,
                items=msg_items + ["Back"],
                help_line="Arrow keys, Enter to open message, b to back, q to quit",
            )
            if inner_idx is None:
                return False
            if inner_idx == len(msg_items):
                continue
            msg_index = msg_indices[inner_idx]
            self._open_route(stdscr, f"{section_path}/{msg_index}", force_pager=True)

    def _prompt_value(self, stdscr: curses.window, label: str) -> str | None:
        curses.curs_set(1)
        stdscr.clear()
        stdscr.addstr(1, 2, label)
        stdscr.addstr(2, 2, "Press Enter to submit. Empty input cancels.")
        stdscr.addstr(4, 2, "> ")
        stdscr.refresh()
        curses.echo()
        raw = stdscr.getstr(4, 4, 128)
        curses.noecho()
        curses.curs_set(0)
        value = raw.decode("utf-8", errors="ignore").strip()
        if not value:
            return None
        return value

    def _open_route(self, stdscr: curses.window, route: str, force_pager: bool = False) -> None:
        try:
            result = execute_route(self.cli_store, route)
        except Exception as exc:
            self._show_error(stdscr, str(exc))
            return
        self._open_result(stdscr, result, force_pager=force_pager)

    def _open_result(self, stdscr: curses.window, result: RouteResult, force_pager: bool = False) -> None:
        use_pager = force_pager or result.pager or len(result.text.splitlines()) > 20
        if use_pager:
            curses.endwin()
            show_text(result.text, title=result.title)
            stdscr.refresh()
            return
        self._show_error(stdscr, result.text, title=result.title)

    def _show_error(self, stdscr: curses.window, message: str, title: str = "Info") -> None:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        stdscr.addstr(1, 2, title[: max(0, w - 4)], curses.A_BOLD)
        lines = str(message or "").splitlines() or [""]
        for idx, line in enumerate(lines[: max(1, h - 4)]):
            stdscr.addstr(3 + idx, 2, line[: max(0, w - 4)])
        stdscr.addstr(h - 2, 2, "Press any key to continue")
        stdscr.refresh()
        stdscr.getch()

    def _select_menu(
        self,
        stdscr: curses.window,
        title: str,
        items: Sequence[str],
        help_line: str,
    ) -> int | None:
        idx = 0
        while True:
            stdscr.clear()
            h, w = stdscr.getmaxyx()
            stdscr.addstr(1, 2, title[: max(0, w - 4)], curses.A_BOLD)
            stdscr.addstr(2, 2, help_line[: max(0, w - 4)])

            top = 4
            visible = max(1, h - top - 2)
            start = 0
            if idx >= visible:
                start = idx - visible + 1
            window_items = list(items[start : start + visible])

            for row, item in enumerate(window_items):
                absolute = start + row
                attr = curses.A_REVERSE if absolute == idx else curses.A_NORMAL
                stdscr.addstr(top + row, 4, item[: max(0, w - 8)], attr)

            stdscr.refresh()
            key = stdscr.getch()
            if key in (ord("q"), 27):
                return None
            if key in (ord("b"), curses.KEY_BACKSPACE, 127) and "Back" in items:
                return len(items) - 1
            if key in (curses.KEY_UP, ord("k")):
                idx = (idx - 1) % len(items)
            elif key in (curses.KEY_DOWN, ord("j")):
                idx = (idx + 1) % len(items)
            elif key in (curses.KEY_ENTER, 10, 13):
                return idx
