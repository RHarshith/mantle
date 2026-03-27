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
                self._show_info(stdscr, "No traces available yet.", title="traces")
                return

            idx = self._select_menu(
                stdscr,
                title="/traces",
                items=trace_ids,
                help_line="Arrow keys to move, Enter to select, q to quit",
            )
            if idx is None:
                return
            selected_trace = trace_ids[idx]
            if not self._trace_summary_screen(stdscr, selected_trace):
                return

    def _trace_summary_screen(self, stdscr: curses.window, trace_id: str) -> bool:
        summary_route = f"{trace_id}/summary"
        while True:
            payload = execute_route(self.cli_store, summary_route)
            metrics = [str(name) for name in payload.meta.get("metrics", []) if name]
            items = [
                "Open summary",
                *[f"Metric: {name}" for name in metrics],
                "Replay turns",
                "Trace files (objects)",
                "Trace pids (objects)",
                "Back",
            ]
            idx = self._select_menu(
                stdscr,
                title=summary_route,
                items=items,
                help_line="Endpoint doubles as menu. Select a route to open.",
            )
            if idx is None:
                return False

            choice = items[idx]
            if choice == "Back":
                return True
            if choice == "Open summary":
                self._open_result(stdscr, payload, force_pager=False)
                continue
            if choice == "Replay turns":
                if not self._turn_list_screen(stdscr, trace_id):
                    return False
                continue
            if choice == "Trace files (objects)":
                if not self._files_tree_menu(stdscr, f"objects/files/trace/{trace_id}"):
                    return False
                continue
            if choice == "Trace pids (objects)":
                if not self._pid_menu(stdscr, f"objects/pids/trace/{trace_id}", scoped=True):
                    return False
                continue
            if choice.startswith("Metric: "):
                metric = choice.split(": ", 1)[1]
                self._open_route(stdscr, f"{summary_route}/metric/{metric}", force_pager=False)

    def _turn_list_screen(self, stdscr: curses.window, trace_id: str) -> bool:
        replay_route = f"{trace_id}/replay"
        while True:
            payload = execute_route(self.cli_store, replay_route)
            turn_ids = [tid for tid in payload.meta.get("turn_ids", []) if tid and tid != "setup"]
            if not turn_ids:
                self._show_info(stdscr, "No replay turns found.", title=replay_route)
                return True

            idx = self._select_menu(
                stdscr,
                title=replay_route,
                items=turn_ids + ["Back"],
                help_line="Select turn (the replay endpoint is the screen)",
            )
            if idx is None:
                return False
            if idx == len(turn_ids):
                return True
            if not self._turn_summary_screen(stdscr, trace_id, turn_ids[idx]):
                return False

    def _turn_summary_screen(self, stdscr: curses.window, trace_id: str, turn_id: str) -> bool:
        summary_route = f"{trace_id}/replay/{turn_id}/summary"
        while True:
            payload = execute_route(self.cli_store, summary_route)
            metrics = [str(name) for name in payload.meta.get("metrics", []) if name]
            sections = [str(name) for name in payload.meta.get("sections", []) if name]
            items = [
                "Open summary",
                *[f"Metric: {name}" for name in metrics],
                *[f"Open: {name}" for name in sections],
                "Back",
            ]
            idx = self._select_menu(
                stdscr,
                title=summary_route,
                items=items,
                help_line="Summary endpoint is the menu for replay turn drilldown",
            )
            if idx is None:
                return False

            choice = items[idx]
            if choice == "Back":
                return True
            if choice == "Open summary":
                self._open_result(stdscr, payload, force_pager=False)
                continue
            if choice.startswith("Metric: "):
                metric = choice.split(": ", 1)[1]
                self._open_route(stdscr, f"{summary_route}/metric/{metric}", force_pager=False)
                continue
            if choice == "Open: context":
                if not self._section_menu(stdscr, f"{trace_id}/replay/{turn_id}/context"):
                    return False
                continue
            if choice == "Open: action":
                if not self._section_menu(stdscr, f"{trace_id}/replay/{turn_id}/action"):
                    return False
                continue
            if choice == "Open: tool-calls":
                self._open_route(stdscr, f"{trace_id}/replay/{turn_id}/tool-calls", force_pager=True)
                continue
            if choice == "Open: files":
                if not self._files_tree_menu(stdscr, f"{trace_id}/replay/{turn_id}/files"):
                    return False
                continue
            if choice == "Open: subprocesses":
                self._open_route(stdscr, f"{trace_id}/replay/{turn_id}/subprocesses", force_pager=True)
                continue
            if choice == "Open: pids":
                if not self._pid_menu(stdscr, f"{trace_id}/replay/{turn_id}/pids", scoped=False):
                    return False

    def _pid_menu(self, stdscr: curses.window, pids_route: str, scoped: bool) -> bool:
        while True:
            payload = execute_route(self.cli_store, pids_route)
            pid_ids = [int(pid) for pid in payload.meta.get("pid_ids", []) if int(pid) > 0]
            if not pid_ids:
                self._open_result(stdscr, payload, force_pager=False)
                return True

            items = [f"pid:{pid}" for pid in pid_ids] + ["Open list", "Back"]
            idx = self._select_menu(
                stdscr,
                title=pids_route,
                items=items,
                help_line="Select a pid to open details",
            )
            if idx is None:
                return False
            if idx == len(pid_ids):
                self._open_result(stdscr, payload, force_pager=False)
                continue
            if idx == len(pid_ids) + 1:
                return True

            pid = pid_ids[idx]
            if scoped:
                if not self._pid_ref_menu(stdscr, f"objects/pids/{pid}"):
                    return False
            else:
                self._open_route(stdscr, f"{pids_route}/{pid}", force_pager=True)

    def _pid_ref_menu(self, stdscr: curses.window, pid_route: str) -> bool:
        while True:
            payload = execute_route(self.cli_store, pid_route)
            refs = list(payload.meta.get("refs", []))
            if not refs:
                self._open_result(stdscr, payload, force_pager=False)
                return True

            labels = [f"{r.get('trace_id')}/{r.get('turn_id')}" for r in refs]
            idx = self._select_menu(
                stdscr,
                title=pid_route,
                items=labels + ["Open pid summary", "Back"],
                help_line="Pick a trace/turn reference for this pid",
            )
            if idx is None:
                return False
            if idx == len(refs):
                self._open_result(stdscr, payload, force_pager=False)
                continue
            if idx == len(refs) + 1:
                return True

            ref = refs[idx]
            trace_id = str(ref.get("trace_id") or "")
            turn_id = str(ref.get("turn_id") or "")
            pid = pid_route.split("/")[-1]
            self._open_route(
                stdscr,
                f"objects/pids/{pid}/trace/{trace_id}/turn/{turn_id}",
                force_pager=True,
            )

    def _files_tree_menu(self, stdscr: curses.window, files_route: str) -> bool:
        stack: list[str] = ["root"]
        while True:
            node_id = stack[-1]
            route = files_route if node_id == "root" else f"{files_route}/node/{node_id}"
            payload = execute_route(self.cli_store, route)
            entries = list(payload.meta.get("entries", []))
            labels = []
            for entry in entries:
                kind = "D" if str(entry.get("kind") or "") == "dir" else "F"
                labels.append(f"[{kind}] {entry.get('name')} ({entry.get('node_id')})")

            nav_items = labels + ["Open Current Node", "Back"]
            idx = self._select_menu(
                stdscr,
                title=route,
                items=nav_items,
                help_line="Choose folder/file to drill down; open current for details",
            )
            if idx is None:
                return False

            if idx < len(entries):
                entry = entries[idx]
                child_id = str(entry.get("node_id") or "")
                if not child_id:
                    continue
                if str(entry.get("kind") or "") == "dir":
                    stack.append(child_id)
                else:
                    self._open_route(stdscr, f"{files_route}/node/{child_id}", force_pager=False)
                continue

            if idx == len(entries):
                self._open_result(stdscr, payload, force_pager=False)
                continue

            if len(stack) > 1:
                stack.pop()
                continue
            return True

    def _section_menu(self, stdscr: curses.window, section_route: str) -> bool:
        while True:
            sections = execute_route(self.cli_store, section_route)
            section_ids = [sid for sid in sections.meta.get("section_ids", []) if sid]
            if not section_ids:
                self._show_info(stdscr, "No sections available.", title=section_route)
                return True

            idx = self._select_menu(
                stdscr,
                title=section_route,
                items=section_ids + ["Back"],
                help_line="Select section to continue",
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
                items=msg_items + ["Open section", "Back"],
                help_line="Open message for full payload",
            )
            if inner_idx is None:
                return False
            if inner_idx == len(msg_items):
                self._open_result(stdscr, details, force_pager=False)
                continue
            if inner_idx == len(msg_items) + 1:
                continue
            msg_index = msg_indices[inner_idx]
            self._open_route(stdscr, f"{section_path}/{msg_index}", force_pager=True)

    def _open_route(self, stdscr: curses.window, route: str, force_pager: bool = False) -> None:
        try:
            result = execute_route(self.cli_store, route)
        except Exception as exc:
            self._show_info(stdscr, str(exc), title="error")
            return
        self._open_result(stdscr, result, force_pager=force_pager)

    def _open_result(self, stdscr: curses.window, result: RouteResult, force_pager: bool = False) -> None:
        use_pager = force_pager or result.pager or len(result.text.splitlines()) > 20
        if use_pager:
            curses.endwin()
            show_text(result.text, title=result.title)
            stdscr.refresh()
            return
        self._show_info(stdscr, result.text, title=result.title)

    def _show_info(self, stdscr: curses.window, message: str, title: str = "Info") -> None:
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
