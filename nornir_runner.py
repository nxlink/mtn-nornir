#!/usr/bin/env python3
"""
General-purpose Nornir runner for network devices.

Features:
- Accepts multiple hosts, commands, SSH ports, and credential pairs.
- Tries all port/credential combinations per host until one succeeds.
- Supports show (read-only) and config (change) modes.
- Concurrency control via --workers (Nornir threaded runner).
- Defaults can be sourced from a CLI-specified defaults file (YAML/JSON). Minimal .env is reserved for inventory source vars.

Dependencies:
  pip install -r requirements.txt

Example:
  python nornir_runner.py \
    --hosts 10.0.0.1,10.0.0.2 \
    --commands "show version","show ip int br" \
    --defaults-file lab/defaults.yaml \
    --mode show

  # Using config mode with commands file and defaults file
  python nornir_runner.py --hosts-file hosts.txt --commands-file cmds.txt --defaults-file lab/defaults.yaml --mode config
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple

try:
    from dotenv import load_dotenv  # type: ignore
except Exception:
    load_dotenv = None  # optional; script still works if environment already exported

# Optional YAML support for defaults file
try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    yaml = None

from nornir import InitNornir
from nornir.core import Nornir as NornirCore
from nornir.core.configuration import Config as NornirConfig, RunnerConfig as NornirRunnerConfig, LoggingConfig as NornirLoggingConfig
from nornir.core.inventory import Inventory as NornirInventory, Hosts as NornirHosts, Host as NornirHost, Groups as NornirGroups, Defaults as NornirDefaults
from nornir.plugins.runners import ThreadedRunner
from nornir.core.plugins.connections import ConnectionPluginRegister
try:
    # Nornir 3.x defines ConnectionOptions in core.inventory
    from nornir.core.inventory import ConnectionOptions  # type: ignore
except Exception as e:  # pragma: no cover - friendlier error for missing/wrong Nornir
    import sys as _sys
    msg = (
        "Missing or incompatible Nornir installation.\n"
        "This script targets Nornir >=3 (tested with 3.5).\n\n"
        "Fix: activate your venv and install requirements:\n"
        "  python3 -m venv venv\n"
        "  source venv/bin/activate\n"
        "  pip install -r requirements.txt\n\n"
        "If you are pinned to Nornir 2.x, please upgrade or adapt the script."
    )
    print(msg, file=_sys.stderr)
    raise
from nornir.core.task import Task, Result
from nornir_utils.plugins.functions import print_result
import logging
from nornir_netmiko.tasks import netmiko_send_command, netmiko_send_config
import io
from contextlib import redirect_stdout
from datetime import datetime
try:
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException  # type: ignore
except Exception:
    NetmikoAuthenticationException = tuple()  # type: ignore
    NetmikoTimeoutException = tuple()  # type: ignore
try:
    from paramiko.ssh_exception import SSHException  # type: ignore
except Exception:  # pragma: no cover
    SSHException = tuple()  # type: ignore
import threading
import time


class ProgressTable:
    """Thread-safe, colorful live table for worker slots.

    Shows columns: Slot, Host, Status, Attempts, Time. Uses ANSI colors and a spinner.
    """

    # ANSI color codes
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"
    FG_RED = "\x1b[31m"
    FG_GREEN = "\x1b[32m"
    FG_YELLOW = "\x1b[33m"
    FG_BLUE = "\x1b[34m"
    FG_MAGENTA = "\x1b[35m"
    FG_CYAN = "\x1b[36m"
    FG_WHITE = "\x1b[37m"

    SPINNER_FRAMES = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]

    def __init__(self, num_slots: int):
        self.num_slots = int(max(1, num_slots))
        self._lock = threading.Lock()
        self._host_to_slot: dict[str, int] = {}
        self._rows: list[tuple[str, str]] = [("", "idle")] * self.num_slots
        self._attempts: dict[str, int] = {}
        self._start_ts: dict[str, float] = {}
        self._frame = 0
        self._stop = threading.Event()
        self._renderer: threading.Thread | None = None
        self._lines_printed = 0

    @staticmethod
    def _color_status(status: str) -> str:
        # Normalize for matching: trim padding and leading spinner/symbols
        s = status.strip().lower()
        # remove any leading spinner and space
        s = s.lstrip("⣾⣽⣻⢿⡿⣟⣯⣷ ")
        if ("failed" in s) or ("error" in s):
            color = ProgressTable.FG_RED
        elif ("done" in s) or ("connected" in s):
            color = ProgressTable.FG_GREEN
        elif s.startswith("config"):
            color = ProgressTable.FG_MAGENTA
        elif s.startswith("show"):
            color = ProgressTable.FG_CYAN
        elif ("connect" in s) or s.startswith("starting"):
            color = ProgressTable.FG_YELLOW
        elif s == "idle":
            color = ProgressTable.DIM
        else:
            color = ProgressTable.FG_WHITE
        # Pad already handled by caller; wrap with color
        return f"{color}{status}{ProgressTable.RESET}"

    def allocate(self, host: str) -> int:
        with self._lock:
            if host in self._host_to_slot:
                return self._host_to_slot[host]
            # find first idle slot
            for idx, (h, status) in enumerate(self._rows):
                if not h or status == "idle":
                    self._rows[idx] = (host, "starting")
                    self._host_to_slot[host] = idx
                    self._attempts[host] = 0
                    self._start_ts[host] = time.time()
                    return idx
            # if no idle slot (shouldn't happen given capacity), reuse last
            idx = (len(self._rows) - 1)
            self._rows[idx] = (host, "starting")
            self._host_to_slot[host] = idx
            self._attempts[host] = 0
            self._start_ts[host] = time.time()
            return idx

    def update(self, host: str, status: str) -> None:
        with self._lock:
            slot = self._host_to_slot.get(host)
            if slot is None:
                slot = self.allocate(host)
            # try to extract attempt number
            st = status.lower()
            if st.startswith("connect #"):
                try:
                    num = int(st.split("#", 1)[1].split()[0])
                    self._attempts[host] = max(self._attempts.get(host, 0), num)
                except Exception:
                    pass
            elif st.startswith("failed attempt"):
                try:
                    num = int(st.split()[2].rstrip(":"))
                    self._attempts[host] = max(self._attempts.get(host, 0), num)
                except Exception:
                    pass
            self._rows[slot] = (host, status)

    def release(self, host: str, final_status: str | None = None) -> None:
        with self._lock:
            slot = self._host_to_slot.pop(host, None)
            if slot is None:
                return
            # Immediately free the slot so it can be reused by the next host
            self._rows[slot] = ("", "idle")
            # Clear attempts and start time for this host
            try:
                self._attempts.pop(host, None)
                self._start_ts.pop(host, None)
            except Exception:
                pass

    def _render_lines(self) -> list[str]:
        with self._lock:
            rows = list(self._rows)
            attempts = dict(self._attempts)
            starts = dict(self._start_ts)
        self._frame = (self._frame + 1) % len(self.SPINNER_FRAMES)
        spin = self.SPINNER_FRAMES[self._frame]

        # column widths (widened status for longer messages)
        w_slot, w_host, w_status, w_att, w_time = 4, 28, 50, 8, 6

        def top_border():
            return f"┌{'─'*w_slot}┬{'─'*w_host}┬{'─'*w_status}┬{'─'*w_att}┬{'─'*w_time}┐"

        def mid_border():
            return f"├{'─'*w_slot}┼{'─'*w_host}┼{'─'*w_status}┼{'─'*w_att}┼{'─'*w_time}┤"

        def bot_border():
            return f"└{'─'*w_slot}┴{'─'*w_host}┴{'─'*w_status}┴{'─'*w_att}┴{'─'*w_time}┘"

        header = (
            f"│{self.BOLD}{'Slot':^{w_slot}}{self.RESET}"
            f"│{self.BOLD}{'Host':^{w_host}}{self.RESET}"
            f"│{self.BOLD}{'Status':^{w_status}}{self.RESET}"
            f"│{self.BOLD}{'Attempts':^{w_att}}{self.RESET}"
            f"│{self.BOLD}{'Time':^{w_time}}{self.RESET}│"
        )

        lines = [self.FG_CYAN + top_border() + self.RESET, header, self.FG_CYAN + mid_border() + self.RESET]

        now = time.time()
        for i, (host, status) in enumerate(rows, start=1):
            raw_host = host if host else "(idle)"
            # time elapsed
            start_ts = starts.get(host)
            elapsed = int(now - start_ts) if (host and start_ts) else 0
            mm = elapsed // 60
            ss = elapsed % 60
            tstr = f"{mm:02d}:{ss:02d}" if elapsed else "--:--"
            # attempts
            att = attempts.get(host, 0)
            att_str = str(att) if att else "-"
            # spinner active if not idle/done
            s_lower = status.lower()
            active = bool(host) and not (s_lower.startswith("done") or s_lower == "idle")
            spin_char = spin if active else " "

            # build padded cells (center all columns)
            c_slot = f"{i:^{w_slot}}"
            c_host = f"{raw_host:^{w_host}}"
            status_with_spin = f"{spin_char} {status}" if active else f"  {status}"
            c_status_plain = f"{status_with_spin:^{w_status}}"
            c_status = self._color_status(c_status_plain)
            c_att = f"{att_str:^{w_att}}"
            c_time = f"{tstr:^{w_time}}"

            lines.append(f"│{c_slot}│{c_host}│{c_status}│{c_att}│{c_time}│")

        lines.append(self.FG_CYAN + bot_border() + self.RESET)
        return lines

    def start(self, interval: float = 0.2):
        if self._renderer and self._renderer.is_alive():
            return
        self._stop.clear()

        def _loop():
            while not self._stop.is_set():
                lines = self._render_lines()
                self._print_lines(lines)
                time.sleep(interval)
            # final render on stop
            self._print_lines(self._render_lines())

        self._renderer = threading.Thread(target=_loop, name="progress-table", daemon=True)
        self._renderer.start()

    def stop(self):
        self._stop.set()
        if self._renderer and self._renderer.is_alive():
            self._renderer.join(timeout=1.0)

    def _print_lines(self, lines: list[str]):
        try:
            # Move cursor up to overwrite previous frame
            if self._lines_printed:
                sys.stdout.write(f"\x1b[{self._lines_printed}A")
            for ln in lines:
                sys.stdout.write("\x1b[2K" + ln + "\n")  # clear line, print
            sys.stdout.flush()
            self._lines_printed = len(lines)
        except Exception:
            pass


def announce(task: Task, message: str, level: int = logging.INFO, live: bool | None = None) -> Result:
    """Lightweight subtask to emit progress messages and optionally print live."""
    if live:
        try:
            sys.stdout.write(f"[{task.host.name}] {message}\n")
            sys.stdout.flush()
        except Exception:
            pass
    return Result(host=task.host, result=message, changed=False, severity_level=level)


def parse_list_arg(value: str | None) -> List[str]:
    if not value:
        return []
    # Support comma-separated or newline-separated lists
    parts: List[str] = []
    for chunk in value.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts.append(chunk)
    return parts


def read_lines_file(path: str | Path) -> List[str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")
    return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]


def parse_credentials_env(value: str | None) -> List[Tuple[str, str]]:
    """
    Parse credential pairs from env.

    Accepted formats (choose one):
    - Semicolon-separated username:password pairs, e.g. "user1:pass1;user2:pass2"
    - JSON array of objects: '[{"username": "u", "password": "p"}, ...]'
    """
    if not value:
        return []

    value = value.strip()
    # Try JSON first if it looks like JSON
    if (value.startswith("[") and value.endswith("]")) or (value.startswith("{") and value.endswith("}")):
        try:
            parsed = json.loads(value)
            pairs: List[Tuple[str, str]] = []
            if isinstance(parsed, dict):
                parsed = [parsed]
            if isinstance(parsed, list):
                for item in parsed:
                    if not isinstance(item, dict):
                        continue
                    u = item.get("username")
                    p = item.get("password")
                    if u and p:
                        pairs.append((str(u), str(p)))
            return pairs
        except Exception:
            pass  # fall back to delimiter-based format

    # Semicolon-separated username:password
    pairs = []
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        if ":" not in chunk:
            continue
        u, p = chunk.split(":", 1)
        pairs.append((u.strip(), p.strip()))
    return pairs


def load_env(env_file: str | None) -> None:
    if env_file and load_dotenv:
        load_dotenv(env_file)
    elif load_dotenv:
        # Load default .env in cwd if present
        default_env = Path(".env")
        if default_env.exists():
            load_dotenv(str(default_env))


@dataclass
class Defaults:
    ports: List[int]
    credentials: List[Tuple[str, str]]
    platform: str | None
    workers: int | None
    timeout: int | None
    enable_secret: str | None
    # Extended config options the user may prefer to set in defaults file
    mode: str | None
    hosts: List[str]
    hosts_file: str | None
    commands: List[str]
    commands_file: str | None
    inventory_dir: str | None
    save_dir: str | None
    per_command_output: bool | None
    quiet: bool | None
    dry_run: bool | None
    env_file: str | None
    live_progress: bool | None
    live_table: bool | None
    log_file: str | None


def parse_credentials_mixed(value) -> List[Tuple[str, str]]:
    """Accept a variety of credential list formats.

    Supported:
      - List of objects with username/password keys
      - List of "username:password" strings
      - Semicolon-separated string "u1:p1;u2:p2" (compat)
    """
    if value is None:
        return []
    if isinstance(value, str):
        return parse_credentials_env(value)
    pairs: List[Tuple[str, str]] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                if ":" in item:
                    u, p = item.split(":", 1)
                    pairs.append((u.strip(), p.strip()))
            elif isinstance(item, dict):
                u = item.get("username")
                p = item.get("password")
                if u and p:
                    pairs.append((str(u), str(p)))
    elif isinstance(value, dict):
        # Single mapping
        u = value.get("username")
        p = value.get("password")
        if u and p:
            pairs.append((str(u), str(p)))
    return pairs


def load_defaults_file(path: str | Path | None) -> Defaults:
    if not path:
        # empty defaults; env/CLI must provide
        return Defaults(
            ports=[],
            credentials=[],
            platform=None,
            workers=None,
            timeout=None,
            enable_secret=None,
            mode=None,
            hosts=[],
            hosts_file=None,
            commands=[],
            commands_file=None,
            inventory_dir=None,
            save_dir=None,
            per_command_output=None,
            quiet=None,
            dry_run=None,
            env_file=None,
            live_progress=None,
            live_table=None,
            log_file=None,
        )
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Defaults file not found: {p}")
    text = p.read_text(encoding="utf-8")
    data = None
    try:
        if p.suffix.lower() in {".yaml", ".yml"}:
            if not yaml:
                raise RuntimeError("PyYAML not installed. Install pyyaml or use JSON defaults file.")
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)
    except Exception as e:
        raise RuntimeError(f"Failed to parse defaults file {p}: {e}")

    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise RuntimeError("Defaults file must be a mapping/object at top level")

    ports = []
    if "ports" in data and data["ports"] is not None:
        if isinstance(data["ports"], str):
            ports = [int(x.strip()) for x in str(data["ports"]).split(",") if str(x).strip()]
        elif isinstance(data["ports"], list):
            ports = [int(x) for x in data["ports"]]

    credentials = parse_credentials_mixed(data.get("credentials"))

    platform = data.get("platform")
    platform = str(platform) if platform is not None else None

    workers = data.get("workers")
    workers = int(workers) if workers is not None else None

    timeout = data.get("timeout")
    timeout = int(timeout) if timeout is not None else None

    enable_secret = data.get("enable_secret")
    enable_secret = str(enable_secret) if enable_secret is not None else None

    # Extended options
    mode = data.get("mode")
    mode = str(mode) if mode is not None else None

    # hosts: list or comma-separated string
    hosts_list: List[str] = []
    hosts_val = data.get("hosts")
    if isinstance(hosts_val, list):
        hosts_list = [str(h).strip() for h in hosts_val if str(h).strip()]
    elif isinstance(hosts_val, str):
        hosts_list = [h.strip() for h in hosts_val.split(",") if h.strip()]

    hosts_file = data.get("hosts_file")
    hosts_file = str(hosts_file) if hosts_file is not None else None

    # commands: list or comma-separated string
    commands_list: List[str] = []
    commands_val = data.get("commands")
    if isinstance(commands_val, list):
        commands_list = [str(c).strip() for c in commands_val if str(c).strip()]
    elif isinstance(commands_val, str):
        commands_list = [c.strip() for c in commands_val.split(",") if c.strip()]

    commands_file = data.get("commands_file")
    commands_file = str(commands_file) if commands_file is not None else None

    inventory_dir = data.get("inventory_dir")
    inventory_dir = str(inventory_dir) if inventory_dir is not None else None

    save_dir = data.get("save_dir")
    save_dir = str(save_dir) if save_dir is not None else None

    per_command_output = data.get("per_command_output")
    if isinstance(per_command_output, bool):
        pass
    else:
        per_command_output = None

    quiet = data.get("quiet")
    if isinstance(quiet, bool):
        pass
    else:
        quiet = None

    dry_run = data.get("dry_run")
    if isinstance(dry_run, bool):
        pass
    else:
        dry_run = None

    env_file = data.get("env_file")
    env_file = str(env_file) if env_file is not None else None

    live_progress = data.get("live_progress")
    if isinstance(live_progress, bool):
        pass
    else:
        live_progress = None

    # live table (boolean)
    live_table = data.get("live_table")
    if isinstance(live_table, bool):
        pass
    else:
        live_table = None

    log_file = data.get("log_file")
    log_file = str(log_file) if log_file is not None else None

    return Defaults(
        ports=ports,
        credentials=credentials,
        platform=platform,
        workers=workers,
        timeout=timeout,
        enable_secret=enable_secret,
        mode=mode,
        hosts=hosts_list,
        hosts_file=hosts_file,
        commands=commands_list,
        commands_file=commands_file,
        inventory_dir=inventory_dir,
        save_dir=save_dir,
        per_command_output=per_command_output,
        quiet=quiet,
        dry_run=dry_run,
        env_file=env_file,
        live_progress=live_progress,
        live_table=live_table,
        log_file=log_file,
    )


def normalize_platform(platform: str) -> str:
    p = platform.strip().lower()
    # Minimal alias support, including MikroTik RouterOS
    if p in {"mikrotik", "routeros", "mikrotik_routeros"}:
        return "mikrotik_routeros"
    # Keep user-provided values for other platforms (e.g., cisco_ios, arista_eos)
    return platform


def parse_hosts_with_platform(host_items: Sequence[str]) -> List[Tuple[str, str | None]]:
    """
    Support per-host platform via token syntax: host|platform
    Example: 10.0.0.1|mikrotik_routeros, 10.0.0.2|cisco_ios
    Returns list of (host, platform_or_none)
    """
    out: List[Tuple[str, str | None]] = []
    for item in host_items:
        token = item.strip()
        if not token:
            continue
        if "|" in token:
            h, plat = token.split("|", 1)
            out.append((h.strip(), normalize_platform(plat.strip())))
        else:
            out.append((token, None))
    return out


def build_inventory(hosts_with_plat: Sequence[Tuple[str, str | None]], default_platform: str) -> dict:
    hosts_dict = {}
    for h, p in hosts_with_plat:
        eff_platform = normalize_platform(p or default_platform)
        hosts_dict[h] = {
            "hostname": h,
            "platform": eff_platform,
        }
    return hosts_dict


def try_connect_and_run(
    task: Task,
    commands: Sequence[str],
    mode: str,
    ports: Sequence[int],
    cred_pairs: Sequence[Tuple[str, str]],
    platform: str,
    enable_secret: str | None,
    cmd_timeout: int,
    dry_run: bool,
    per_command_output: bool,
    suppress_output: bool,
    live_progress: bool,
    progress_table: ProgressTable | None,
    save_dir: str | None,
) -> Result:
    last_err: str | None = None

    attempt = 0
    for port in ports:
        for username, password in cred_pairs:
            attempt += 1
            if progress_table is not None:
                progress_table.allocate(task.host.name)
            task.run(task=announce, message=f"Attempt {attempt}: connect {task.host.hostname}:{port} as {username}", live=live_progress)
            if progress_table is not None:
                progress_table.update(task.host.name, f"connect #{attempt} {task.host.hostname}:{port} as {username}")
            # Reset connection with new options each attempt
            task.host.close_connections()
            device_type = normalize_platform(getattr(task.host, "platform", None) or platform)
            task.host.connection_options["netmiko"] = ConnectionOptions(
                hostname=task.host.hostname,
                port=int(port),
                username=username,
                password=password,
                extras={
                    "device_type": device_type,
                    "fast_cli": False,
                    "timeout": cmd_timeout,
                    # Use secret if provided
                    **({"secret": enable_secret} if enable_secret else {}),
                },
            )

            # Attempt to open the connection explicitly to avoid noisy failed task results
            try:
                task.host.get_connection("netmiko", task.nornir.config)
                task.run(task=announce, message=f"Connected: {task.host.hostname}:{port} as {username}", live=live_progress)
                if progress_table is not None:
                    progress_table.update(task.host.name, f"connected {task.host.hostname}:{port} as {username}")
            except (Exception,) as e:
                # Gracefully skip bad credentials/ports without creating failed child results
                last_err = f"{type(e).__name__}: {e} (user={username}, port={port})"
                task.run(task=announce, message=f"Failed attempt {attempt}: {last_err}", level=logging.WARNING, live=live_progress)
                if progress_table is not None:
                    progress_table.update(task.host.name, f"failed attempt {attempt}")
                continue

            # Connection established; now run commands as tasks (these will reuse the open connection)
            try:
                if mode == "show":
                    task.run(task=announce, message=f"Sending {len(commands)} command(s) in show mode", live=live_progress)
                    if progress_table is not None:
                        progress_table.update(task.host.name, f"show: {len(commands)} cmd(s)")
                    outputs = []
                    for cmd in commands:
                        r = task.run(
                            name=f"{task.host.name} | {cmd}",
                            task=netmiko_send_command,
                            command_string=cmd,
                            enable=bool(enable_secret),
                            use_textfsm=False,
                            severity_level=(logging.INFO if (per_command_output and not suppress_output) else logging.DEBUG),
                        )
                        outputs.append(str(r.result))
                    aggregated = "\n".join(outputs)
                    task.host["used_username"] = username
                    task.host["used_port"] = port
                    # Persist the final aggregated output directly on the host to avoid
                    # any ambiguity with MultiResult ordering when saving later
                    task.host["final_output"] = aggregated
                    if per_command_output:
                        # with per-command output, final aggregation is auxiliary; keep low severity
                        res = Result(host=task.host, result=aggregated, changed=False, severity_level=logging.DEBUG)
                    else:
                        res = Result(host=task.host, result=aggregated, changed=False, severity_level=(logging.DEBUG if suppress_output else logging.INFO))
                    # Immediately persist to disk if requested (per-host, per-worker)
                    if save_dir:
                        try:
                            outdir = Path(save_dir)
                            outdir.mkdir(parents=True, exist_ok=True)
                            outfile = outdir / f"{task.host.name}.txt"
                            outfile.write_text(str(aggregated).rstrip("\n") + "\n", encoding="utf-8")
                            task.host["saved_to_disk"] = True
                        except Exception as _e:
                            # Non-fatal; will attempt again in final aggregation phase
                            pass

                    # Close connection and announce
                    try:
                        task.host.close_connections()
                    finally:
                        task.run(task=announce, message="Closed connection", live=live_progress)
                        if progress_table is not None:
                            progress_table.release(task.host.name, final_status="done (show)")
                    return res
                else:  # config mode
                    if dry_run:
                        preview = "\n".join(commands)
                        task.host["used_username"] = username
                        task.host["used_port"] = port
                        task.host["final_output"] = f"DRY-RUN (no changes):\n{preview}"
                        res = Result(host=task.host, result=f"DRY-RUN (no changes):\n{preview}", changed=False, severity_level=(logging.DEBUG if suppress_output else logging.INFO))
                        # Immediately persist to disk if requested (per-host, per-worker)
                        if save_dir:
                            try:
                                outdir = Path(save_dir)
                                outdir.mkdir(parents=True, exist_ok=True)
                                outfile = outdir / f"{task.host.name}.txt"
                                outfile.write_text((f"DRY-RUN (no changes):\n{preview}").rstrip("\n") + "\n", encoding="utf-8")
                                task.host["saved_to_disk"] = True
                            except Exception as _e:
                                pass
                        try:
                            task.host.close_connections()
                        finally:
                            task.run(task=announce, message="Closed connection", live=live_progress)
                            if progress_table is not None:
                                progress_table.release(task.host.name, final_status="done (dry-run)")
                        return res
                    else:
                        task.run(task=announce, message=f"Sending {len(commands)} command(s) in config mode", live=live_progress)
                        if progress_table is not None:
                            progress_table.update(task.host.name, f"config: {len(commands)} cmd(s)")
                        r = task.run(
                            name=f"{task.host.name} | config",
                            task=netmiko_send_config,
                            config_commands=list(commands),
                            severity_level=(logging.INFO if (per_command_output and not suppress_output) else logging.DEBUG),
                        )
                        task.host["used_username"] = username
                        task.host["used_port"] = port
                        task.host["final_output"] = str(r.result)
                        # Immediately persist to disk if requested (per-host, per-worker)
                        if save_dir:
                            try:
                                outdir = Path(save_dir)
                                outdir.mkdir(parents=True, exist_ok=True)
                                outfile = outdir / f"{task.host.name}.txt"
                                outfile.write_text(str(r.result).rstrip("\n") + "\n", encoding="utf-8")
                                task.host["saved_to_disk"] = True
                            except Exception as _e:
                                pass
                        if per_command_output:
                            res = Result(host=task.host, result=str(r.result), changed=True, severity_level=logging.DEBUG)
                        else:
                            res = Result(host=task.host, result=str(r.result), changed=True, severity_level=(logging.DEBUG if suppress_output else logging.INFO))
                        try:
                            task.host.close_connections()
                        finally:
                            task.run(task=announce, message="Closed connection", live=live_progress)
                            if progress_table is not None:
                                progress_table.release(task.host.name, final_status="done (config)")
                        return res
            except Exception as e:
                last_err = f"{type(e).__name__}: {e} (user={username}, port={port})"
                task.run(task=announce, message=f"Error during session: {last_err}", level=logging.WARNING, live=live_progress)
                if progress_table is not None:
                    progress_table.update(task.host.name, "error; retrying")
                continue

    # Exhausted all attempts
    raise RuntimeError(
        last_err or "All credential/port attempts failed with unknown error"
    )


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="General-purpose Nornir network runner")
    p.add_argument("--hosts", help="Comma-separated hostnames/IPs")
    p.add_argument("--hosts-file", help="File with one host per line")
    p.add_argument("--commands", help="Comma-separated commands to run (quote if needed)")
    p.add_argument("--commands-file", help="File with one command per line")
    p.add_argument("--mode", choices=["show", "config"], default=None)
    p.add_argument("--ports", help="Comma-separated SSH ports to try (e.g. 22,2222)")
    p.add_argument("--workers", type=int, default=None)
    p.add_argument(
        "--platform",
        default=None,
        help="Netmiko device_type/platform (e.g. cisco_ios, arista_eos, mikrotik_routeros)",
    )
    p.add_argument("--inventory-dir", help="Directory with SimpleInventory files (hosts.yaml, groups.yaml, defaults.yaml)")
    p.add_argument("--dry-run", action="store_true", help="Do not push config; print what would be sent")
    p.add_argument("--env-file", help="Path to .env file to load")
    p.add_argument("--timeout", type=int, default=None, help="Command/connect timeout seconds")
    p.add_argument(
        "--defaults-file",
        help=(
            "Path to defaults file (YAML/JSON) with ports, credentials, platform, workers, timeout, enable_secret, "
            "and optionally hosts/hosts_file, commands/commands_file, inventory_dir, save_dir, per_command_output, quiet, dry_run, env_file"
        ),
    )
    p.add_argument("--save-dir", help="Directory to save per-host outputs (optional)")
    p.add_argument("--log-file", help="Write screen output to this file instead of stdout")
    p.add_argument(
        "--per-command-output",
        action="store_true",
        help="Print each command result per host; hide aggregated block",
    )
    p.add_argument(
        "--live-progress",
        action="store_true",
        help="Stream real-time progress of connection attempts and steps",
    )
    p.add_argument(
        "--live-table",
        action="store_true",
        help="Render a live table showing worker slot, host, and status",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress Nornir headers; print only raw device output",
    )

    args = p.parse_args(list(argv) if argv is not None else None)

    # Load defaults file (if provided) early so it can influence env/paths
    defaults = load_defaults_file(args.defaults_file)

    # Load env (CLI overrides defaults)
    load_env(args.env_file or defaults.env_file)

    # Gather hosts unless using inventory-dir
    inv_dir_opt = args.inventory_dir or defaults.inventory_dir
    use_inventory_dir = bool(inv_dir_opt)
    hosts_raw: List[str] = []
    hosts_with_plat: List[Tuple[str, str | None]] = []
    if not use_inventory_dir:
        # CLI hosts first
        if args.hosts:
            hosts_raw.extend(parse_list_arg(args.hosts))
        if args.hosts_file:
            hosts_raw.extend(read_lines_file(args.hosts_file))
        # Defaults fallback if still empty
        if not hosts_raw:
            if defaults.hosts:
                hosts_raw.extend([h.strip() for h in defaults.hosts if h.strip()])
            if defaults.hosts_file:
                hosts_raw.extend(read_lines_file(defaults.hosts_file))
        hosts_raw = [h for h in (x.strip() for x in hosts_raw) if h]
        if not hosts_raw:
            print("Error: no hosts provided (use --hosts/--hosts-file or --inventory-dir)", file=sys.stderr)
            return 2
        hosts_with_plat = parse_hosts_with_platform(hosts_raw)

    # Gather commands
    commands: List[str] = []
    if args.commands:
        # Allow commands that contain commas by permitting quoted splitting from shell
        commands.extend([c.strip() for c in args.commands.split(",") if c.strip()])
    if args.commands_file:
        commands.extend(read_lines_file(args.commands_file))
    # Defaults fallback if still empty
    if not commands:
        if defaults.commands:
            commands.extend([c.strip() for c in defaults.commands if c.strip()])
        if defaults.commands_file:
            commands.extend(read_lines_file(defaults.commands_file))
    if not commands:
        print("Error: no commands provided (use --commands or --commands-file)", file=sys.stderr)
        return 2

    # Ports precedence: CLI > defaults file > env > 22
    ports: List[int] = []
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    elif defaults.ports:
        ports = list(defaults.ports)
    elif os.getenv("NORNIR_SSH_PORTS"):
        ports = [int(p.strip()) for p in os.getenv("NORNIR_SSH_PORTS", "").split(",") if p.strip()]
    else:
        ports = [22]

    # Credentials precedence: defaults file > env
    creds = list(defaults.credentials)
    if not creds:
        cred_env = os.getenv("NORNIR_CREDENTIALS") or os.getenv("NR_CREDENTIALS")
        creds = parse_credentials_env(cred_env)
    if not creds:
        print("Error: no credentials provided (use --defaults-file or set NORNIR_CREDENTIALS)", file=sys.stderr)
        return 2

    # Enable secret precedence: CLI has no flag; defaults file > env
    enable_secret = defaults.enable_secret or os.getenv("NORNIR_ENABLE_SECRET") or None

    # Resolve baseline mode/platform/workers/timeout with precedence: CLI > defaults file > env/defaults
    effective_mode = (args.mode or defaults.mode or os.getenv("NORNIR_MODE", "show"))
    effective_platform = normalize_platform(
        (args.platform or defaults.platform or os.getenv("NORNIR_PLATFORM") or "cisco_ios")
    )
    effective_workers = args.workers or defaults.workers or int(os.getenv("NORNIR_WORKERS", "10"))
    effective_timeout = args.timeout or defaults.timeout or int(os.getenv("NORNIR_CMD_TIMEOUT", "30"))

    # Build Nornir instance
    if use_inventory_dir:
        inv_dir = Path(inv_dir_opt)  # type: ignore[arg-type]
        hosts_file = str(inv_dir / "hosts.yaml")
        groups_file = str(inv_dir / "groups.yaml")
        defaults_file = str(inv_dir / "defaults.yaml")
        nr = InitNornir(
            runner={"plugin": "threaded", "options": {"num_workers": int(effective_workers)}},
            inventory={
                "plugin": "SimpleInventory",
                "options": {
                    "host_file": hosts_file,
                    "group_file": groups_file,
                    "defaults_file": defaults_file,
                },
            },
            logging={"enabled": False},
        )
    else:
        # Build in-memory inventory using core classes (no plugin required)
        inv_hosts = NornirHosts()
        for h, meta in build_inventory(hosts_with_plat, effective_platform).items():
            inv_hosts[h] = NornirHost(
                name=h,
                hostname=meta.get("hostname", h),
                platform=meta.get("platform", effective_platform),
            )
        inv = NornirInventory(hosts=inv_hosts, groups=NornirGroups(), defaults=NornirDefaults())
        # Ensure connection plugins (e.g., netmiko) are registered when bypassing InitNornir
        ConnectionPluginRegister.auto_register()

        runner_obj = ThreadedRunner(num_workers=int(effective_workers))
        cfg = NornirConfig(
            runner=NornirRunnerConfig(plugin="threaded", options={"num_workers": int(effective_workers)}),
            logging=NornirLoggingConfig(enabled=False),
        )
        nr = NornirCore(inventory=inv, runner=runner_obj, config=cfg)

    # Run task over all hosts
    # Effective booleans/flags merged with defaults (CLI overrides)
    effective_per_cmd_out = bool(args.per_command_output or (defaults.per_command_output is True))
    effective_quiet = bool(args.quiet or (defaults.quiet is True))
    effective_dry_run = bool(args.dry_run or (defaults.dry_run is True))

    # Determine if we should suppress printing command outputs when saving
    save_dir_opt = args.save_dir or defaults.save_dir
    suppress_output = bool(save_dir_opt)

    effective_live_progress = bool(args.live_progress or (defaults.live_progress is True))
    effective_live_table = bool(args.live_table or (defaults.live_table is True))

    # Initialize live table renderer if requested
    progress_table: ProgressTable | None = None
    if effective_live_table:
        progress_table = ProgressTable(num_slots=int(effective_workers))
        progress_table.start()

    # Ensure save directory exists before workers start (avoids race on first write)
    if save_dir_opt:
        try:
            Path(save_dir_opt).mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    result = nr.run(
        name=f"run-{effective_mode}",
        task=try_connect_and_run,
        commands=commands,
        mode=effective_mode,
        ports=ports,
        cred_pairs=creds,
        platform=effective_platform,
        enable_secret=enable_secret,
        cmd_timeout=int(effective_timeout),
        dry_run=effective_dry_run,
        per_command_output=effective_per_cmd_out,
        suppress_output=suppress_output,
        live_progress=effective_live_progress,
        progress_table=progress_table,
        save_dir=save_dir_opt,
    )

    # Stop live table renderer (if running) before printing results
    if progress_table is not None:
        progress_table.stop()

    # When saving outputs, suppress printing raw command output to screen but keep progress
    if suppress_output:
        effective_quiet = False

    # Determine logging to file vs stdout
    log_file_opt = args.log_file or defaults.log_file

    if not log_file_opt:
        if not effective_quiet:
            print_result(result)
        else:
            # Quiet mode: print only the top-level task result per host
            # Note: the last child may be a trailing announce (e.g., "Closed connection").
            # The top-level task result is at index 0.
            for host, multi_result in result.items():
                top_res = multi_result[0] if len(multi_result) else None
                if top_res is not None and top_res.result is not None:
                    try:
                        sys.stdout.write(str(top_res.result).rstrip("\n") + "\n")
                    except Exception:
                        # Best-effort; skip problematic encodings
                        pass
    else:
        # Capture what would normally go to the screen and write it to a log file
        buf = io.StringIO()
        if not effective_quiet:
            try:
                with redirect_stdout(buf):
                    print_result(result)
            except Exception:
                # Fallback: at least dump a simple summary
                for host, multi_result in result.items():
                    buf.write(f"[{host}] {"FAILED" if multi_result.failed else "OK"}\n")
        else:
            # Quiet mode: write only the top-level task results to log file
            for host, multi_result in result.items():
                top_res = multi_result[0] if len(multi_result) else None
                if top_res is not None and top_res.result is not None:
                    buf.write(str(top_res.result).rstrip("\n") + "\n")

        try:
            log_path = Path(log_file_opt)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as fh:
                raw = buf.getvalue()
                if raw:
                    lines = raw.splitlines()
                    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    for ln in lines:
                        fh.write(f"{stamp} {ln}\n")
        except Exception as e:
            print(f"Warn: failed to write log file {log_file_opt}: {e}", file=sys.stderr)

    # Optional save outputs per host
    if save_dir_opt:
        outdir = Path(save_dir_opt)
        outdir.mkdir(parents=True, exist_ok=True)
        for host, multi_result in result.items():
            outfile = outdir / f"{host}.txt"
            try:
                # Skip hosts already saved by the worker (best-effort check)
                host_obj = nr.inventory.hosts[str(host)] if hasattr(nr, "inventory") else None
                if host_obj is not None:
                    try:
                        if host_obj.get("saved_to_disk"):
                            continue
                    except Exception:
                        pass
                host_output = None
                if host_obj is not None:
                    try:
                        host_output = host_obj.get("final_output")
                    except Exception:
                        host_output = None
                if host_output is None:
                    # Fallback: attempt to use the task's returned Result. In Nornir, the
                    # returned Result is typically appended last, but earlier code assumed
                    # index 0. Be defensive and pick the last element with a non-empty result.
                    chosen = None
                    for r in reversed(list(multi_result)):
                        if getattr(r, "result", None):
                            chosen = r
                            break
                    if chosen is not None:
                        host_output = str(chosen.result)
                # Write the determined output (or a newline if unavailable)
                if host_output is not None:
                    outfile.write_text(str(host_output).rstrip("\n") + "\n", encoding="utf-8")
                else:
                    outfile.write_text("\n", encoding="utf-8")
            except Exception as e:
                print(f"Warn: failed to write {outfile}: {e}", file=sys.stderr)

    # Determine exit code: non-zero if any host failed
    failed = [h for h, r in result.items() if r.failed]
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
