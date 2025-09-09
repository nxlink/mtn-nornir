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
try:
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException  # type: ignore
except Exception:
    NetmikoAuthenticationException = tuple()  # type: ignore
    NetmikoTimeoutException = tuple()  # type: ignore
try:
    from paramiko.ssh_exception import SSHException  # type: ignore
except Exception:  # pragma: no cover
    SSHException = tuple()  # type: ignore


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
        return Defaults(ports=[], credentials=[], platform=None, workers=None, timeout=None, enable_secret=None)
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

    return Defaults(ports=ports, credentials=credentials, platform=platform, workers=workers, timeout=timeout, enable_secret=enable_secret)


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
) -> Result:
    last_err: str | None = None

    for port in ports:
        for username, password in cred_pairs:
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
            except (Exception,) as e:
                # Gracefully skip bad credentials/ports without creating failed child results
                last_err = f"{type(e).__name__}: {e} (user={username}, port={port})"
                continue

            # Connection established; now run commands as tasks (these will reuse the open connection)
            try:
                if mode == "show":
                    outputs = []
                    for cmd in commands:
                        r = task.run(
                            name=f"{task.host.name} | {cmd}",
                            task=netmiko_send_command,
                            command_string=cmd,
                            enable=bool(enable_secret),
                            use_textfsm=False,
                            severity_level=(logging.INFO if per_command_output else logging.DEBUG),
                        )
                        outputs.append(str(r.result))
                    aggregated = "\n".join(outputs)
                    task.host["used_username"] = username
                    task.host["used_port"] = port
                    if per_command_output:
                        return Result(host=task.host, result=aggregated, changed=False, severity_level=logging.DEBUG)
                    else:
                        return Result(host=task.host, result=aggregated, changed=False)
                else:  # config mode
                    if dry_run:
                        preview = "\n".join(commands)
                        task.host["used_username"] = username
                        task.host["used_port"] = port
                        return Result(host=task.host, result=f"DRY-RUN (no changes):\n{preview}", changed=False)
                    else:
                        r = task.run(
                            name=f"{task.host.name} | config",
                            task=netmiko_send_config,
                            config_commands=list(commands),
                            severity_level=(logging.INFO if per_command_output else logging.DEBUG),
                        )
                        task.host["used_username"] = username
                        task.host["used_port"] = port
                        if per_command_output:
                            return Result(host=task.host, result=str(r.result), changed=True, severity_level=logging.DEBUG)
                        else:
                            return Result(host=task.host, result=str(r.result), changed=True)
            except Exception as e:
                last_err = f"{type(e).__name__}: {e} (user={username}, port={port})"
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
    p.add_argument("--mode", choices=["show", "config"], default=os.getenv("NORNIR_MODE", "show"))
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
    p.add_argument("--defaults-file", help="Path to defaults file (YAML/JSON) with ports, credentials, platform, workers, timeout, enable_secret")
    p.add_argument("--save-dir", help="Directory to save per-host outputs (optional)")
    p.add_argument(
        "--per-command-output",
        action="store_true",
        help="Print each command result per host; hide aggregated block",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress Nornir headers; print only raw device output",
    )

    args = p.parse_args(list(argv) if argv is not None else None)

    # Load env
    load_env(args.env_file)

    # Gather hosts unless using inventory-dir
    use_inventory_dir = bool(args.inventory_dir)
    hosts_raw: List[str] = []
    hosts_with_plat: List[Tuple[str, str | None]] = []
    if not use_inventory_dir:
        if args.hosts:
            hosts_raw.extend(parse_list_arg(args.hosts))
        if args.hosts_file:
            hosts_raw.extend(read_lines_file(args.hosts_file))
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
    if not commands:
        print("Error: no commands provided (use --commands or --commands-file)", file=sys.stderr)
        return 2

    # Load defaults file (if provided) and merge with CLI/env
    defaults = load_defaults_file(args.defaults_file)

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

    # Resolve baseline platform/workers/timeout with precedence: CLI > defaults file > env/defaults
    effective_platform = normalize_platform(
        (args.platform or defaults.platform or os.getenv("NORNIR_PLATFORM") or "cisco_ios")
    )
    effective_workers = args.workers or defaults.workers or int(os.getenv("NORNIR_WORKERS", "10"))
    effective_timeout = args.timeout or defaults.timeout or int(os.getenv("NORNIR_CMD_TIMEOUT", "30"))

    # Build Nornir instance
    if use_inventory_dir:
        inv_dir = Path(args.inventory_dir)
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
    result = nr.run(
        name=f"run-{args.mode}",
        task=try_connect_and_run,
        commands=commands,
        mode=args.mode,
        ports=ports,
        cred_pairs=creds,
        platform=effective_platform,
        enable_secret=enable_secret,
        cmd_timeout=int(effective_timeout),
        dry_run=bool(args.dry_run),
        per_command_output=bool(args.per_command_output),
    )

    if not args.quiet:
        print_result(result)
    else:
        # Quiet mode: print only raw outputs (final task result per host)
        for host, multi_result in result.items():
            final_res = multi_result[-1] if len(multi_result) else None
            if final_res is not None and final_res.result is not None:
                try:
                    sys.stdout.write(str(final_res.result).rstrip("\n") + "\n")
                except Exception:
                    # Best-effort; skip problematic encodings
                    pass

    # Optional save outputs per host
    if args.save_dir:
        outdir = Path(args.save_dir)
        outdir.mkdir(parents=True, exist_ok=True)
        for host, multi_result in result.items():
            # The final return from try_connect_and_run is the last child Result
            final_res = multi_result[-1] if len(multi_result) else None
            outfile = outdir / f"{host}.txt"
            try:
                if final_res is not None:
                    outfile.write_text(str(final_res.result) + "\n", encoding="utf-8")
                else:
                    outfile.write_text("\n", encoding="utf-8")
            except Exception as e:
                print(f"Warn: failed to write {outfile}: {e}", file=sys.stderr)

    # Determine exit code: non-zero if any host failed
    failed = [h for h, r in result.items() if r.failed]
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
