#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Refactored Cortensor Watcher (single-file)

- Discovers nodes by scanning: /home/cortensor/.cortensor/.env-1, .env-2, ...
  extracting NODE_PUBLIC_KEY=0x...
- Tails per-node logs: /var/log/cortensord-<n>.log (or /var/log/cortensor-<n>.log)
- Detects only:
    * traceback
    * traceback_unrecovered (traceback persists beyond a window)
    * pingfail
    * node_pool_stale
    * wrong_user_state  (node in USER mode but appears in "Assigned Miners" list)
- Displays latest Cognitive Level ("Cognitive Level:" or "CL:") per node as CL:<value>
  (handles leading whitespace and optional '*' bullet)
- Prints "last complete session" (max session id where State=6) in the header
- Shows per-node "session_id/State=n" (e.g., 1101/State=3), else USER/Mode=USER
- Restarts with: systemctl restart cortensor-<n>
  * Supports sudo via config: use_sudo + sudo_non_interactive + sudo_path + systemctl_path
- Per-reason enable/disable flags via config.json
- Writes restart evidence to ./restart_logs and a master watcher.log

No Docker, no TX FSM, no reputation/session API polling.

Tested with Python 3.10+ (standard library only).
"""

from __future__ import annotations

import os
import re
import sys
import json
import time
import glob
import signal
import subprocess
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from collections import deque

# -------------------------
# Constants & Regex Patterns
# -------------------------

ENV_DIR = Path("/home/deploy/.cortensor")
ENV_GLOB = ".env-*"

# Prefer daemon-style name first; fall back to non-daemon if missing.
LOG_PRIMARY_FMT = "/var/log/cortensord-{idx}.log"
LOG_FALLBACK_FMT = "/var/log/cortensor-{idx}.log"

SYSTEMD_SERVICE_FMT = "cortensor-{idx}"

# Error scan patterns
TRACEBACK_PATTERN = "Traceback (most recent call last):"
PING_FAIL_PATTERN = "Pinging network..."
NODE_POOL_STALE_KEYS = (
    "Node Pool Ephemeral Node Stale:",
    "Node Pool Reserved Node Stale:",
)

# Wrong user state & CL
ASSIGNED_MINERS_RE = re.compile(r".*Assigned Miners:\s*(.+)")
USER_TOKEN = "USER"

# Cognitive Level (display) — allow leading whitespace and optional '*' bullet
# Matches: "    Cognitive Level: 4", "   * Cognitive Level: 3", "CL: 2"
COGNITIVE_LEVEL_RE = re.compile(
    r"^\s*(?:\*\s*)?(?:Cognitive\s+Level|CL)\s*:\s*([^\r\n]+)$",
    re.IGNORECASE
)

# Session/State parsing:
# - New format (combined): "* Latest ID:  1101  / Latest State:  3"
LATEST_BOTH_RE = re.compile(
    r"^\s*(?:\*\s*)?Latest\s+ID\s*:\s*(\d+)\s*(?:/|\|)\s*Latest\s+State\s*:\s*(\d+)\s*$",
    re.IGNORECASE
)
# - New format (split): "* Latest ID: 1101" or "* Latest State: 3"
LATEST_ID_RE = re.compile(r"^\s*(?:\*\s*)?Latest\s+ID\s*:\s*(\d+)\s*$", re.IGNORECASE)
LATEST_STATE_RE = re.compile(r"^\s*(?:\*\s*)?Latest\s+State\s*:\s*(\d+)\s*$", re.IGNORECASE)

# - Legacy/other formats (still supported)
SESSION_STATE_COMBINED_RE = re.compile(
    r"^\s*(?:\*\s*)?(?:Remote\s*Session|Session\s*ID)\s*[:=\s]*\s*(\d+).*?\bState\s*[:=\s]*\s*(\d+)",
    re.IGNORECASE
)
SESSION_ID_RE = re.compile(r"(?i)(?:Remote\s*Session|Session\s*ID)\s*[:=\s]*\s*(\d+)")
STATE_RE = re.compile(r"(?i)\bState\s*[:=\s]*\s*(\d+)")

# -------------------------
# Config Management
# -------------------------

DEFAULT_CONFIG = {
    "check_interval_seconds": 5,              # polling interval
    "tail_lines": 400,                         # in-memory buffer per node
    "traceback_recovery_seconds": 240,         # window before 'traceback_unrecovered'
    "pingfail_threshold": 2,                   # count within window
    "pingfail_window": 52,                     # sliding window size
    "cooldown_minutes": 2,                     # min time between restarts per node
    "restart_dry_run": False,                  # if True, do not actually restart
    # ---- systemctl / sudo integration ----
    "use_sudo": True,                         # set True if running as non-root without polkit
    "sudo_path": "/usr/bin/sudo",
    "sudo_non_interactive": True,              # adds '-n' (no password prompt)
    "systemctl_path": "/bin/systemctl",
    # --------------------------------------
    "restart_flags": {
        "traceback": False,
        "traceback_unrecovered": True,
        "pingfail": True,
        "node_pool_stale": True,
        "wrong_user_state": False,
    },
    # Auto-discovered nodes are persisted for visibility:
    # "nodes": [{"index": 1, "address": "0x...", "env_path": "...", "log_path": "...", "service": "cortensor-1"}]
    "nodes": []
}

def load_config(path: Path) -> dict:
    if not path.exists():
        cfg = DEFAULT_CONFIG.copy()
        save_config(path, cfg)
        return cfg
    try:
        with path.open("r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        print(f"[WARN] Failed to parse config: {path}. Using defaults.", file=sys.stderr)
        cfg = DEFAULT_CONFIG.copy()
    return deep_merge(DEFAULT_CONFIG, cfg)

def save_config(path: Path, cfg: dict) -> None:
    try:
        tmp = path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, sort_keys=True)
        tmp.replace(path)
    except Exception as e:
        print(f"[WARN] Failed to save config: {e}", file=sys.stderr)

def deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out

# -------------------------
# Discovery
# -------------------------

@dataclass
class NodeConfig:
    index: int
    address: str
    env_path: str
    log_path: str
    service: str

def discover_nodes_from_envs() -> List[NodeConfig]:
    nodes: List[NodeConfig] = []
    if not ENV_DIR.exists():
        print(f"[WARN] ENV directory missing: {ENV_DIR}", file=sys.stderr)
        return nodes

    env_paths = sorted(Path(p) for p in glob.glob(str(ENV_DIR / ENV_GLOB)))
    env_re = re.compile(r"\.env-(\d+)$")

    for env_path in env_paths:
        m = env_re.search(env_path.name)
        if not m:
            continue
        idx = int(m.group(1))
        address = parse_env_for_address(env_path)
        if not address:
            print(f"[WARN] No NODE_PUBLIC_KEY found in {env_path}", file=sys.stderr)
            continue

        log_primary = Path(LOG_PRIMARY_FMT.format(idx=idx))
        log_fallback = Path(LOG_FALLBACK_FMT.format(idx=idx))
        log_path = str(log_primary if log_primary.exists() else log_fallback)

        service = SYSTEMD_SERVICE_FMT.format(idx=idx)

        nodes.append(NodeConfig(
            index=idx,
            address=address,
            env_path=str(env_path),
            log_path=log_path,
            service=service
        ))
    return nodes

def parse_env_for_address(env_path: Path) -> Optional[str]:
    try:
        with env_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("NODE_PUBLIC_KEY"):
                    parts = line.split("=", 1)
                    if len(parts) == 2:
                        addr = parts[1].strip().strip('"').strip("'")
                        return addr
    except Exception as e:
        print(f"[WARN] Failed reading env file {env_path}: {e}", file=sys.stderr)
    return None

def merge_discovered_nodes_into_config(cfg: dict, discovered: List[NodeConfig]) -> dict:
    existing_by_index: Dict[int, dict] = {n.get("index"): n for n in cfg.get("nodes", []) if "index" in n}
    for nd in discovered:
        existing_by_index[nd.index] = {
            "index": nd.index,
            "address": nd.address,
            "env_path": nd.env_path,
            "log_path": nd.log_path,
            "service": nd.service
        }
    cfg["nodes"] = sorted(existing_by_index.values(), key=lambda x: x["index"])
    return cfg

# -------------------------
# File Tailer
# -------------------------

class FileTailer:
    """
    Minimal tail -F like follower:
      - Reads appended data as the file grows
      - Reopens when inode changes or file is truncated (rotation)
      - On open, captures last `init_tail_lines` lines to buffer (returned once via `prime_tail()`)
    """
    def __init__(self, path: str, init_tail_lines: int = 200, encoding: str = "utf-8"):
        self.path = path
        self.encoding = encoding
        self.init_tail_lines = init_tail_lines
        self._f = None
        self._inode = None
        self._leftover = ""
        self._primed = False
        self._missing_notice = False

    def prime_tail(self) -> List[str]:
        if self._primed:
            return []
        self._primed = True
        try:
            if not os.path.exists(self.path):
                if not self._missing_notice:
                    print(f"[INFO] Waiting for log file to appear: {self.path}")
                    self._missing_notice = True
                return []
            with open(self.path, "r", encoding=self.encoding, errors="replace") as f:
                lines = f.readlines()
            if self._missing_notice:
                self._missing_notice = False
            return [ln.rstrip("\n") for ln in lines[-self.init_tail_lines:]]
        except Exception as e:
            print(f"[WARN] Failed to prime tail for {self.path}: {e}", file=sys.stderr)
            return []

    def _open_follow(self):
        st = os.stat(self.path)
        self._f = open(self.path, "r", encoding=self.encoding, errors="replace")
        self._inode = st.st_ino
        self._f.seek(0, os.SEEK_END)

    def _maybe_reopen_on_rotate(self):
        try:
            st = os.stat(self.path)
            if self._inode is None or self._f is None:
                self._open_follow()
                return
            curpos = self._f.tell()
            if st.st_ino != self._inode or st.st_size < curpos:
                try:
                    self._f.close()
                except Exception:
                    pass
                self._open_follow()
        except FileNotFoundError:
            if self._f:
                try:
                    self._f.close()
                except Exception:
                    pass
            self._f = None
            self._inode = None

    def read_new_lines(self) -> List[str]:
        out: List[str] = []
        if not os.path.exists(self.path):
            if not self._missing_notice:
                print(f"[INFO] Waiting for log file to appear: {self.path}")
                self._missing_notice = True
            return out
        else:
            if self._missing_notice:
                print(f"[INFO] Log file available: {self.path}")
                self._missing_notice = False

        if self._f is None or self._inode is None:
            try:
                self._open_follow()
            except Exception:
                return out

        self._maybe_reopen_on_rotate()

        try:
            chunk = self._f.read()
            if not chunk:
                return out
            data = self._leftover + chunk
            lines = data.splitlines(keepends=True)
            if lines and not lines[-1].endswith("\n"):
                self._leftover = lines[-1]
                lines = lines[:-1]
            else:
                self._leftover = ""
            for ln in lines:
                out.append(ln.rstrip("\n"))
            return out
        except Exception:
            return out

# -------------------------
# Restart Manager
# -------------------------

class RestartManager:
    def __init__(
        self,
        log_dir="restart_logs",
        master_log="watcher.log",
        cooldown_minutes=2,
        dry_run=False,
        use_sudo=False,
        sudo_path="/usr/bin/sudo",
        sudo_non_interactive=True,
        systemctl_path="/bin/systemctl",
    ):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.master_log = Path(master_log)
        if not self.master_log.exists():
            self.master_log.write_text("", encoding="utf-8")
        self.cooldown = timedelta(minutes=cooldown_minutes)
        self.last_restart: Dict[str, datetime] = {}
        self.dry_run = dry_run

        self.use_sudo = use_sudo
        self.sudo_path = sudo_path
        self.sudo_non_interactive = sudo_non_interactive
        self.systemctl_path = systemctl_path

    def attempt_restart(self, node_service: str, reason_key: str, evidence_lines: List[str]) -> bool:
        now = datetime.now(timezone.utc)
        last = self.last_restart.get(node_service, datetime.fromtimestamp(0, timezone.utc))
        if now - last < self.cooldown:
            print(f"[{node_service}] ⚠ Restart skipped (cooldown active)")
            return False

        ts = now.strftime("%Y%m%dT%H%M%S")
        fname = f"{node_service}_{reason_key}_{ts}.log"
        try:
            self.log_dir.joinpath(fname).write_text("\n".join(evidence_lines), encoding="utf-8")
        except Exception as e:
            print(f"[WARN] Failed to write evidence file {fname}: {e}", file=sys.stderr)

        entry = f"{now.isoformat()}Z  Restarted '{node_service}' ({reason_key}) -> '{fname}'\n"
        try:
            with self.master_log.open("a", encoding="utf-8") as f:
                f.write(entry)
        except Exception as e:
            print(f"[WARN] Failed to write master log: {e}", file=sys.stderr)

        if self.dry_run:
            print(f"[{node_service}] ✔ (dry-run) Would restart ({reason_key})")
        else:
            cmd: List[str] = []
            if self.use_sudo:
                cmd.extend([self.sudo_path])
                if self.sudo_non_interactive:
                    cmd.append("-n")
            cmd.extend([self.systemctl_path, "restart", node_service])

            try:
                subprocess.run(cmd, check=True)
                print(f"[{node_service}] ✔ Restarted ({reason_key})")
            except subprocess.CalledProcessError as e:
                print(f"[{node_service}] ✘ Restart failed: {e}", file=sys.stderr)

        self.last_restart[node_service] = now
        return True

# -------------------------
# Node State
# -------------------------

@dataclass
class NodeConfigState:
    index: int
    address: str
    env_path: str
    log_path: str
    service: str

@dataclass
class NodeState:
    cfg: NodeConfigState
    tailer: FileTailer
    buf: deque[str] = field(default_factory=lambda: deque(maxlen=200))
    # traceback tracking
    traceback_first_detected: Optional[datetime] = None
    traceback_last_seen: Optional[datetime] = None
    # wrong_user_state debouncer
    last_assignment_snapshot_at: Optional[datetime] = None
    # cognitive level display
    last_cl: Optional[str] = None
    # session/state display
    last_session_id: Optional[int] = None
    last_state: Optional[int] = None

    def is_user_mode_recent(self, window: int = 30) -> bool:
        recent = list(self.buf)[-window:]
        return any(USER_TOKEN in ln for ln in recent)

# -------------------------
# Error Scanners
# -------------------------

def saw_traceback(lines: List[str]) -> bool:
    return any(TRACEBACK_PATTERN in ln for ln in lines)

def saw_ping_fail(buf: deque[str], threshold: int, window: int) -> bool:
    recent = list(buf)[-window:]
    count = sum(1 for ln in recent if ln.strip().startswith(PING_FAIL_PATTERN))
    return count >= threshold

def saw_node_pool_stale(lines: List[str]) -> bool:
    for ln in lines:
        if any(k in ln for k in NODE_POOL_STALE_KEYS):
            parts = ln.split(":", 1)
            if len(parts) == 2 and parts[1].strip().lower().startswith("true"):
                return True
    return False

def maybe_update_cognitive_level(st: NodeState, line: str) -> None:
    m = COGNITIVE_LEVEL_RE.search(line)
    if m:
        val = m.group(1).strip()
        val = re.sub(r"[.\s]+$", "", val)
        if val:
            st.last_cl = val

# ---- Session/State parsing helpers ----

def parse_session_state_from_line(line: str) -> Optional[Tuple[int, int]]:
    """Try to parse BOTH (session_id, state) from one line."""
    m = LATEST_BOTH_RE.search(line)
    if m:
        try:
            sid = int(m.group(1))
            state = int(m.group(2))
            return sid, state
        except Exception:
            return None

    m = SESSION_STATE_COMBINED_RE.search(line)
    if m:
        try:
            sid = int(m.group(1))
            state = int(m.group(2))
            return sid, state
        except Exception:
            return None

    # Fallback: separate legacy hints in same line
    m_sid = SESSION_ID_RE.search(line)
    m_st = STATE_RE.search(line)
    if m_sid and m_st:
        try:
            sid = int(m_sid.group(1))
            state = int(m_st.group(1))
            return sid, state
        except Exception:
            return None

    return None

def parse_latest_id_only(line: str) -> Optional[int]:
    m = LATEST_ID_RE.search(line)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            return None
    # also allow "Session ID:" legacy when alone in a line
    m2 = re.search(r"^\s*(?:\*\s*)?(?:Remote\s*Session|Session\s*ID)\s*[:=\s]*\s*(\d+)\s*$", line, re.IGNORECASE)
    if m2:
        try:
            return int(m2.group(1))
        except Exception:
            return None
    return None

def parse_latest_state_only(line: str) -> Optional[int]:
    m = LATEST_STATE_RE.search(line)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            return None
    # also allow "State:" legacy when alone in a line
    m2 = re.search(r"^\s*(?:\*\s*)?\bState\s*[:=\s]*\s*(\d+)\s*$", line, re.IGNORECASE)
    if m2:
        try:
            return int(m2.group(1))
        except Exception:
            return None
    return None

# -------------------------
# Assigned Miners Snapshot
# -------------------------

@dataclass
class AssignedMinersSnapshot:
    at: datetime
    source_service: str
    miners: set[str]
    context: List[str]

def scan_assigned_miners_from_lines(lines: List[str]) -> Optional[Tuple[set[str], int]]:
    for idx, ln in enumerate(lines):
        m = ASSIGNED_MINERS_RE.search(ln)
        if m:
            miners = {a.strip().lower() for a in m.group(1).split(",") if a.strip()}
            return miners, idx
    return None

# -------------------------
# Utilities
# -------------------------

def clear_screen():
    try:
        sys.stdout.write("\x1b[H\x1b[2J")
        sys.stdout.flush()
    except Exception:
        pass

def line_idx_in_buf(buf: deque[str], pattern: re.Pattern) -> Optional[int]:
    arr = list(buf)
    for i in range(len(arr) - 1, -1, -1):
        if pattern.search(arr[i]):
            return i
    return None

def extract_context(buf: deque[str], idx: Optional[int], radius: int = 20) -> List[str]:
    if idx is None:
        return list(buf)[-radius:]
    arr = list(buf)
    start = max(0, idx - radius)
    end = min(len(arr), idx + radius + 1)
    return arr[start:end]

def _restart_if_enabled(restarter: RestartManager, st: NodeState, reason: str, flags: dict, evidence: List[str]):
    if not flags.get(reason, False if reason == "traceback" else True):
        print(f"[{st.cfg.service}] ▶ {reason}: flag disabled")
        return
    restarter.attempt_restart(st.cfg.service, reason, evidence)

def _consume_recent_pattern(buf: deque[str], startswith: str, window: int = 52):
    if not buf:
        return
    recent = list(buf)
    keep_prefix = recent[:-window] if window < len(recent) else []
    tail = recent[-window:]
    tail_filtered = [ln for ln in tail if not ln.strip().startswith(startswith)]
    new_list = keep_prefix + tail_filtered
    buf.clear()
    for ln in new_list[-buf.maxlen:]:
        buf.append(ln)

# -------------------------
# Main Orchestration
# -------------------------

def main():
    CONFIG_PATH = Path("config.json")
    cfg = load_config(CONFIG_PATH)

    discovered = discover_nodes_from_envs()
    if not discovered:
        print("[ERROR] No nodes discovered from env files. Exiting.", file=sys.stderr)
        sys.exit(1)

    cfg = merge_discovered_nodes_into_config(cfg, discovered)
    save_config(CONFIG_PATH, cfg)

    tail_lines = int(cfg.get("tail_lines", 200))
    pingfail_threshold = int(cfg.get("pingfail_threshold", 2))
    pingfail_window = int(cfg.get("pingfail_window", 52))
    traceback_grace = int(cfg.get("traceback_recovery_seconds", 240))
    cooldown_minutes = int(cfg.get("cooldown_minutes", 2))
    interval = float(cfg.get("check_interval_seconds", 30.0))
    flags = cfg.get("restart_flags", {})
    dry_run = bool(cfg.get("restart_dry_run", False))

    # systemctl/sudo integration
    use_sudo = bool(cfg.get("use_sudo", False))
    sudo_path = str(cfg.get("sudo_path", "/usr/bin/sudo"))
    sudo_non_interactive = bool(cfg.get("sudo_non_interactive", True))
    systemctl_path = str(cfg.get("systemctl_path", "/bin/systemctl"))

    nodes_cfg: List[NodeConfigState] = [
        NodeConfigState(
            index=n["index"],
            address=n["address"],
            env_path=n["env_path"],
            log_path=n["log_path"],
            service=n["service"],
        )
        for n in cfg["nodes"]
    ]

    states: Dict[int, NodeState] = {}
    for nd in nodes_cfg:
        tailer = FileTailer(nd.log_path, init_tail_lines=tail_lines)
        st = NodeState(cfg=nd, tailer=tailer, buf=deque(maxlen=tail_lines))
        primed = tailer.prime_tail()
        for ln in primed:
            st.buf.append(ln)
            maybe_update_cognitive_level(st, ln)
            # initialize session/state from primed lines
            res = parse_session_state_from_line(ln)
            if res:
                sid, state = res
                st.last_session_id = sid
                st.last_state = state
            else:
                sid_only = parse_latest_id_only(ln)
                if sid_only is not None:
                    st.last_session_id = sid_only
                st_only = parse_latest_state_only(ln)
                if st_only is not None:
                    st.last_state = st_only
        states[nd.index] = st

    restarter = RestartManager(
        cooldown_minutes=cooldown_minutes,
        dry_run=dry_run,
        use_sudo=use_sudo,
        sudo_path=sudo_path,
        sudo_non_interactive=sudo_non_interactive,
        systemctl_path=systemctl_path,
    )

    assigned_snapshot: Optional[AssignedMinersSnapshot] = None
    last_complete_session: Optional[int] = None

    # After priming, if any state==6 lines were seen, compute last_complete_session
    for st in states.values():
        if st.last_state == 6 and st.last_session_id is not None:
            last_complete_session = st.last_session_id if last_complete_session is None else max(last_complete_session, st.last_session_id)

    # Graceful shutdown
    running = True
    def handle_sig(signum, frame):
        nonlocal running
        print("\n[INFO] Shutting down...", file=sys.stderr)
        running = False
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, handle_sig)
        except Exception:
            pass

    # Main loop
    while running:
        now = datetime.now(timezone.utc)

        # Read new lines and update buffers
        new_lines_by_idx: Dict[int, List[str]] = {}
        for idx, st in states.items():
            new_lines = st.tailer.read_new_lines()
            if new_lines:
                for ln in new_lines:
                    st.buf.append(ln)
                    maybe_update_cognitive_level(st, ln)

                    # Combined parse first
                    res = parse_session_state_from_line(ln)
                    if res:
                        sid, state = res
                        st.last_session_id = sid
                        st.last_state = state
                        if state == 6:
                            if sid is not None:
                                last_complete_session = sid if last_complete_session is None else max(last_complete_session, sid)
                        continue

                    # If not combined, try split (ID only / State only)
                    sid_only = parse_latest_id_only(ln)
                    if sid_only is not None:
                        st.last_session_id = sid_only

                    st_only = parse_latest_state_only(ln)
                    if st_only is not None:
                        st.last_state = st_only
                        if st_only == 6 and st.last_session_id is not None:
                            last_complete_session = st.last_session_id if last_complete_session is None else max(last_complete_session, st.last_session_id)

            new_lines_by_idx[idx] = new_lines

        # Wrong User State snapshot
        src_idx_found = None
        miners_found: Optional[set[str]] = None
        line_idx = None
        for idx, lines in new_lines_by_idx.items():
            if not lines:
                continue
            res = scan_assigned_miners_from_lines(lines)
            if res:
                miners_found, line_idx = res
                src_idx_found = idx
                break

        if miners_found is not None and src_idx_found is not None:
            src_state = states[src_idx_found]
            ctx = extract_context(src_state.buf, line_idx_in_buf(src_state.buf, ASSIGNED_MINERS_RE), radius=20)
            assigned_snapshot = AssignedMinersSnapshot(
                at=now,
                source_service=src_state.cfg.service,
                miners=miners_found,
                context=ctx
            )
            print(f"[ASSIGN] Snapshot from {src_state.cfg.service} at {assigned_snapshot.at.isoformat()} "
                  f"miners={sorted(list(assigned_snapshot.miners))}")

        # Apply wrong_user_state rule
        flags_wrong = flags.get("wrong_user_state", True)
        if assigned_snapshot and flags_wrong:
            for idx, st in states.items():
                if st.is_user_mode_recent():
                    in_list = st.cfg.address.lower() in assigned_snapshot.miners
                    snapshot_ts = assigned_snapshot.at
                    if in_list and (st.last_assignment_snapshot_at != snapshot_ts):
                        ev = []
                        ev.append(f"Assigned Miners snapshot @ {assigned_snapshot.at.isoformat()} from {assigned_snapshot.source_service}")
                        ev.extend(assigned_snapshot.context or [])
                        ev.append("")
                        ev.append(f"USER-mode detected in recent logs of {st.cfg.service} (address {st.cfg.address})")
                        _restart_if_enabled(restarter, st, "wrong_user_state", flags, ev)
                        st.last_assignment_snapshot_at = snapshot_ts

        # Error scans
        for idx, st in states.items():
            lines = new_lines_by_idx[idx]

            # Traceback immediate
            if lines and saw_traceback(lines):
                st.traceback_last_seen = now
                if st.traceback_first_detected is None:
                    st.traceback_first_detected = now

                if flags.get("traceback", False):
                    evidence = list(st.buf)[-50:]
                    evidence.append(f"[meta] immediate traceback at {now.isoformat()}")
                    _restart_if_enabled(restarter, st, "traceback", flags, evidence)
                    st.traceback_first_detected = None
                    st.traceback_last_seen = None

            # Traceback unrecovered
            if flags.get("traceback_unrecovered", True) and st.traceback_first_detected:
                elapsed = (now - st.traceback_first_detected).total_seconds()
                recent_tracebacks = (st.traceback_last_seen is not None) and \
                                    ((now - st.traceback_last_seen).total_seconds() <= traceback_grace)
                if elapsed >= traceback_grace and recent_tracebacks:
                    evidence = list(st.buf)[-100:]
                    evidence.append(f"[meta] unrecovered traceback; first={st.traceback_first_detected.isoformat()} "
                                    f"last={st.traceback_last_seen.isoformat()} window={traceback_grace}s")
                    _restart_if_enabled(restarter, st, "traceback_unrecovered", flags, evidence)
                    st.traceback_first_detected = None
                    st.traceback_last_seen = None

            # Ping fail
            if flags.get("pingfail", True) and saw_ping_fail(st.buf, pingfail_threshold, pingfail_window):
                evidence = list(st.buf)[-pingfail_window:]
                _restart_if_enabled(restarter, st, "pingfail", flags, evidence)
                _consume_recent_pattern(st.buf, PING_FAIL_PATTERN)

            # Node pool stale
            if lines and flags.get("node_pool_stale", True) and saw_node_pool_stale(lines):
                evidence = list(st.buf)[-50:]
                _restart_if_enabled(restarter, st, "node_pool_stale", flags, evidence)

        # Render status
        clear_screen()
        lcs = last_complete_session if last_complete_session is not None else "-"
        print(f"=== {now.isoformat()}Z | nodes={len(states)} | interval={interval}s | cooldown={cooldown_minutes}m "
              f"| last_complete_session={lcs} | dry_run={dry_run} ===")
        print("Flags: " + ", ".join(f"{k}={'on' if v else 'off'}" for k, v in cfg.get("restart_flags", {}).items()))
        if assigned_snapshot:
            ago = int((now - assigned_snapshot.at).total_seconds())
            print(f"[ASSIGN] last from {assigned_snapshot.source_service} {ago}s ago; miners={len(assigned_snapshot.miners)}")
        for idx in sorted(states):
            st = states[idx]
            if st.last_session_id is not None and st.last_state is not None:
                sess_disp = f"{st.last_session_id}/State={st.last_state}"
            elif st.is_user_mode_recent():
                sess_disp = "USER/Mode=USER"
            else:
                sess_disp = "-/State=-"
            last_restart = restarter.last_restart.get(st.cfg.service)
            lr = f"{int((now - last_restart).total_seconds())}s ago" if last_restart else "-"
            cl = st.last_cl if st.last_cl is not None else "-"
            print(f"[{st.cfg.service}] addr={st.cfg.address} | {sess_disp} | CL:{cl} | last_restart={lr}")

        time.sleep(interval)

    print("[INFO] Exited cleanly.")

# -------------------------
# Entrypoint
# -------------------------

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user.")
