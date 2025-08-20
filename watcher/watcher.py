#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cortensor Node Watcher (single-file)

- Discovers nodes by scanning: /home/deploy/.cortensor/.env-1, .env-2, ...
  extracting NODE_PUBLIC_KEY=0x... (canonicalized to lowercase)
- Tails per-node logs: /var/log/cortensord-<n>.log (or /var/log/cortensor-<n>.log)
- Detects only:
    * traceback
    * traceback_unrecovered (traceback persists beyond a window)
    * pingfail
    * node_pool_stale
    * wrong_user_state  (node in USER mode but appears in "Assigned Miners" list; flag default OFF)
- Displays latest Cognitive Level (Cognitive Level: <n>) per node as CL:<value>
  * tolerant of leading tabs/whitespace, anywhere-in-line matches, trailing punctuation
  * updates to CL are **gated**: only when node is **Selected** and **State == 3**
  * startup backfill scan (last ~2MB of each log) to seed CL if it’s older than the initial tail
  * persists to config.json as last_cognitive_level
- Prints "last complete session" (max session id where State=6) in the header
- Shows per-node "session_id/State=n"; when State is 3 or 4, appends "Selected" or "Not Selected"
  based on most recent "Assigned Miners" snapshot
- Persists the last session ID a node was selected for as last_selected_task (in config.json)
- Restarts with: systemctl restart cortensor-<n>
  * Supports sudo via config: use_sudo + sudo_non_interactive + sudo_path + systemctl_path
- Version check: compares local version v1.0.1 against GitHub latest
  (repo: scerb/node_switch_watch) on startup and once every 24h.
- **New:** Each node line shows the **last restart reason** alongside the last restart age.

Python 3.10+ (standard library only).
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
import urllib.request
import urllib.error
from typing import List, Dict, Optional, Tuple, Set
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from collections import deque

# -------------------------
# Versioning (local + remote check)
# -------------------------

LOCAL_VERSION = "v1.0.2"
VERSION_REPO = "scerb/node_switch_watch"
VERSION_API_URL = f"https://api.github.com/repos/{VERSION_REPO}/releases/latest"

def fetch_latest_release_tag(url: str, timeout: float = 5.0) -> Optional[str]:
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "cortensor-watcher/1.0",
                "Accept": "application/vnd.github+json",
            },
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            data = json.loads(raw)
            tag = data.get("tag_name")
            return str(tag) if tag else None
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError):
        return None

# -------------------------
# Constants & Regex Patterns
# -------------------------

ENV_DIR = Path("/home/deploy/.cortensor")
ENV_GLOB = ".env-*"

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

# Assigned miners / user mode
ASSIGNED_MINERS_RE = re.compile(r".*Assigned Miners:\s*(.+)")
USER_TOKEN = "USER"

# Cognitive Level detection (Cognitive Level only; not generic "CL:")
COGNITIVE_LEVEL_ANCHORED_RE = re.compile(
    r"^\s*(?:\*\s*)?Cognitive\s+Level\s*:\s*([^\r\n]+)\s*$",
    re.IGNORECASE
)
COGNITIVE_LEVEL_ANY_RE = re.compile(
    r"Cognitive\s+Level\s*:\s*([0-9]+)(?:\s*[^\d\r\n]*)?",
    re.IGNORECASE
)

# Session/State parsing:
LATEST_BOTH_RE = re.compile(
    r"^\s*(?:\*\s*)?Latest\s+ID\s*:\s*(\d+)\s*(?:/|\|)\s*Latest\s+State\s*:\s*(\d+)\s*$",
    re.IGNORECASE
)
LATEST_ID_RE = re.compile(r"^\s*(?:\*\s*)?Latest\s+ID\s*:\s*(\d+)\s*$", re.IGNORECASE)
LATEST_STATE_RE = re.compile(r"^\s*(?:\*\s*)?Latest\s+State\s*:\s*(\d+)\s*$", re.IGNORECASE)
SESSION_STATE_COMBINED_RE = re.compile(
    r"^\s*(?:\*\s*)?(?:Remote\s*Session|Session\s*ID)\s*[:=\s]*\s*(\d+).*?\bState\s*[:=\s]*\s*(\d+)",
    re.IGNORECASE
)
SESSION_ID_SOLO_RE = re.compile(r"^\s*(?:\*\s*)?(?:Remote\s*Session|Session\s*ID)\s*[:=\s]*\s*(\d+)\s*$", re.IGNORECASE)
STATE_SOLO_RE = re.compile(r"^\s*(?:\*\s*)?\bState\s*[:=\s]*\s*(\d+)\s*$", re.IGNORECASE)

# Address extraction & normalization
ADDR_RE = re.compile(r"0[xX][0-9a-fA-F]+")  # any hex token that starts with 0x/0X

def extract_addresses(text: str) -> Set[str]:
    return {m.lower() for m in ADDR_RE.findall(text or "")}

def canonicalize_address(text: str) -> Optional[str]:
    if not text:
        return None
    s = text.strip().strip('",[]{}()<>')
    if s.lower().startswith("0x"):
        return s.lower()
    found = extract_addresses(text)
    if found:
        m = ADDR_RE.search(text)
        return m.group(0).lower() if m else next(iter(found))
    return None

def short_addr(addr: Optional[str], head: int = 6, tail: int = 6) -> str:
    if not addr:
        return "-"
    if len(addr) <= head + tail:
        return addr
    return f"{addr[:head]}…{addr[-tail:]}"

def fmt_age(now: datetime, then: Optional[datetime]) -> str:
    if not then:
        return "-"
    return f"{int((now - then).total_seconds())}s"

# -------------------------
# Config Management
# -------------------------

DEFAULT_CONFIG = {
    "check_interval_seconds": 5,
    "tail_lines": 400,
    "traceback_recovery_seconds": 240,
    "pingfail_threshold": 2,
    "pingfail_window": 52,
    "cooldown_minutes": 2,
    "restart_dry_run": False,
    # systemctl / sudo
    "use_sudo": True,
    "sudo_path": "/usr/bin/sudo",
    "sudo_non_interactive": True,
    "systemctl_path": "/bin/systemctl",
    # restart flags
    "restart_flags": {
        "traceback": False,
        "traceback_unrecovered": True,
        "pingfail": True,
        "node_pool_stale": True,
        "wrong_user_state": False,
    },
    # nodes array is persisted with extras like last_selected_task, last_cognitive_level
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
    address: str     # canonicalized
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
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("NODE_PUBLIC_KEY"):
                    parts = line.split("=", 1)
                    if len(parts) == 2:
                        val = parts[1].split("#", 1)[0].strip().strip('"').strip("'")
                        canon = canonicalize_address(val)
                        return canon or val.strip().lower()
    except Exception as e:
        print(f"[WARN] Failed reading env file {env_path}: {e}", file=sys.stderr)
    return None

def merge_discovered_nodes_into_config(cfg: dict, discovered: List[NodeConfig]) -> dict:
    """
    Preserve any existing custom fields (e.g., last_selected_task, last_cognitive_level) while updating
    discovered fields (address/env_path/log_path/service).
    """
    existing_by_index: Dict[int, dict] = {n.get("index"): dict(n) for n in cfg.get("nodes", []) if "index" in n}
    for nd in discovered:
        existing = existing_by_index.get(nd.index, {})
        existing.update({
            "index": nd.index,
            "address": nd.address,
            "env_path": nd.env_path,
            "log_path": nd.log_path,
            "service": nd.service
        })
        existing_by_index[nd.index] = existing
    cfg["nodes"] = sorted(existing_by_index.values(), key=lambda x: x["index"])
    return cfg

# -------------------------
# File Tailer
# -------------------------

class FileTailer:
    """
    Minimal tail -F like follower with rotation handling and initial tail capture.
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
        self.last_reason: Dict[str, str] = {}           # <--- store reason per service
        self.last_evidence_file: Dict[str, str] = {}    # optional: evidence file name
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

        # Build command (sudo/systemctl)
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

        # Record last restart time + reason (even in dry-run to make it visible)
        self.last_restart[node_service] = now
        self.last_reason[node_service] = reason_key
        self.last_evidence_file[node_service] = fname
        return True

# -------------------------
# Node State
# -------------------------

@dataclass
class NodeConfigState:
    index: int
    address: str   # canonicalized
    env_path: str
    log_path: str
    service: str
    last_selected_task: Optional[int] = None   # persisted
    last_cognitive_level: Optional[str] = None # persisted

@dataclass
class NodeState:
    cfg: NodeConfigState
    tailer: FileTailer
    buf: deque[str] = field(default_factory=lambda: deque(maxlen=200))
    traceback_first_detected: Optional[datetime] = None
    traceback_last_seen: Optional[datetime] = None
    last_assignment_snapshot_at: Optional[datetime] = None
    last_cl: Optional[str] = None
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

# -------------------------
# Cognitive Level helpers
# -------------------------

def normalize_cl_value(raw: str) -> Optional[str]:
    if raw is None:
        return None
    raw = raw.strip()
    mnum = re.search(r"(\d+)", raw)
    if mnum:
        return mnum.group(1)
    raw = re.sub(r"[.\s]+$", "", raw)
    return raw or None

def detect_cognitive_level_value(line: str) -> Optional[str]:
    # Only accept "Cognitive Level:" phrases (not generic "CL:")
    m = COGNITIVE_LEVEL_ANCHORED_RE.search(line)
    if not m:
        m = COGNITIVE_LEVEL_ANY_RE.search(line)
    if not m:
        return None
    return normalize_cl_value(m.group(1))

def backfill_cognitive_level_from_file(path: str, max_bytes: int = 2_000_000, encoding: str = "utf-8") -> Optional[str]:
    """
    Scan the last max_bytes of the file for the most recent 'Cognitive Level' occurrence.
    Returns the normalized value or None.
    """
    if not path or not os.path.exists(path):
        return None
    try:
        size = os.path.getsize(path)
        offset = max(0, size - max_bytes)
        with open(path, "r", encoding=encoding, errors="replace") as f:
            if offset:
                f.seek(offset)
                _ = f.readline()
            last_val = None
            for line in f:
                nv = detect_cognitive_level_value(line)
                if nv is not None:
                    last_val = nv
            return last_val
    except Exception:
        return None

# -------------------------
# Session/State parsing helpers
# -------------------------

def parse_session_state_from_line(line: str) -> Optional[Tuple[int, int]]:
    m = LATEST_BOTH_RE.search(line)
    if m:
        try:
            return int(m.group(1)), int(m.group(2))
        except Exception:
            return None
    m = SESSION_STATE_COMBINED_RE.search(line)
    if m:
        try:
            return int(m.group(1)), int(m.group(2))
        except Exception:
            return None
    m_sid = SESSION_ID_SOLO_RE.search(line)
    m_st = STATE_SOLO_RE.search(line)
    if m_sid and m_st:
        try:
            return int(m_sid.group(1)), int(m_st.group(1))
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
    m2 = SESSION_ID_SOLO_RE.search(line)
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
    m2 = STATE_SOLO_RE.search(line)
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
    miners: set[str]  # canonicalized
    context: List[str]

def scan_assigned_miners_from_lines(lines: List[str]) -> Optional[Tuple[set[str], int]]:
    for idx, ln in enumerate(lines):
        m = ASSIGNED_MINERS_RE.search(ln)
        if m:
            miners = extract_addresses(m.group(1))
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

def _update_cfg_node_field(cfg: dict, node_index: int, field: str, value):
    for n in cfg["nodes"]:
        if n.get("index") == node_index:
            n[field] = value
            return True
    return False

# -------------------------
# Main Orchestration
# -------------------------

def main():
    CONFIG_PATH = Path("config.json")
    cfg = load_config(CONFIG_PATH)

    # --- Version check on startup ---
    last_version_check: datetime = datetime.min.replace(tzinfo=timezone.utc)
    remote_tag = fetch_latest_release_tag(VERSION_API_URL)
    if remote_tag is None:
        version_status = "unknown"
    elif remote_tag == LOCAL_VERSION:
        version_status = "latest"
    else:
        version_status = f"please update ({remote_tag})"
    last_version_check = datetime.now(timezone.utc)

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

    # Build node states (preserving persisted fields)
    nodes_cfg: List[NodeConfigState] = []
    for n in cfg["nodes"]:
        nodes_cfg.append(
            NodeConfigState(
                index=n["index"],
                address=n["address"],
                env_path=n["env_path"],
                log_path=n["log_path"],
                service=n["service"],
                last_selected_task=n.get("last_selected_task"),
                last_cognitive_level=n.get("last_cognitive_level"),
            )
        )

    states: Dict[int, NodeState] = {}
    for nd in nodes_cfg:
        tailer = FileTailer(nd.log_path, init_tail_lines=tail_lines)
        st = NodeState(cfg=nd, tailer=tailer, buf=deque(maxlen=tail_lines))

        # Seed with persisted CL so it shows immediately on restart
        if nd.last_cognitive_level:
            st.last_cl = nd.last_cognitive_level

        # Prime tail and parse historical lines
        primed = tailer.prime_tail()
        primed_cl_candidate: Optional[str] = None

        for ln in primed:
            st.buf.append(ln)

            # Collect candidate CL (we'll accept at startup to seed)
            nv = detect_cognitive_level_value(ln)
            if nv is not None:
                primed_cl_candidate = nv

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

        # On startup, accept the last CL candidate found in primed lines (no gating)
        if primed_cl_candidate is not None:
            st.last_cl = primed_cl_candidate
            st.cfg.last_cognitive_level = primed_cl_candidate
            _update_cfg_node_field(cfg, st.cfg.index, "last_cognitive_level", primed_cl_candidate)

        states[nd.index] = st

        # Backfill CL from older part of the file, if still missing
        if st.last_cl is None:
            bf = backfill_cognitive_level_from_file(nd.log_path)
            if bf:
                st.last_cl = bf
                st.cfg.last_cognitive_level = bf
                _update_cfg_node_field(cfg, st.cfg.index, "last_cognitive_level", bf)

    # Persist any seeded CL updates
    save_config(CONFIG_PATH, cfg)

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

    # After priming, compute last_complete_session if any state==6
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
    config_dirty = False
    while running:
        now = datetime.now(timezone.utc)

        # Daily version re-check
        if (now - last_version_check).total_seconds() >= 86400:
            rt = fetch_latest_release_tag(VERSION_API_URL)
            if rt is None:
                version_status = "unknown"
            elif rt == LOCAL_VERSION:
                version_status = "latest"
            else:
                version_status = f"please update ({rt})"
            last_version_check = now

        # Pass 1: Read new lines for each node and extract data
        new_lines_by_idx: Dict[int, List[str]] = {}
        cl_candidates: Dict[int, str] = {}  # collect potential CL updates this tick

        for idx, st in states.items():
            new_lines = st.tailer.read_new_lines()
            if new_lines:
                for ln in new_lines:
                    st.buf.append(ln)

                    # Collect CL candidate (apply later with gating)
                    nv = detect_cognitive_level_value(ln)
                    if nv is not None:
                        cl_candidates[idx] = nv  # keep latest in this batch

                    # Session/State updates (apply immediately)
                    res = parse_session_state_from_line(ln)
                    if res:
                        sid, state = res
                        st.last_session_id = sid
                        st.last_state = state
                        if state == 6 and sid is not None:
                            last_complete_session = sid if last_complete_session is None else max(last_complete_session, sid)
                        continue

                    sid_only = parse_latest_id_only(ln)
                    if sid_only is not None:
                        st.last_session_id = sid_only

                    st_only = parse_latest_state_only(ln)
                    if st_only is not None:
                        st.last_state = st_only
                        if st_only == 6 and st.last_session_id is not None:
                            last_complete_session = st.last_session_id if last_complete_session is None else max(last_complete_session, st.last_session_id)

            new_lines_by_idx[idx] = new_lines

        # Pass 2: Look for new "Assigned Miners" snapshot in any node's lines
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

        # Pass 3: Apply "wrong_user_state" rule (optional by flag)
        if assigned_snapshot and flags.get("wrong_user_state", False):
            for idx, st in states.items():
                if st.is_user_mode_recent():
                    in_list = st.cfg.address in assigned_snapshot.miners
                    snapshot_ts = assigned_snapshot.at
                    if in_list and (st.last_assignment_snapshot_at != snapshot_ts):
                        ev = []
                        ev.append(f"Assigned Miners snapshot @ {assigned_snapshot.at.isoformat()} from {assigned_snapshot.source_service}")
                        ev.extend(assigned_snapshot.context or [])
                        ev.append("")
                        ev.append(f"USER-mode detected in recent logs of {st.cfg.service}")
                        _restart_if_enabled(restarter, st, "wrong_user_state", flags, ev)
                        st.last_assignment_snapshot_at = snapshot_ts

        # Pass 4: Error scans
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

        # Pass 5: Apply CL candidates with gating (Selected & State == 3 only)
        if cl_candidates:
            for idx, cand in cl_candidates.items():
                st = states[idx]
                selected_now = bool(assigned_snapshot and (st.cfg.address in assigned_snapshot.miners))
                if selected_now and st.last_state == 3:
                    if st.last_cl != cand:
                        st.last_cl = cand
                        st.cfg.last_cognitive_level = cand
                        _update_cfg_node_field(cfg, st.cfg.index, "last_cognitive_level", cand)
                        config_dirty = True
                # else: ignore the candidate to keep the previous CL persistent

        # Update "last_selected_task" when selected in State 3/4
        if assigned_snapshot:
            for idx, st in states.items():
                if st.last_session_id is not None and st.last_state in (3, 4):
                    selected = st.cfg.address in assigned_snapshot.miners
                    if selected and st.cfg.last_selected_task != st.last_session_id:
                        st.cfg.last_selected_task = st.last_session_id
                        _update_cfg_node_field(cfg, st.cfg.index, "last_selected_task", st.cfg.last_selected_task)
                        config_dirty = True

        # Persist config if modified
        if config_dirty:
            save_config(CONFIG_PATH, cfg)
            config_dirty = False

        # Render status
        clear_screen()
        lcs = last_complete_session if last_complete_session is not None else "-"
        print(
            f"=== {now.isoformat()}Z | v={LOCAL_VERSION}({version_status}) | "
            f"nodes={len(states)} | interval={interval}s | cooldown={cooldown_minutes}m "
            f"| last_complete_session={lcs} | dry_run={dry_run} ==="
        )
        print("Flags: " + ", ".join(f"{k}={'on' if v else 'off'}" for k, v in cfg.get("restart_flags", {}).items()))
        if assigned_snapshot:
            ago = int((now - assigned_snapshot.at).total_seconds())
            print(f"[ASSIGN] last from {assigned_snapshot.source_service} {ago}s ago; miners={len(assigned_snapshot.miners)}")

        for idx in sorted(states):
            st = states[idx]
            # session/state display
            if st.last_session_id is not None and st.last_state is not None:
                sess_disp = f"{st.last_session_id}/State={st.last_state}"
                if st.last_state in (3, 4):
                    selected = bool(assigned_snapshot and (st.cfg.address in assigned_snapshot.miners))
                    sess_disp += f" {'Selected' if selected else 'Not Selected'}"
            elif st.is_user_mode_recent():
                sess_disp = "USER/Mode=USER"
            else:
                sess_disp = "-/State=-"

            # restart age + reason
            last_restart_time = restarter.last_restart.get(st.cfg.service)
            last_restart_age = fmt_age(now, last_restart_time)
            last_reason = restarter.last_reason.get(st.cfg.service, "-")

            cl = st.last_cl if st.last_cl is not None else "-"
            lts = st.cfg.last_selected_task if st.cfg.last_selected_task is not None else "-"
            addr_disp = short_addr(st.cfg.address)

            print(f"[{st.cfg.service}] addr={addr_disp} | {sess_disp} | CL:{cl} | last_task={lts} | last_restart={last_restart_age} reason={last_reason}")

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
