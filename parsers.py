# ============================================================
# parsers.py — Volatility 3 CSV Output Parsers
# Reads CSV output from eight Volatility 3 plugins into
# normalised Python dicts for the detection engine and UI.
#
# Column headers are matched to Volatility 3's *exact* output
# format — this was the single biggest unlock for accurate AI
# analysis.  Getting these wrong produces garbage-in / garbage-out.
#
# Author: Simon | COMP3000 | University of Plymouth
# ============================================================
"""
Each parser function accepts raw CSV text (str) and returns a list of
dicts with consistent, lowercase keys.  The `detect_plugin` function
maps filenames to canonical plugin names.

Supported plugins:
    pslist / pstree  →  "pslist"
    netscan / netstat →  "netscan"
    cmdline           →  "cmdline"
    dlllist           →  "dlllist"
    malfind           →  "malfind"
    handles           →  "handles"
    privs / privileges → "privs"
    envars            →  "envars"
"""

from __future__ import annotations

import csv
import io
import logging
from typing import Any

log = logging.getLogger("vipersist.parsers")


# ── Helpers ───────────────────────────────────────────────────

def _safe_int(value: Any) -> int:
    """Convert a value to int, returning 0 on failure."""
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return 0


def _reader(content: str) -> csv.DictReader:
    """Build a DictReader, stripping BOM if present."""
    if content.startswith("\ufeff"):
        content = content[1:]
    return csv.DictReader(io.StringIO(content))


# ── Plugin detection ──────────────────────────────────────────

# Mapping from keyword found in filename → canonical plugin name
_PLUGIN_ALIASES: dict[str, str] = {
    "pslist":     "pslist",
    "pstree":     "pslist",
    "netscan":    "netscan",
    "netstat":    "netscan",
    "cmdline":    "cmdline",
    "dlllist":    "dlllist",
    "malfind":    "malfind",
    "handles":    "handles",
    "privs":      "privs",
    "privileges": "privs",
    "envars":     "envars",
}


def detect_plugin(filename: str) -> str | None:
    """
    Infer the Volatility 3 plugin from a CSV filename.

    Returns the canonical plugin name, or None if unrecognised.
    >>> detect_plugin("memlabs_pslist_output.csv")
    'pslist'
    >>> detect_plugin("random_file.csv") is None
    True
    """
    name = filename.lower()
    for keyword, canonical in _PLUGIN_ALIASES.items():
        if keyword in name:
            return canonical
    return None


# ── Individual parsers ────────────────────────────────────────

def parse_pslist(content: str) -> list[dict]:
    """
    Parse pslist / pstree CSV.

    Volatility 3 headers:
        TreeDepth, PID, PPID, ImageFileName, Offset(V), Threads,
        Handles, SessionId, Wow64, CreateTime, ExitTime, File output
    """
    records = []
    for row in _reader(content):
        records.append({
            "pid":         _safe_int(row.get("PID", 0)),
            "ppid":        _safe_int(row.get("PPID", 0)),
            "name":        row.get("ImageFileName", "Unknown").strip(),
            "create_time": row.get("CreateTime", "").strip(),
            "threads":     _safe_int(row.get("Threads", 0)),
            "handles":     _safe_int(row.get("Handles", 0)),
            "wow64":       row.get("Wow64", "").strip(),
            "offset":      row.get("Offset(V)", "").strip(),
            "session_id":  _safe_int(row.get("SessionId", 0)),
            "exit_time":   row.get("ExitTime", "").strip(),
        })
    log.info("pslist: parsed %d processes", len(records))
    return records


def parse_netscan(content: str) -> list[dict]:
    """
    Parse netscan / netstat CSV.

    Volatility 3 headers:
        TreeDepth, Offset, Proto, LocalAddr, LocalPort, ForeignAddr,
        ForeignPort, State, PID, Owner, Created
    """
    records = []
    for row in _reader(content):
        records.append({
            "pid":          _safe_int(row.get("PID", 0)),
            "owner":        row.get("Owner", "Unknown").strip(),
            "proto":        row.get("Proto", "").strip(),
            "local_addr":   row.get("LocalAddr", "").strip(),
            "local_port":   _safe_int(row.get("LocalPort", 0)),
            "foreign_addr": row.get("ForeignAddr", "").strip(),
            "foreign_port": _safe_int(row.get("ForeignPort", 0)),
            "state":        row.get("State", "").strip(),
            "created":      row.get("Created", "").strip(),
        })
    log.info("netscan: parsed %d connections", len(records))
    return records


def parse_cmdline(content: str) -> list[dict]:
    """
    Parse cmdline CSV.

    Volatility 3 headers:  TreeDepth, PID, Process, Args
    """
    records = []
    for row in _reader(content):
        records.append({
            "pid":  _safe_int(row.get("PID", 0)),
            "name": row.get("Process", "Unknown").strip(),
            "args": row.get("Args", "").strip(),
        })
    log.info("cmdline: parsed %d entries", len(records))
    return records


def parse_dlllist(content: str) -> list[dict]:
    """
    Parse dlllist CSV.

    Volatility 3 headers:
        TreeDepth, PID, Process, Base, Size, Name, Path,
        LoadCount, LoadTime, File output
    """
    records = []
    for row in _reader(content):
        records.append({
            "pid":       _safe_int(row.get("PID", 0)),
            "name":      row.get("Process", "Unknown").strip(),
            "base":      row.get("Base", "").strip(),
            "size":      row.get("Size", "").strip(),
            "dll_name":  row.get("Name", "").strip(),
            "path":      row.get("Path", "").strip(),
            "load_time": row.get("LoadTime", "").strip(),
        })
    log.info("dlllist: parsed %d DLLs", len(records))
    return records


def parse_malfind(content: str) -> list[dict]:
    """
    Parse malfind CSV.

    Volatility 3 headers:
        TreeDepth, PID, Process, Start VPN, End VPN, Tag, Protection,
        CommitCharge, PrivateMemory, File output, Notes, Hexdump, Disasm
    """
    records = []
    for row in _reader(content):
        records.append({
            "pid":        _safe_int(row.get("PID", 0)),
            "name":       row.get("Process", "Unknown").strip(),
            "address":    row.get("Start VPN", "").strip(),
            "end":        row.get("End VPN", "").strip(),
            "protection": row.get("Protection", "").strip(),
            "tag":        row.get("Tag", "").strip(),
            "hexdump":    row.get("Hexdump", "").strip()[:200],
            "disasm":     row.get("Disasm", "").strip()[:200],
        })
    log.info("malfind: parsed %d regions", len(records))
    return records


def parse_handles(content: str) -> list[dict]:
    """
    Parse handles CSV.

    Volatility 3 headers:
        TreeDepth, PID, Process, Offset, HandleValue, Type,
        GrantedAccess, Name
    """
    records = []
    for row in _reader(content):
        records.append({
            "pid":            _safe_int(row.get("PID", 0)),
            "name":           row.get("Process", "Unknown").strip(),
            "handle":         row.get("HandleValue", "").strip(),
            "type":           row.get("Type", "").strip(),
            "granted_access": row.get("GrantedAccess", "").strip(),
            "value":          row.get("Name", "").strip(),
        })
    log.info("handles: parsed %d handles", len(records))
    return records


def parse_privs(content: str) -> list[dict]:
    """
    Parse privs / privileges CSV.

    Volatility 3 headers:
        TreeDepth, PID, Process, Value, Privilege, Attributes, Description

    The Attributes field contains comma-separated flags like
    'Present,Enabled,Default'.  We derive boolean `enabled` and
    `present` fields for the detection engine.
    """
    records = []
    for row in _reader(content):
        attrs = row.get("Attributes", "").strip()
        records.append({
            "pid":         _safe_int(row.get("PID", 0)),
            "name":        row.get("Process", "Unknown").strip(),
            "priv":        row.get("Privilege", "").strip(),
            "enabled":     "enabled" in attrs.lower(),
            "present":     "present" in attrs.lower(),
            "attrs":       attrs,
            "description": row.get("Description", "").strip(),
        })
    log.info("privs: parsed %d privilege entries", len(records))
    return records


def parse_envars(content: str) -> list[dict]:
    """
    Parse envars CSV.

    Volatility 3 headers:  TreeDepth, PID, Process, Block, Variable, Value
    """
    records = []
    for row in _reader(content):
        records.append({
            "pid":   _safe_int(row.get("PID", 0)),
            "name":  row.get("Process", "Unknown").strip(),
            "block": row.get("Block", "").strip(),
            "key":   row.get("Variable", "").strip(),
            "value": row.get("Value", "").strip(),
        })
    log.info("envars: parsed %d variables", len(records))
    return records


# ── Dispatcher ────────────────────────────────────────────────

PLUGIN_PARSERS: dict[str, callable] = {
    "pslist":  parse_pslist,
    "netscan": parse_netscan,
    "cmdline": parse_cmdline,
    "dlllist": parse_dlllist,
    "malfind": parse_malfind,
    "handles": parse_handles,
    "privs":   parse_privs,
    "envars":  parse_envars,
}


def parse_file(plugin: str, content: str) -> list[dict]:
    """
    Dispatch to the correct parser for the given plugin name.

    Returns an empty list if the plugin is unknown or parsing fails.
    """
    parser = PLUGIN_PARSERS.get(plugin)
    if parser is None:
        log.warning("No parser registered for plugin: %s", plugin)
        return []
    try:
        return parser(content)
    except Exception:
        log.exception("Parser failed for %s", plugin)
        return []