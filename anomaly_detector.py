# ============================================================
# anomaly_detector.py — Rule-Based Detection Engine
# 11 detection rules across 9 categories, all mapped to
# MITRE ATT&CK v15 techniques.
#
# Rule catalogue:
#   PROC-001  Wrong parent process
#   PROC-002  Duplicate singleton process
#   PROC-003  Typosquatted process name
#   NET-001   Suspicious port (common C2/reverse-shell)
#   NET-002   System process with external connection
#   CMD-001   Obfuscated / suspicious command line
#   DLL-001   DLL loaded from suspicious path
#   MAL-001   Injected code region (malfind)
#   HDL-001   Handle to persistence registry key
#   PRV-001   Dangerous privilege on non-system process
#   ENV-001   Suspicious environment variable modification
#   XREF-001  Multi-source compromise corroboration
#
# Author: Simon | COMP3000 | University of Plymouth
# ============================================================
"""
Pure-function detection engine.  `run_detection(session)` accepts a
dict of plugin_name → [records] and returns:

    {
        "findings": [ {rule, severity, title, detail, mitre} ... ],
        "summary":  {"CRITICAL": n, "HIGH": n, "MEDIUM": n, "LOW": n},
    }

Design philosophy:
- Every finding must cite specific PIDs and evidence.
- MITRE ATT&CK mapping on every finding enables the UI to link directly
  to the knowledge base.
- Cross-reference rule (XREF-001) fires when a PID is flagged by ≥2
  independent data sources — the strongest triage signal.
"""

from __future__ import annotations

# ── Knowledge bases ───────────────────────────────────────────

# Expected parent for critical Windows processes
EXPECTED_PARENTS: dict[str, str] = {
    "svchost.exe":  "services.exe",
    "lsass.exe":    "wininit.exe",
    "services.exe": "wininit.exe",
    "csrss.exe":    "smss.exe",
    "winlogon.exe": "smss.exe",
    "wininit.exe":  "smss.exe",
}

# Processes that should only have a single instance
SINGLETON_PROCESSES: set[str] = {"lsass.exe", "services.exe", "wininit.exe"}

# Misspellings / typosquats of legitimate Windows process names
SUSPICIOUS_NAMES: set[str] = {
    "svch0st.exe", "scvhost.exe", "svchosl.exe",
    "lssas.exe", "cssrs.exe", "explore.exe",
    "svchosts.exe", "lsas.exe", "csrs.exe",
}

# Ports commonly used by Meterpreter, reverse shells, and RATs
SUSPICIOUS_PORTS: set[int] = {4444, 5555, 6666, 8888, 9999, 1234, 12345, 31337}

# System-level processes that should never make external connections
SYSTEM_PROCESSES: set[str] = {"lsass.exe", "csrss.exe", "smss.exe", "wininit.exe"}

# DLL paths that are unusual / suspicious
# Note: \programdata\ was removed — too many false positives from
# legitimate software (Windows Defender, etc.) storing DLLs there.
SUSPICIOUS_DLL_PATHS: list[str] = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\users\\public\\", "\\downloads\\", "\\desktop\\",
    "\\recycle",
]

# Known safe DLL paths that should NOT be flagged even if they match above.
# This handles edge cases like DumpIt being run from Downloads by an analyst.
SAFE_DLL_PROCESSES: set[str] = {
    "dumpit.exe",      # memory capture tool — analyst tooling
}

# Command-line flags associated with malicious PowerShell / script use
SUSPICIOUS_CMD_FLAGS: list[str] = [
    "-enc", "-encodedcommand", "-nop", "-noprofile",
    "-windowstyle hidden", "-exec bypass", "iex ",
    "invoke-expression", "downloadstring", "webclient",
    "frombase64string", "hidden -ep bypass",
    "new-object net.webclient", "bitstransfer",
]

# Registry keys commonly used for persistence
PERSISTENCE_KEYS: list[str] = [
    "software\\microsoft\\windows\\currentversion\\run",
    "software\\microsoft\\windows\\currentversion\\runonce",
    "system\\currentcontrolset\\services",
    "software\\microsoft\\windows nt\\currentversion\\winlogon",
]

# Privileges that enable credential theft, injection, or escalation
DANGEROUS_PRIVS: set[str] = {
    "sedebugprivilege",
    "seimpersonateprivilege",
    "setcbprivilege",
    "seloaddriverprivilege",
    "serestoreprivilege",
    "setakeownershipprivilege",
}

# Processes where dangerous privileges are expected (SYSTEM-level)
# These are legitimate Windows processes that routinely hold elevated
# privileges — flagging them would produce excessive false positives.
EXPECTED_PRIV_PROCS: set[str] = {
    "system", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "lsm.exe", "svchost.exe",
    "winlogon.exe",        # handles user logon — needs SeTcbPrivilege
    "psxss.exe",           # POSIX subsystem — runs as SYSTEM
    "sppsvc.exe",          # Software Protection Platform
    "searchindexer.",      # Windows Search — truncated in Vol3 output
    "searchfilterho",      # Search Filter Host — truncated in Vol3
    "audiodg.exe",         # Audio Device Graph — runs with elevated privs
    "wmpnetwk.exe",        # Windows Media Player Network Sharing
    "taskhost.exe",        # Task Host — runs scheduled tasks as SYSTEM
    "msdtc.exe",           # Distributed Transaction Coordinator
    "spoolsv.exe",         # Print Spooler
    "dllhost.exe",         # COM Surrogate
    "vboxservice.ex",      # VirtualBox Guest Additions — runs as SYSTEM in VMs
    "vboxtray.exe",        # VirtualBox system tray — VM environment
    "dumpit.exe",          # Memory capture tool — analyst/investigator tooling
    "conhost.exe",         # Console Window Host — legitimate Windows process
}

# Environment variable keys that may indicate tampering
SUSPICIOUS_ENV_KEYS: set[str] = {
    "comspec", "path", "pathext", "windir", "systemroot",
}


# ── MITRE ATT&CK v15 Technique Library ───────────────────────

MITRE_TECHNIQUES: dict[str, dict] = {
    "T1036.005": {
        "id": "T1036.005",
        "name": "Masquerading: Match Legitimate Name or Location",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1036/005/",
        "description": (
            "Adversaries rename or misspell malicious executables to match "
            "legitimate Windows process names."
        ),
    },
    "T1055": {
        "id": "T1055",
        "name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1055/",
        "description": (
            "Adversaries inject code into processes to evade defences and "
            "elevate privileges."
        ),
    },
    "T1041": {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1041/",
        "description": (
            "Adversaries steal data by sending it over the existing "
            "command-and-control channel."
        ),
    },
    "T1219": {
        "id": "T1219",
        "name": "Remote Access Software",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1219/",
        "description": (
            "Adversaries use tools such as Meterpreter or reverse shells "
            "to maintain persistent access."
        ),
    },
    "T1059.001": {
        "id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
        "description": (
            "Adversaries abuse PowerShell using obfuscation flags to evade "
            "detection."
        ),
    },
    "T1574.001": {
        "id": "T1574.001",
        "name": "Hijack Execution Flow: DLL Search Order Hijacking",
        "tactic": "Persistence, Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1574/001/",
        "description": (
            "Adversaries plant malicious DLLs in locations searched before "
            "legitimate ones."
        ),
    },
    "T1547.001": {
        "id": "T1547.001",
        "name": "Boot or Logon Autostart: Registry Run Keys",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1547/001/",
        "description": (
            "Adversaries add programs to Run keys to achieve persistence "
            "across reboots."
        ),
    },
    "T1134": {
        "id": "T1134",
        "name": "Access Token Manipulation",
        "tactic": "Defense Evasion, Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1134/",
        "description": (
            "Adversaries manipulate access tokens to escalate privileges "
            "or bypass access controls."
        ),
    },
    "T1057": {
        "id": "T1057",
        "name": "Process Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1057/",
        "description": (
            "Adversaries enumerate running processes to identify targets "
            "for injection or lateral movement."
        ),
    },
    "T1562.001": {
        "id": "T1562.001",
        "name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1562/001/",
        "description": (
            "Adversaries modify environment variables such as PATH to "
            "redirect execution or disable security tools."
        ),
    },
}


# ── Detection functions ───────────────────────────────────────

def check_processes(processes: list[dict]) -> list[dict]:
    """PROC-001 / PROC-002 / PROC-003 — process-level anomalies."""
    findings = []
    pid_lookup = {p["pid"]: p for p in processes}

    # PROC-001: Wrong parent
    for proc in processes:
        name_lower = proc["name"].lower()
        if name_lower in EXPECTED_PARENTS:
            expected = EXPECTED_PARENTS[name_lower]
            actual_parent = pid_lookup.get(proc["ppid"])
            if actual_parent and actual_parent["name"].lower() != expected:
                findings.append({
                    "rule": "PROC-001", "severity": "HIGH",
                    "title": f"Wrong parent for {proc['name']} (PID {proc['pid']})",
                    "detail": (
                        f"{proc['name']} (PID {proc['pid']}) is a child of "
                        f"{actual_parent['name']} (PID {proc['ppid']}) but should be "
                        f"started by {expected}. This strongly suggests masquerading."
                    ),
                    "mitre": MITRE_TECHNIQUES["T1036.005"],
                })

    # PROC-002: Duplicate singletons
    name_count: dict[str, list] = {}
    for proc in processes:
        name_count.setdefault(proc["name"].lower(), []).append(proc)
    for name, lst in name_count.items():
        if name in SINGLETON_PROCESSES and len(lst) > 1:
            pids = ", ".join(str(p["pid"]) for p in lst)
            findings.append({
                "rule": "PROC-002", "severity": "HIGH",
                "title": f"Multiple instances of {lst[0]['name']}",
                "detail": (
                    f"Found {len(lst)} copies (PIDs: {pids}). Only one should "
                    f"exist. The extra copy is likely malware."
                ),
                "mitre": MITRE_TECHNIQUES["T1055"],
            })

    # PROC-003: Typosquatted names
    for proc in processes:
        if proc["name"].lower() in SUSPICIOUS_NAMES:
            findings.append({
                "rule": "PROC-003", "severity": "CRITICAL",
                "title": f"Suspicious process name: {proc['name']} (PID {proc['pid']})",
                "detail": (
                    f"'{proc['name']}' mimics a legitimate Windows process. "
                    f"Almost certainly malware."
                ),
                "mitre": MITRE_TECHNIQUES["T1036.005"],
            })

    # PROC-004: Ghost parent — PPID not present in process list
    # Some processes normally have ghost parents because their creator exits
    # (e.g. smss.exe spawns csrss/wininit/winlogon then exits).  We only
    # flag processes where a ghost parent is genuinely suspicious.
    _NORMAL_GHOST_PARENTS = {
        "csrss.exe", "wininit.exe", "winlogon.exe",  # created by smss.exe
        "system",                                       # kernel process
    }
    for proc in processes:
        if proc["ppid"] == 0:
            continue  # System/Idle — always PPID 0
        if proc["name"].lower() in _NORMAL_GHOST_PARENTS:
            continue  # expected ghost parent
        if proc["ppid"] not in pid_lookup:
            findings.append({
                "rule": "PROC-004", "severity": "HIGH",
                "title": (
                    f"Ghost parent: {proc['name']} (PID {proc['pid']}) "
                    f"has non-existent PPID {proc['ppid']}"
                ),
                "detail": (
                    f"{proc['name']} (PID {proc['pid']}) claims parent PID "
                    f"{proc['ppid']}, but that process does not exist in the "
                    f"process list. This indicates the parent has terminated — "
                    f"consistent with a staged attack loader or process hollowing."
                ),
                "mitre": MITRE_TECHNIQUES["T1055"],
            })

    return findings


def check_network(connections: list[dict]) -> list[dict]:
    """NET-001 / NET-002 — network-level anomalies."""
    findings = []
    seen_ports: set[tuple] = set()

    _TRIVIAL_ADDRS = {"0.0.0.0", "127.0.0.1", "*", "", "-", "::"}

    for conn in connections:
        # NET-001: Suspicious ports
        port_key = (conn["pid"], conn["local_port"])
        if conn["local_port"] in SUSPICIOUS_PORTS and port_key not in seen_ports:
            seen_ports.add(port_key)
            findings.append({
                "rule": "NET-001", "severity": "MEDIUM",
                "title": (
                    f"{conn['owner']} (PID {conn['pid']}) "
                    f"using port {conn['local_port']}"
                ),
                "detail": (
                    f"Port {conn['local_port']} is commonly used by Meterpreter "
                    f"or reverse shells."
                ),
                "mitre": MITRE_TECHNIQUES["T1219"],
            })

        # NET-002: System processes with external connections
        owner = conn["owner"].lower()
        foreign = conn["foreign_addr"]
        if owner in SYSTEM_PROCESSES and foreign:
            if foreign in _TRIVIAL_ADDRS:
                continue
            if foreign.startswith(("192.168.", "10.", "172.16.")):
                continue
            findings.append({
                "rule": "NET-002", "severity": "HIGH",
                "title": (
                    f"{conn['owner']} (PID {conn['pid']}) "
                    f"connecting to {foreign}"
                ),
                "detail": (
                    f"{conn['owner']} is a system process that should never "
                    f"communicate with external IPs.  Possible C2 or data "
                    f"exfiltration."
                ),
                "mitre": MITRE_TECHNIQUES["T1041"],
            })

    return findings


def check_cmdline(cmdlines: list[dict]) -> list[dict]:
    """CMD-001 — suspicious command-line arguments."""
    findings = []
    for entry in cmdlines:
        args_lower = entry["args"].lower()
        for flag in SUSPICIOUS_CMD_FLAGS:
            if flag in args_lower:
                findings.append({
                    "rule": "CMD-001", "severity": "HIGH",
                    "title": (
                        f"Suspicious command line for {entry['name']} "
                        f"(PID {entry['pid']})"
                    ),
                    "detail": (
                        f"Command contains '{flag}' — commonly used to obfuscate "
                        f"malicious execution. Args: {entry['args'][:300]}"
                    ),
                    "mitre": MITRE_TECHNIQUES["T1059.001"],
                })
                break  # one finding per process
    return findings


def check_dlllist(dlls: list[dict]) -> list[dict]:
    """DLL-001 — DLLs loaded from suspicious paths."""
    findings = []
    seen: set[tuple] = set()
    for entry in dlls:
        # Skip known safe processes (e.g. analyst tooling)
        if entry["name"].lower() in SAFE_DLL_PROCESSES:
            continue
        path_lower = entry["path"].lower()
        key = (entry["pid"], entry["path"])
        if key in seen:
            continue
        for sus in SUSPICIOUS_DLL_PATHS:
            if sus in path_lower:
                seen.add(key)
                findings.append({
                    "rule": "DLL-001", "severity": "HIGH",
                    "title": (
                        f"Suspicious DLL path in {entry['name']} "
                        f"(PID {entry['pid']})"
                    ),
                    "detail": (
                        f"DLL loaded from suspicious location: {entry['path']}. "
                        f"Legitimate DLLs load from System32 or Program Files."
                    ),
                    "mitre": MITRE_TECHNIQUES["T1574.001"],
                })
                break
    return findings


def check_malfind(malfind_entries: list[dict]) -> list[dict]:
    """
    MAL-001 — injected code regions.

    Every malfind entry is a PAGE_EXECUTE_READWRITE region not backed by
    a file on disk — the primary indicator of process injection / shellcode.
    We emit one finding per unique PID.
    """
    findings = []
    seen_pids: set[int] = set()
    for entry in malfind_entries:
        if entry["pid"] in seen_pids:
            continue
        seen_pids.add(entry["pid"])
        findings.append({
            "rule": "MAL-001", "severity": "CRITICAL",
            "title": (
                f"Injected code region detected in {entry['name']} "
                f"(PID {entry['pid']})"
            ),
            "detail": (
                f"malfind found a {entry['protection']} memory region at "
                f"{entry['address']} in {entry['name']} (PID {entry['pid']}) "
                f"that is not backed by any file on disk. This is a strong "
                f"indicator of shellcode injection or reflective DLL loading."
            ),
            "mitre": MITRE_TECHNIQUES["T1055"],
        })
    return findings


def check_handles(handles: list[dict]) -> list[dict]:
    """HDL-001 — handles to persistence registry keys."""
    findings = []
    seen: set[tuple] = set()
    for entry in handles:
        value_lower = entry["value"].lower()
        key = (entry["pid"], entry["value"])
        if key in seen:
            continue
        for run_key in PERSISTENCE_KEYS:
            if run_key in value_lower:
                seen.add(key)
                findings.append({
                    "rule": "HDL-001", "severity": "HIGH",
                    "title": (
                        f"Persistence registry key opened by {entry['name']} "
                        f"(PID {entry['pid']})"
                    ),
                    "detail": (
                        f"Process has an open handle to known persistence "
                        f"location: {entry['value']}"
                    ),
                    "mitre": MITRE_TECHNIQUES["T1547.001"],
                })
                break
    return findings


def check_privs(privs: list[dict]) -> list[dict]:
    """
    PRV-001 — dangerous privileges enabled on non-system processes.

    Volatility 3 Attributes field contains comma-separated values like
    'Present,Enabled,Default'.  We flag ENABLED dangerous privileges on
    processes that are not expected to hold them.
    """
    findings = []
    seen: set[tuple] = set()
    for entry in privs:
        priv_lower = entry["priv"].lower()
        proc_lower = entry["name"].lower()
        key = (entry["pid"], entry["priv"])

        if key in seen:
            continue
        if proc_lower in EXPECTED_PRIV_PROCS:
            continue
        if priv_lower in DANGEROUS_PRIVS and entry.get("enabled"):
            seen.add(key)
            findings.append({
                "rule": "PRV-001", "severity": "HIGH",
                "title": (
                    f"Dangerous privilege enabled: {entry['priv']} on "
                    f"{entry['name']} (PID {entry['pid']})"
                ),
                "detail": (
                    f"{entry['priv']} is enabled on {entry['name']} "
                    f"(PID {entry['pid']}). This privilege is commonly abused "
                    f"for credential theft, lateral movement, or privilege "
                    f"escalation. Attributes: {entry['attrs']}"
                ),
                "mitre": MITRE_TECHNIQUES["T1134"],
            })
    return findings


def check_envars(envars: list[dict]) -> list[dict]:
    """
    ENV-001 — suspicious environment variable modifications.

    Flags processes that set security-sensitive environment variables
    (e.g. PATH, COMSPEC) to non-standard values, which may indicate
    execution-flow hijacking.
    """
    findings = []
    seen: set[tuple] = set()
    for entry in envars:
        key_lower = entry["key"].lower()
        if key_lower not in SUSPICIOUS_ENV_KEYS:
            continue
        # Flag if value looks unusual (contains temp/download paths)
        val_lower = entry["value"].lower()
        suspicious = any(
            s in val_lower
            for s in ["\\temp", "\\tmp", "\\downloads", "\\appdata\\local\\temp"]
        )
        if not suspicious:
            continue
        dedup_key = (entry["pid"], entry["key"])
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        findings.append({
            "rule": "ENV-001", "severity": "MEDIUM",
            "title": (
                f"Suspicious environment variable in {entry['name']} "
                f"(PID {entry['pid']})"
            ),
            "detail": (
                f"Process {entry['name']} (PID {entry['pid']}) has "
                f"{entry['key']}={entry['value'][:200]}. Modification of "
                f"security-sensitive environment variables may indicate "
                f"execution-flow hijacking."
            ),
            "mitre": MITRE_TECHNIQUES["T1562.001"],
        })
    return findings


def check_cross_references(session: dict) -> list[dict]:
    """
    XREF-001 — multi-source compromise indicator.

    Finds processes flagged by ≥2 independent data sources.  This is the
    highest-confidence triage signal because independent corroboration
    dramatically reduces false-positive probability.
    """
    findings = []

    processes   = session.get("pslist", [])
    connections = session.get("netscan", [])
    malfind     = session.get("malfind", [])
    cmdlines    = session.get("cmdline", [])

    if not processes:
        return findings

    pid_lookup = {p["pid"]: p for p in processes}

    # Build suspicious-PID sets per data source
    _TRIVIAL = {"0.0.0.0", "127.0.0.1", "*", "", "-", "::"}

    net_pids = {
        c["pid"] for c in connections
        if c.get("foreign_addr")
        and c["foreign_addr"] not in _TRIVIAL
        and not c["foreign_addr"].startswith(("192.168.", "10.", "172.16."))
    }

    mal_pids = {e["pid"] for e in malfind}

    cmd_sus_pids: set[int] = set()
    for e in cmdlines:
        if any(f in e["args"].lower() for f in SUSPICIOUS_CMD_FLAGS):
            cmd_sus_pids.add(e["pid"])

    # Ghost parent PIDs — processes whose parent doesn't exist in pslist
    # (excluding processes where ghost parents are normal, e.g. csrss)
    _NORMAL_GHOST = {"csrss.exe", "wininit.exe", "winlogon.exe", "system"}
    ghost_pids: set[int] = set()
    for p in processes:
        if p["ppid"] != 0 and p["ppid"] not in pid_lookup:
            if p["name"].lower() not in _NORMAL_GHOST:
                ghost_pids.add(p["pid"])

    pid_name = {p["pid"]: p["name"] for p in processes}

    for pid, name in pid_name.items():
        sources = []
        if pid in net_pids:
            sources.append("external network connection (netscan)")
        if pid in mal_pids:
            sources.append("injected memory region (malfind)")
        if pid in cmd_sus_pids:
            sources.append("suspicious command-line arguments (cmdline)")
        if pid in ghost_pids:
            sources.append("ghost parent PID — creator no longer running (pslist)")

        if len(sources) >= 2:
            findings.append({
                "rule": "XREF-001", "severity": "CRITICAL",
                "title": f"Multi-source compromise indicator: {name} (PID {pid})",
                "detail": (
                    f"PID {pid} ({name}) was independently flagged by "
                    f"{len(sources)} data sources: {'; '.join(sources)}. "
                    f"Corroboration across multiple plugins is a very strong "
                    f"indicator of active compromise."
                ),
                "mitre": MITRE_TECHNIQUES["T1057"],
            })

    return findings


# ── Main entry point ──────────────────────────────────────────

def run_detection(session: dict) -> dict:
    """
    Execute all detection rules against the current session data.

    Parameters
    ----------
    session : dict
        Mapping of plugin_name → list[record_dict].

    Returns
    -------
    dict
        ``{"findings": [...], "summary": {"CRITICAL": n, ...}}``
    """
    findings: list[dict] = []

    _CHECKS = [
        ("pslist",  check_processes),
        ("netscan", check_network),
        ("cmdline", check_cmdline),
        ("dlllist", check_dlllist),
        ("malfind", check_malfind),
        ("handles", check_handles),
        ("privs",   check_privs),
        ("envars",  check_envars),
    ]

    for plugin, checker in _CHECKS:
        data = session.get(plugin)
        if data:
            findings.extend(checker(data))

    # Cross-reference rule operates on the whole session
    findings.extend(check_cross_references(session))

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1

    return {"findings": findings, "summary": summary}