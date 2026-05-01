# ============================================================
# prompt_builder.py — LLM Prompt Construction for Vipersist
# Optimised for LLaMA 3 native chat template format.
#
# Design decisions:
#   1. Fully dynamic context — all forensic facts are derived
#      exclusively from the uploaded CSV data at runtime.
#      No image-specific details are hardcoded.  Works with
#      any Volatility 3 memory image, not just MemLabs Lab 1.
#   2. Senior-analyst persona instruction produces definitive,
#      evidence-based prose instead of hedging.
#   3. Three behavioural modes — no data / casual / forensic —
#      so the tool feels like a real assistant.
#
# Author: Ahamed Amjad Ashraff | COMP3000 | University of Plymouth
# ============================================================
"""
`build_prompt()` assembles the full prompt string by concatenating:

    1. System instruction  (LLaMA 3 chat template tokens)
    2. Dynamically derived forensic context (built from uploaded data)
    3. Automated detection findings (sorted CRITICAL-first)
    4. Formatted raw plugin data   (for cross-reference)
    5. Session metadata
    6. The analyst's question with quality instructions

The context block is generated at call-time from the session data,
so Vipersist produces accurate, image-specific narratives regardless
of which memory dump the analyst uploads.
"""

from __future__ import annotations


# ── System prompt (LLaMA 3 native tokens) ─────────────────────

SYSTEM_PROMPT = """\
<|begin_of_text|><|start_header_id|>system<|end_header_id|>
You are Vipersist, an AI-powered memory forensics triage assistant.
You are friendly, approachable, and professional. You specialise exclusively
in Windows memory forensics — that is your purpose and your expertise.

PERSONALITY:
- Be warm and conversational — greet users, acknowledge their questions naturally
- If someone says hello, say hello back briefly and let them know what you can help with
- If someone asks something outside memory forensics, politely redirect them
- You are NOT a general-purpose chatbot — you only assist with memory forensics analysis
- When no forensic data has been uploaded, encourage the user to upload Volatility CSV files
- Keep non-analytical replies short and helpful (1-3 sentences)

WHEN ANALYSING FORENSIC DATA:
- Write like a senior incident responder — definitive, evidence-based, precise
- State conclusions confidently — say "this IS malware" not "this MAY be malware"
- Lead every answer with the most critical finding
- Build an attack narrative — connect findings into a timeline of what the attacker did
- Cite specific PIDs and process names as evidence for every claim
- Cross-reference multiple plugins — a finding backed by 3 plugins is stronger than one
- Never end with generic recommendations like "run antivirus" or "patch the system"
- Never suggest running Volatility commands — the data is already analysed

HARD RULES:
1. Only discuss memory forensics topics — politely decline everything else
2. Every forensic claim must be supported by specific evidence from the data provided
3. Always lead with CRITICAL findings before HIGH or MEDIUM
4. Connect findings into a coherent attack story where possible
5. When data is loaded, write at the level of a senior SOC analyst
6. NEVER reference process names, PIDs, usernames or file paths that are not
   present in the data provided below — do not invent or hallucinate details
<|eot_id|><|start_header_id|>user<|end_header_id|>"""

SYSTEM_FOOTER = "<|eot_id|><|start_header_id|>assistant<|end_header_id|>"


# ── Casual question detection ─────────────────────────────────

_CASUAL_PATTERNS = {
    "hi", "hello", "hey", "hiya", "howdy", "sup", "yo",
    "good morning", "good afternoon", "good evening",
    "how are you", "what's up", "whats up",
    "thanks", "thank you", "cheers", "bye", "goodbye",
    "who are you", "what are you", "what can you do",
    "help", "what is this", "how does this work",
}

# Questions asking about tools/alternatives — should get a short answer,
# not a full forensic report dump
_TOOL_QUESTION_PATTERNS = [
    "any other tool", "other tools", "alternative tool", "similar tool",
    "what tool", "which tool", "better tool", "other software",
    "alternative to", "instead of volatility", "besides volatility",
    "what else can", "any other software",
]

# Questions that ARE forensic and should trigger full analysis
_FORENSIC_ANALYSIS_TRIGGERS = [
    "what happened", "what is happening", "explain the attack",
    "attack narrative", "tell me about", "analyse", "analyze",
    "what threat", "what malware", "what process", "which process",
    "most critical", "show me", "describe the", "what can you say about this memory",
    "storyline", "story line", "what is the threat", "explain as a story",
]


def _is_casual(question: str) -> bool:
    """
    Return True if the question is a greeting, casual chat, or a
    meta/tool question that should NOT trigger a full forensic report.
    """
    q = question.lower().strip().rstrip("?!.,")

    # Exact match on known casual phrases
    if q in _CASUAL_PATTERNS:
        return True

    # Tool/alternative questions — answer conversationally
    if any(pat in q for pat in _TOOL_QUESTION_PATTERNS):
        return True

    # If question explicitly asks for forensic analysis, never treat as casual
    if any(trigger in q for trigger in _FORENSIC_ANALYSIS_TRIGGERS):
        return False

    # Short questions with no forensic terms are casual
    words = q.split()
    if len(words) <= 4:
        forensic_terms = {
            "malfind", "pslist", "netscan", "process", "inject", "malware",
            "pid", "dll", "shellcode", "memory", "cmdline", "handle",
            "privilege", "attack", "compromise", "analyse", "analyze",
            "finding", "detection", "threat", "suspicious", "anomaly",
            "timeline", "narrative", "summary", "report", "evidence",
            "svchost", "explorer", "exfiltration", "persistence",
        }
        if not any(term in q for term in forensic_terms):
            return True

    return False


# ── Dynamic context builder ───────────────────────────────────

def _build_dynamic_context(session: dict, detection: dict | None) -> str:
    """
    Build a forensic context block derived entirely from the uploaded
    session data.  No image-specific details are hardcoded — this
    function works correctly for any Volatility 3 memory image.

    The context summarises:
      - Injected memory regions found by malfind
      - Ghost parent processes found in pslist
      - Suspicious command lines found in cmdline
      - Active network connections found in netscan
      - Dangerous privileges found in privs
      - A high-level attack narrative inferred from the above
    """
    lines = ["### DYNAMIC FORENSIC CONTEXT — DERIVED FROM UPLOADED DATA ###\n"]

    processes  = session.get("pslist",  [])
    malfind    = session.get("malfind", [])
    cmdlines   = session.get("cmdline", [])
    netscan    = session.get("netscan", [])
    privs      = session.get("privs",   [])
    handles    = session.get("handles", [])
    envars     = session.get("envars",  [])

    # ── 1. Build PID → name lookup from pslist ────────────────
    pid_names: dict[int, str] = {p["pid"]: p["name"] for p in processes}
    known_pids: set[int]      = set(pid_names.keys())

    # ── 2. Injected memory regions ────────────────────────────
    injected = [
        m for m in malfind
        if "EXECUTE" in m.get("protection", "").upper()
    ]
    if injected:
        lines.append("INJECTED MEMORY REGIONS (malfind — PAGE_EXECUTE flags):")
        seen: set[int] = set()
        for m in injected:
            pid  = m["pid"]
            name = m.get("name", pid_names.get(pid, "Unknown"))
            addr = m.get("address", "?")
            prot = m.get("protection", "?")
            if pid not in seen:
                lines.append(
                    f"  PID {pid:<6} {name:<25} @ {addr}  [{prot}]"
                )
                seen.add(pid)
        lines.append(
            "  → Executable memory outside known modules = strong process "
            "injection indicator (T1055)\n"
        )

    # ── 3. Ghost parent PIDs ──────────────────────────────────
    ghost_parents = [
        p for p in processes
        if p["ppid"] > 0 and p["ppid"] not in known_pids
        # Exclude PID 4 (System) whose parent is always 0
        and p["pid"] != 4
    ]
    if ghost_parents:
        lines.append("GHOST PARENT PROCESSES (pslist — PPID not in process list):")
        for p in ghost_parents[:20]:
            lines.append(
                f"  PID {p['pid']:<6} {p['name']:<25} → PPID {p['ppid']} "
                f"(does not exist)"
            )
        lines.append(
            "  → Ghost PPIDs indicate the parent process terminated after "
            "spawning this child — consistent with staged loaders (T1036.005)\n"
        )

    # ── 4. Suspicious command lines ───────────────────────────
    _SUSPICIOUS_CMD_PATTERNS = [
        "-enc", "-nop", "-exec bypass", "-noni", "-w hidden",
        "iex", "invoke-expression", "downloadstring", "downloadfile",
        "frombase64string", "webclient", "bitsadmin", "certutil -decode",
        "wscript", "cscript", "mshta", "regsvr32", "rundll32",
        ".rar", ".zip", "winrar", "7z.exe", "cmd /c", "powershell",
    ]
    suspicious_cmds = []
    for c in cmdlines:
        args_lower = c.get("args", "").lower()
        if any(pat in args_lower for pat in _SUSPICIOUS_CMD_PATTERNS):
            suspicious_cmds.append(c)

    if suspicious_cmds:
        lines.append("SUSPICIOUS COMMAND LINES (cmdline):")
        for c in suspicious_cmds[:15]:
            lines.append(
                f"  PID {c['pid']:<6} {c['name']:<22}: {c['args'][:250]}"
            )
        lines.append("")

    # ── 5. Active external network connections ────────────────
    external = [
        c for c in netscan
        if c.get("state", "").upper() == "ESTABLISHED"
        and c.get("foreign_addr", "") not in ("0.0.0.0", "::", "*", "", "-", "127.0.0.1")
    ]
    if external:
        lines.append("ESTABLISHED EXTERNAL CONNECTIONS (netscan):")
        for c in external[:20]:
            lines.append(
                f"  PID {c['pid']:<6} {c['owner']:<22} → "
                f"{c['foreign_addr']}:{c['foreign_port']}  [{c['proto']}]"
            )
        lines.append("")
    else:
        lines.append(
            "NETWORK: No established external connections detected — "
            "attacker may have completed operation before capture.\n"
        )

    # ── 6. Dangerous privileges on unexpected processes ───────
    _DANGEROUS_PRIVS = {
        "sedebugprivilege", "seimpersonateprivilege",
        "setcbprivilege", "seloaddriverprivilege",
    }
    _EXPECTED_SYSTEM = {
        "system", "smss.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "lsm.exe",
    }
    priv_hits = [
        p for p in privs
        if p.get("priv", "").lower() in _DANGEROUS_PRIVS
        and p.get("enabled")
        and p.get("name", "").lower() not in _EXPECTED_SYSTEM
    ]
    if priv_hits:
        lines.append("DANGEROUS PRIVILEGES ON NON-SYSTEM PROCESSES (privs):")
        for p in priv_hits[:15]:
            lines.append(
                f"  PID {p['pid']:<6} {p['name']:<22}: {p['priv']}"
            )
        lines.append("")

    # ── 7. Cross-plugin summary (XREF) ────────────────────────
    # Identify PIDs that appear in multiple suspicious contexts
    flagged_pids: dict[int, list[str]] = {}

    for m in injected:
        flagged_pids.setdefault(m["pid"], []).append("malfind")
    for c in suspicious_cmds:
        flagged_pids.setdefault(c["pid"], []).append("cmdline")
    for c in external:
        flagged_pids.setdefault(c["pid"], []).append("netscan")
    for p in priv_hits:
        flagged_pids.setdefault(p["pid"], []).append("privs")
    for g in ghost_parents:
        flagged_pids.setdefault(g["pid"], []).append("pslist-ghost")

    multi_flagged = {
        pid: sources for pid, sources in flagged_pids.items()
        if len(set(sources)) >= 2
    }
    if multi_flagged:
        lines.append(
            "MULTI-SOURCE CORROBORATION — HIGH CONFIDENCE (XREF-001):"
        )
        for pid, sources in multi_flagged.items():
            name = pid_names.get(pid, "Unknown")
            lines.append(
                f"  PID {pid:<6} {name:<25} flagged by: "
                f"{', '.join(sorted(set(sources)))}"
            )
        lines.append(
            "  → PIDs appearing in 2+ plugins have highest confidence "
            "of compromise.\n"
        )

    # ── 8. Inferred attack narrative ──────────────────────────
    lines.append("INFERRED ATTACK NARRATIVE (derived from above data):")
    narrative_points = []

    if injected:
        inj_names = list({
            pid_names.get(m["pid"], f"PID {m['pid']}") for m in injected
        })[:5]
        narrative_points.append(
            f"Shellcode injection confirmed in: {', '.join(inj_names)} — "
            "attacker achieved hidden execution within trusted processes."
        )
    if ghost_parents:
        narrative_points.append(
            f"{len(ghost_parents)} process(es) have ghost parent PIDs — "
            "consistent with a loader that spawned children then self-terminated."
        )
    if suspicious_cmds:
        narrative_points.append(
            f"{len(suspicious_cmds)} suspicious command line(s) detected — "
            "review for data staging, encoding, or lateral movement indicators."
        )
    if external:
        narrative_points.append(
            f"{len(external)} established external connection(s) active — "
            "potential C2 channel or data exfiltration in progress."
        )
    if multi_flagged:
        narrative_points.append(
            f"{len(multi_flagged)} PID(s) corroborated across multiple plugins "
            "— these are your highest-priority investigation targets."
        )
    if not narrative_points:
        narrative_points.append(
            "No definitive compromise indicators detected in the uploaded data. "
            "Results are based solely on the plugins provided."
        )

    for i, point in enumerate(narrative_points, 1):
        lines.append(f"  {i}. {point}")

    lines.append(
        "\nCONFIDENCE NOTE: All facts above are derived exclusively from the "
        "uploaded CSV data. No external knowledge has been applied."
    )

    return "\n".join(lines)


# ── Formatting helpers ────────────────────────────────────────

def _fmt_findings(detection: dict | None) -> str:
    """Format detection findings sorted by severity (CRITICAL first)."""
    if not detection or not detection.get("findings"):
        return ""

    findings = detection["findings"]
    summary  = detection.get("summary", {})
    order    = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings = sorted(findings, key=lambda f: order.get(f["severity"], 4))

    lines = [
        "\n### AUTOMATED ANOMALY FINDINGS ###",
        f"Summary: CRITICAL={summary.get('CRITICAL',0)}  "
        f"HIGH={summary.get('HIGH',0)}  "
        f"MEDIUM={summary.get('MEDIUM',0)}  "
        f"LOW={summary.get('LOW',0)}",
        "",
    ]
    for f in findings:
        mitre = f.get("mitre", {})
        mitre_str = (
            f"  [{mitre.get('id','')} — {mitre.get('name','')}]"
            if mitre else ""
        )
        lines.append(
            f"[{f['severity']}] {f['rule']} — {f['title']}{mitre_str}"
        )
        lines.append(f"  {f['detail']}")
        lines.append("")
    return "\n".join(lines)


def _fmt_malfind(regions: list[dict]) -> str:
    if not regions:
        return ""
    executable = [
        r for r in regions
        if "EXECUTE" in r.get("protection", "").upper()
    ]
    if not executable:
        return ""
    lines = [
        "\n### MALFIND — EXECUTABLE MEMORY REGIONS ###",
        f"{'PID':<7} {'Name':<22} {'Address':<18} {'Protection'}",
        "-" * 65,
    ]
    for r in executable[:30]:
        lines.append(
            f"{r['pid']:<7} {r['name']:<22} {r['address']:<18} "
            f"{r['protection']}"
        )
    return "\n".join(lines)


def _fmt_processes(processes: list[dict]) -> str:
    if not processes:
        return ""
    lines = [
        "\n### PROCESS LIST (pslist) ###",
        f"Total: {len(processes)}",
        f"{'PID':<7} {'PPID':<7} {'Name':<25} {'Created'}",
        "-" * 65,
    ]
    for p in processes:
        lines.append(
            f"{p['pid']:<7} {p['ppid']:<7} {p['name']:<25} {p['create_time']}"
        )
    return "\n".join(lines)


def _fmt_network(connections: list[dict]) -> str:
    if not connections:
        return ""
    interesting = [
        c for c in connections
        if c["foreign_addr"] not in ("0.0.0.0", "::", "*", "", "-")
    ]
    lines = [
        "\n### NETWORK CONNECTIONS (netscan) ###",
        f"Showing {len(interesting)} non-trivial of {len(connections)} total",
        f"{'PID':<7} {'Owner':<22} {'Proto':<7} {'Port':<8} "
        f"{'Foreign Addr':<22} {'State'}",
        "-" * 72,
    ]
    for c in interesting[:50]:
        lines.append(
            f"{c['pid']:<7} {c['owner']:<22} {c['proto']:<7} "
            f"{c['local_port']:<8} {c['foreign_addr']:<22} {c['state']}"
        )
    return "\n".join(lines)


def _fmt_cmdline(cmdlines: list[dict]) -> str:
    if not cmdlines:
        return ""
    lines = ["\n### COMMAND LINES (cmdline) ###"]
    for e in cmdlines:
        if e["args"] and e["args"] not in ("-", ""):
            lines.append(
                f"  PID {e['pid']:<6} {e['name']:<22}: {e['args'][:300]}"
            )
    return "\n".join(lines)


def _fmt_privs(privs: list[dict]) -> str:
    if not privs:
        return ""
    dangerous = {
        "sedebugprivilege", "seimpersonateprivilege",
        "setcbprivilege", "seloaddriverprivilege",
    }
    expected = {
        "system", "smss.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "lsm.exe",
    }
    interesting = [
        p for p in privs
        if p["priv"].lower() in dangerous
        and p.get("enabled")
        and p["name"].lower() not in expected
    ]
    if not interesting:
        return ""
    lines = ["\n### DANGEROUS PRIVILEGES ON NON-SYSTEM PROCESSES (privs) ###"]
    for p in interesting[:40]:
        lines.append(
            f"  PID {p['pid']:<6} {p['name']:<22}: {p['priv']}"
        )
    return "\n".join(lines)


# ── Main builder ──────────────────────────────────────────────

def build_prompt(
    question: str,
    session: dict,
    detection: dict | None = None,
) -> str:
    """
    Assemble a complete LLaMA 3 prompt from session data.

    Three behavioural modes:

    1. **No data loaded + any question** → Friendly greeting, encourage upload.
    2. **Data loaded + casual question** → Brief friendly reply, nudge toward
       asking forensic questions about the loaded data.
    3. **Data loaded + forensic question** → Full expert analysis with all
       dynamically-generated context, findings, and raw data injected.

    The dynamic context is built entirely from the uploaded CSV data —
    no image-specific details are hardcoded, making Vipersist work
    correctly for any Volatility 3 memory image.
    """
    has_data = len(session) > 0
    casual   = _is_casual(question)

    # ── Mode 1: No data loaded ────────────────────────────────
    if not has_data:
        parts = [SYSTEM_PROMPT]
        parts.append(
            "\n### CONTEXT ###\n"
            "No forensic data has been uploaded yet. "
            "The analyst has not provided any Volatility CSV files.\n"
        )
        parts.append(f"\n### USER MESSAGE ###\n{question}")
        parts.append(
            "\nRespond conversationally in 1-3 sentences. "
            "If the user greeted you, greet them back warmly. "
            "Always let them know they can upload Volatility 3 CSV files "
            "(pslist, netscan, cmdline, dlllist, malfind, handles, privs, envars) "
            "to begin forensic analysis. "
            "Do NOT make up any forensic findings — no data is loaded yet. "
            "Keep it short and friendly."
        )
        parts.append(SYSTEM_FOOTER)
        return "\n".join(p for p in parts if p)

    # ── Mode 2: Data loaded + casual question ─────────────────
    if casual:
        plugin_list   = ", ".join(session.keys())
        finding_count = len(detection.get("findings", [])) if detection else 0
        parts = [SYSTEM_PROMPT]
        parts.append(
            f"\n### CONTEXT ###\n"
            f"Forensic data IS loaded. Plugins: {plugin_list}. "
            f"Detection engine found {finding_count} anomalies.\n"
        )
        parts.append(f"\n### USER MESSAGE ###\n{question}")
        parts.append(
            "\nRespond conversationally in 2-4 sentences. "
            "Acknowledge the user's message warmly. "
            "Then briefly mention what data is loaded and how many "
            "anomalies were detected. Suggest they ask a specific "
            "forensic question such as: "
            "'What happened on this machine?', "
            "'Which processes are injected?', "
            "'Show me the attack narrative', or "
            "'What is the most critical finding?'. "
            "Keep it short, friendly, and helpful. "
            "Do NOT write a full forensic report for a casual greeting."
        )
        parts.append(SYSTEM_FOOTER)
        return "\n".join(p for p in parts if p)

    # ── Mode 3: Data loaded + forensic question ───────────────
    parts: list[str] = [SYSTEM_PROMPT]

    # 1. Dynamic forensic context — built from uploaded data only
    parts.append(_build_dynamic_context(session, detection))

    # 2. Automated detection findings
    parts.append(_fmt_findings(detection))

    # 3. Raw plugin data for cross-reference
    # Row caps keep the prompt within LLaMA 3's context window.
    # The detection engine already ran on ALL rows — no findings
    # are lost by capping here.  We only cap what the LLM reads.
    # handles and dlllist are intentionally excluded — they are
    # too large to be useful in the narrative prompt and their
    # relevant signals are already captured by the detection engine.
    parts.append(_fmt_malfind(session.get("malfind", [])[:50]))
    parts.append(_fmt_processes(session.get("pslist", [])[:80]))
    parts.append(_fmt_network(session.get("netscan", [])[:60]))
    parts.append(_fmt_cmdline(session.get("cmdline", [])[:50]))
    parts.append(_fmt_privs(session.get("privs",    [])))

    # 4. Session metadata
    plugins_loaded = ", ".join(session.keys())
    process_count  = len(session.get("pslist", []))
    parts.append(
        f"\n### SESSION ###\n"
        f"Plugins loaded: {plugins_loaded}  |  "
        f"Total processes: {process_count}"
    )

    # 5. The question with quality instructions
    parts.append("\n### ANALYST QUESTION ###")
    parts.append(question)
    parts.append(
        f"\nIMPORTANT: The analyst asked a specific question: '{question}'\n"
        "You MUST directly answer THIS specific question first before anything else. "
        "Do NOT just summarise the data — answer exactly what was asked. "
        "Use ONLY the DYNAMIC FORENSIC CONTEXT and FINDINGS above as evidence. "
        "Do NOT reference any process names, PIDs, usernames, or file "
        "paths that are not explicitly present in the data above. "
        "Be definitive — state what IS happening, not what might be. "
        "Lead with the most critical findings relevant to the question asked. "
        "Build a coherent answer connecting the evidence to the specific question. "
        "Reference specific PIDs throughout. "
        "Do NOT suggest running tools or commands. "
        "Do NOT end with generic security recommendations."
    )
    parts.append(SYSTEM_FOOTER)

    return "\n".join(p for p in parts if p)