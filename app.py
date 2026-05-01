# ============================================================
# app.py — Vipersist Flask Server
# AI-Assisted Memory Forensics Triage Tool
# Architecture: Flask + Ollama (LLaMA 3) + Custom Detection Engine
# Author: Simon | COMP3000 Computing Project | University of Plymouth
# ============================================================
"""
Core web server for Vipersist.  Exposes a REST API that the single-page
frontend consumes.  Design decisions:

* Thread-safe in-memory session store (dict guarded by a threading lock)
  instead of a global mutable — safe under Flask's dev server and Gunicorn.
* Structured JSON logging so every request/response is auditable.
* Configurable via environment variables (MODEL_NAME, OLLAMA_URL, PORT).
* Health-check endpoint (/api/health) for monitoring.
* Export endpoints for JSON, CSV, and standalone HTML report generation.
"""

from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
import csv
import datetime
import io
import json
import logging
import os
import threading
import requests
import time

from parsers import detect_plugin, parse_file
from anomaly_detector import run_detection
from prompt_builder import build_prompt

# ── Configuration ─────────────────────────────────────────────
class Config:
    """Centralised configuration — reads from env vars with sane defaults."""
    OLLAMA_URL   = os.getenv("OLLAMA_URL",   "http://localhost:11434/api/generate")
    MODEL_NAME   = os.getenv("MODEL_NAME",   "llama3")
    PORT         = int(os.getenv("PORT",      "5000"))
    TIMEOUT      = int(os.getenv("TIMEOUT",   "600"))   # 10 min — generous for CPU inference
    TEMPERATURE  = float(os.getenv("TEMPERATURE", "0.2"))
    TOP_P        = float(os.getenv("TOP_P",       "0.9"))
    REPEAT_PEN   = float(os.getenv("REPEAT_PEN",  "1.1"))
    NUM_PREDICT  = int(os.getenv("NUM_PREDICT",   "512"))  # reduced: faster on CPU

    @classmethod
    def ollama_options(cls):
        return {
            "temperature":    cls.TEMPERATURE,
            "top_p":          cls.TOP_P,
            "repeat_penalty": cls.REPEAT_PEN,
            "num_predict":    cls.NUM_PREDICT,
        }

# ── Logging ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("vipersist")

# ── Thread-safe session store ─────────────────────────────────
class SessionStore:
    """Guards all mutable analysis state behind a lock."""

    def __init__(self):
        self._lock      = threading.Lock()
        self._plugins   = {}                       # plugin_name → [records]
        self._detection = {"findings": [], "summary": {}}
        self._history   = []                       # chat history

    # -- plugin data --
    def set_plugin(self, name, records):
        with self._lock:
            self._plugins[name] = records

    def get_plugin(self, name, default=None):
        with self._lock:
            return self._plugins.get(name, default)

    def all_plugins(self):
        with self._lock:
            return dict(self._plugins)

    def plugin_names(self):
        with self._lock:
            return list(self._plugins.keys())

    def plugin_counts(self):
        with self._lock:
            return {k: len(v) for k, v in self._plugins.items()}

    # -- detection --
    def set_detection(self, det):
        with self._lock:
            self._detection = det

    def get_detection(self):
        with self._lock:
            return self._detection

    # -- chat history --
    def add_chat(self, role, text):
        with self._lock:
            self._history.append({
                "role": role, "text": text,
                "ts": datetime.datetime.utcnow().isoformat() + "Z",
            })

    def get_history(self):
        with self._lock:
            return list(self._history)

    # -- reset --
    def clear(self):
        with self._lock:
            self._plugins.clear()
            self._detection = {"findings": [], "summary": {}}
            self._history.clear()

store = SessionStore()

# ── Flask app ─────────────────────────────────────────────────
app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app)

# ── LLM helper ────────────────────────────────────────────────
def ask_ollama(prompt: str) -> str:
    """Send a prompt to Ollama and return the model's response string."""
    t0 = time.time()
    try:
        resp = requests.post(Config.OLLAMA_URL, json={
            "model":   Config.MODEL_NAME,
            "prompt":  prompt,
            "stream":  False,
            "options": Config.ollama_options(),
        }, timeout=Config.TIMEOUT)
        resp.raise_for_status()
        answer = resp.json().get("response", "").strip()
        log.info("Ollama responded in %.1fs (%d chars)", time.time() - t0, len(answer))
        return answer
    except requests.exceptions.ConnectionError:
        log.error("Ollama unreachable at %s", Config.OLLAMA_URL)
        return ("Error: Ollama is not running. Start it with: ollama serve")
    except requests.exceptions.Timeout:
        log.error("Ollama timed out after %ds", Config.TIMEOUT)
        return "Error: LLM request timed out. The memory image may be too large."
    except Exception as exc:
        log.exception("Ollama error")
        return f"Error: {exc}"

# ── Routes: static ────────────────────────────────────────────
@app.route("/")
def home():
    """Serve the single-page frontend."""
    return send_from_directory("static", "index.html")

# ── Routes: upload & analysis ─────────────────────────────────
@app.route("/api/upload", methods=["POST"])
def upload():
    """
    Accept one or more Volatility 3 CSV files, parse them, run the
    detection engine, and return structured results.
    """
    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "No files provided"}), 400

    uploaded, errors = [], []

    for f in files:
        try:
            content = f.read().decode("utf-8", errors="replace")
        except Exception as exc:
            errors.append(f"Could not read {f.filename}: {exc}")
            continue

        plugin = detect_plugin(f.filename)
        if plugin is None:
            errors.append(f"Unknown plugin type: {f.filename}")
            continue

        parsed = parse_file(plugin, content)
        if not parsed:
            errors.append(f"No data parsed from: {f.filename}")
            continue

        store.set_plugin(plugin, parsed)
        uploaded.append({
            "plugin":       plugin,
            "filename":     f.filename,
            "record_count": len(parsed),
            "data":         parsed[:200],
        })
        log.info("Parsed %s → %s (%d records)", f.filename, plugin, len(parsed))

    if not uploaded:
        return jsonify({"error": "; ".join(errors) or "No valid files parsed"}), 400

    # Run detection engine across all loaded plugins
    detection = run_detection(store.all_plugins())
    store.set_detection(detection)

    processes = store.get_plugin("pslist", [])
    log.info(
        "Detection complete: %s",
        {k: v for k, v in detection["summary"].items() if v > 0},
    )

    return jsonify({
        "success":        True,
        "uploaded":       uploaded,
        "errors":         errors,
        "detection":      detection,
        "processes":      processes,
        "plugins_loaded": store.plugin_names(),
    })

# ── Routes: chat ──────────────────────────────────────────────
@app.route("/api/chat", methods=["POST"])
def chat():
    """Forward a forensic question to the LLM with full session context."""
    data     = request.get_json(silent=True) or {}
    question = data.get("input", "").strip()
    if not question:
        return jsonify({"error": "Empty question"}), 400
    if len(question) > 2000:
        return jsonify({"error": "Question too long (max 2 000 chars)"}), 400

    store.add_chat("user", question)

    prompt = build_prompt(
        question=question,
        session=store.all_plugins(),
        detection=store.get_detection(),
    )

    reply = ask_ollama(prompt)
    store.add_chat("assistant", reply)

    return jsonify({"result": reply})

# ── Routes: session ───────────────────────────────────────────
@app.route("/api/session", methods=["GET"])
def get_session():
    """Return current plugin inventory and record counts."""
    return jsonify({
        "plugins_loaded": store.plugin_names(),
        "counts":         store.plugin_counts(),
    })

@app.route("/api/reset", methods=["POST"])
def reset():
    """Clear all session data and detection results."""
    store.clear()
    log.info("Session reset")
    return jsonify({"success": True})

# ── Routes: health ────────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def health():
    """Health-check endpoint for monitoring / CI."""
    ollama_ok = False
    try:
        r = requests.get(
            Config.OLLAMA_URL.replace("/api/generate", "/api/tags"),
            timeout=5,
        )
        ollama_ok = r.status_code == 200
    except Exception:
        pass

    return jsonify({
        "status":       "ok",
        "model":        Config.MODEL_NAME,
        "ollama_alive": ollama_ok,
        "plugins":      store.plugin_names(),
        "timestamp":    datetime.datetime.utcnow().isoformat() + "Z",
    })

# ── Routes: export ────────────────────────────────────────────
@app.route("/api/export/json", methods=["GET"])
def export_json():
    """Export full analysis session as JSON."""
    payload = {
        "exported_at": datetime.datetime.utcnow().isoformat() + "Z",
        "tool":        "Vipersist v1.0",
        "model":       Config.MODEL_NAME,
        "plugins":     store.all_plugins(),
        "detection":   store.get_detection(),
        "chat_history": store.get_history(),
    }
    return Response(
        json.dumps(payload, indent=2, default=str),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=vipersist_export.json"},
    )

@app.route("/api/export/csv", methods=["GET"])
def export_csv():
    """Export detection findings as a CSV file."""
    detection = store.get_detection()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Rule", "Severity", "Title", "Detail", "MITRE ID", "MITRE Name"])

    for f in detection.get("findings", []):
        mitre = f.get("mitre", {})
        writer.writerow([
            f.get("rule", ""),
            f.get("severity", ""),
            f.get("title", ""),
            f.get("detail", ""),
            mitre.get("id", ""),
            mitre.get("name", ""),
        ])

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=vipersist_findings.csv"},
    )

@app.route("/api/export/html", methods=["GET"])
def export_html():
    """Export a standalone HTML forensic report."""
    detection = store.get_detection()
    plugins   = store.all_plugins()
    history   = store.get_history()
    now       = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    findings_html = ""
    for f in detection.get("findings", []):
        mitre = f.get("mitre", {})
        badge = ""
        if mitre:
            badge = (
                f'<span style="background:#1a3a5c;color:#58a6ff;padding:2px 8px;'
                f'border-radius:4px;font-size:11px;margin-left:8px;">'
                f'{mitre.get("id","")} — {mitre.get("name","")}</span>'
            )
        sev_colors = {
            "CRITICAL": "#f85149", "HIGH": "#db6d28",
            "MEDIUM": "#d29922", "LOW": "#58a6ff"
        }
        color = sev_colors.get(f["severity"], "#8b949e")
        findings_html += f"""
        <div style="border-left:4px solid {color};padding:10px 16px;
                     margin-bottom:10px;background:#161b22;border-radius:0 6px 6px 0;">
            <div style="font-weight:700;color:{color};margin-bottom:4px;">
                [{f['severity']}] {f['rule']} — {f['title']}{badge}
            </div>
            <div style="color:#8b949e;font-size:13px;">{f['detail']}</div>
        </div>"""

    chat_html = ""
    for msg in history:
        align = "right" if msg["role"] == "user" else "left"
        bg    = "#1f3a5f" if msg["role"] == "user" else "#21262d"
        label = "Analyst" if msg["role"] == "user" else "Vipersist AI"
        chat_html += f"""
        <div style="text-align:{align};margin-bottom:10px;">
            <div style="display:inline-block;background:{bg};padding:10px 14px;
                        border-radius:8px;max-width:80%;text-align:left;">
                <strong>{label}:</strong> {msg['text'][:2000]}
            </div>
        </div>"""

    summary = detection.get("summary", {})

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Vipersist Forensic Report — {now}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, "Segoe UI", sans-serif;
         background: #0d1117; color: #e6edf3; padding: 40px; line-height: 1.6; }}
  h1 {{ font-size: 24px; margin-bottom: 8px; }}
  h2 {{ font-size: 18px; margin: 24px 0 12px; border-bottom: 1px solid #30363d;
       padding-bottom: 6px; }}
  .meta {{ color: #8b949e; font-size: 13px; margin-bottom: 24px; }}
  .summary-bar {{ display: flex; gap: 12px; margin-bottom: 20px; }}
  .summary-bar span {{ padding: 4px 14px; border-radius: 16px; font-weight: 700;
                       font-size: 13px; }}
  .crit {{ background: #3d1214; color: #f85149; }}
  .high {{ background: #3d2010; color: #db6d28; }}
  .med  {{ background: #3d2e00; color: #d29922; }}
  .low  {{ background: #12243d; color: #58a6ff; }}
  pre {{ background: #161b22; padding: 12px; border-radius: 6px; overflow-x: auto;
        font-size: 12px; color: #8b949e; }}
</style>
</head>
<body>
<h1>Vipersist — Forensic Analysis Report</h1>
<div class="meta">Generated: {now} &nbsp;|&nbsp; Model: {Config.MODEL_NAME}
  &nbsp;|&nbsp; Plugins: {', '.join(plugins.keys()) or 'none'}</div>

<h2>Threat Summary</h2>
<div class="summary-bar">
  <span class="crit">CRITICAL: {summary.get('CRITICAL',0)}</span>
  <span class="high">HIGH: {summary.get('HIGH',0)}</span>
  <span class="med">MEDIUM: {summary.get('MEDIUM',0)}</span>
  <span class="low">LOW: {summary.get('LOW',0)}</span>
</div>

<h2>Detection Findings ({len(detection.get('findings',[]))})</h2>
{findings_html or '<p style="color:#8b949e;">No findings.</p>'}

<h2>AI Analysis Chat Log</h2>
{chat_html or '<p style="color:#8b949e;">No chat messages.</p>'}

<h2>Raw Plugin Counts</h2>
<pre>{json.dumps({k: len(v) for k, v in plugins.items()}, indent=2)}</pre>

<hr style="border-color:#30363d;margin:30px 0;">
<p style="color:#8b949e;font-size:11px;text-align:center;">
  Vipersist v1.0 — AI-Assisted Memory Forensics Triage — University of Plymouth COMP3000
</p>
</body>
</html>"""

    return Response(
        html,
        mimetype="text/html",
        headers={"Content-Disposition": "attachment; filename=vipersist_report.html"},
    )

# ── Error handlers ────────────────────────────────────────────
@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def server_error(_):
    log.exception("Internal server error")
    return jsonify({"error": "Internal server error"}), 500

# ── Entrypoint ────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n╔══════════════════════════════════════════════╗")
    print("║   Vipersist — Memory Forensics Triage        ║")
    print("╚══════════════════════════════════════════════╝")
    print(f"  Model    : {Config.MODEL_NAME}")
    print(f"  Ollama   : {Config.OLLAMA_URL}")
    print(f"  Server   : http://127.0.0.1:{Config.PORT}")
    print("  Ensure Ollama is running: ollama serve\n")
    app.run(debug=True, port=Config.PORT)