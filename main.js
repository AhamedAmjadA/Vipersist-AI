// ============================================================
// main.js — Vipersist Frontend Controller
// Handles file upload, detection display, chat, process tree,
// attack timeline, risk dashboard, and export functions.
//
// Author: Simon | COMP3000 | University of Plymouth
// ============================================================
"use strict";

const API = window.location.origin;

// ── State ────────────────────────────────────────────────
let allData           = {};
let currentProcesses  = [];
let flaggedPids       = new Set();
let currentDetection  = null;

// ── DOM refs ─────────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const dropZone     = $("#dropZone");
const fileInput    = $("#fileInput");
const chatBox      = $("#chatBox");
const userInput    = $("#userInput");
const sendBtn      = $("#sendBtn");

// ============================================================
// 1. FILE UPLOAD
// ============================================================

dropZone.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", (e) => uploadFiles(e.target.files));

dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("drag-over");
});
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("drag-over");
  if (e.dataTransfer.files.length > 0) uploadFiles(e.dataTransfer.files);
});

async function uploadFiles(files) {
  if (!files || files.length === 0) return;

  const status = $("#uploadStatus");
  status.textContent = `Uploading ${files.length} file(s)…`;
  status.className = "loading";

  const formData = new FormData();
  for (const file of files) formData.append("files", file);

  try {
    const resp = await fetch(API + "/api/upload", { method: "POST", body: formData });
    const data = await resp.json();

    if (data.error) {
      status.textContent = data.error;
      status.className = "error";
      return;
    }

    // Store parsed data
    data.uploaded.forEach((u) => { allData[u.plugin] = u.data; });
    if (data.processes && data.processes.length > 0) currentProcesses = data.processes;

    // Build flagged PID set
    flaggedPids = new Set();
    if (data.detection) {
      currentDetection = data.detection;
      data.detection.findings.forEach((f) => {
        const matches = f.title.match(/PID\s+(\d+)/g);
        if (matches) matches.forEach((m) => flaggedPids.add(parseInt(m.replace(/PID\s+/, ""))));
      });
    }

    // Update all UI sections
    status.textContent = `Loaded ${data.uploaded.length} plugin(s) successfully.`;
    status.className = "success";
    if (data.errors && data.errors.length > 0) {
      status.textContent += ` Warnings: ${data.errors.join("; ")}`;
    }

    showUploadList(data.uploaded);
    updatePluginBadges(data.plugins_loaded);
    showDataCard(data.uploaded);
    enableExports();

    if (data.detection) {
      showThreatMeter(data.detection);
      showFindings(data.detection);
    }

    if (currentProcesses.length > 0) {
      renderProcessTree(currentProcesses, flaggedPids);
      $("#treeHint").style.display = "none";
    }

    if (data.detection && data.detection.findings.length > 0) {
      renderTimeline(data.detection.findings);
      $("#timelineHint").style.display = "none";
      renderDashboard(data.detection, data.plugins_loaded);
      $("#dashboardHint").style.display = "none";
    }

    // Chat notification
    const anomalyCount = data.detection ? data.detection.findings.length : 0;
    const pluginNames = data.uploaded.map((u) => u.plugin).join(", ");
    const totalRecords = data.uploaded.reduce((s, u) => s + u.record_count, 0);
    addChatMessage("ai",
      `Loaded: ${pluginNames}. Total records: ${totalRecords}. ` +
      (anomalyCount > 0
        ? `⚠ ${anomalyCount} anomalies detected across all plugins.`
        : "No anomalies detected.")
    );

  } catch (err) {
    status.textContent = "Error: Cannot connect to backend. Is it running?";
    status.className = "error";
  }
}

function showUploadList(uploaded) {
  const list = $("#uploadList");
  list.innerHTML = "";
  uploaded.forEach((u) => {
    const row = document.createElement("div");
    row.className = "upload-row";
    row.innerHTML = `
      <span class="plugin-tag">${u.plugin}</span>
      <span class="upload-filename">${u.filename}</span>
      <span class="upload-count">${u.record_count} records</span>`;
    list.appendChild(row);
  });
}

function updatePluginBadges(plugins) {
  const container = $("#pluginBadges");
  container.innerHTML = "";
  plugins.forEach((p) => {
    const b = document.createElement("span");
    b.className = "plugin-badge";
    b.textContent = p;
    container.appendChild(b);
  });
}

function enableExports() {
  ["exportJsonBtn", "exportCsvBtn", "exportHtmlBtn"].forEach((id) => {
    document.getElementById(id).disabled = false;
  });
}

// ============================================================
// 2. THREAT METER
// ============================================================

function showThreatMeter(detection) {
  const card = $("#threatCard");
  card.style.display = "block";

  const { summary } = detection;
  const crit = summary.CRITICAL || 0;
  const high = summary.HIGH || 0;
  const med  = summary.MEDIUM || 0;
  const low  = summary.LOW || 0;

  // Score: weighted sum (max ~100 for severe compromise)
  const score = Math.min(100, crit * 25 + high * 10 + med * 4 + low * 1);

  // Determine level
  let level, color;
  if (score >= 70) { level = "CRITICAL"; color = "#ef4444"; }
  else if (score >= 40) { level = "HIGH"; color = "#f97316"; }
  else if (score >= 15) { level = "MEDIUM"; color = "#eab308"; }
  else if (score > 0) { level = "LOW"; color = "#3b82f6"; }
  else { level = "CLEAN"; color = "#22c55e"; }

  // Animate gauge
  const arc = document.getElementById("gaugeArc");
  const needle = document.getElementById("gaugeNeedle");
  const totalLen = 251.2;
  const offset = totalLen - (totalLen * score / 100);
  const needleAngle = -90 + (180 * score / 100);

  setTimeout(() => {
    arc.style.transition = "stroke-dashoffset 1.2s ease-out";
    arc.style.strokeDashoffset = offset;
    needle.style.transition = "transform 1.2s ease-out";
    needle.setAttribute("transform", `rotate(${needleAngle}, 100, 100)`);
  }, 100);

  $("#threatLevel").textContent = level;
  $("#threatLevel").style.color = color;
  $("#threatScore").textContent = `${score} / 100`;

  // Breakdown
  const bd = $("#threatBreakdown");
  bd.innerHTML = "";
  const items = [
    { label: "Critical", count: crit, color: "#ef4444" },
    { label: "High", count: high, color: "#f97316" },
    { label: "Medium", count: med, color: "#eab308" },
    { label: "Low", count: low, color: "#3b82f6" },
  ];
  items.forEach((item) => {
    if (item.count > 0) {
      const el = document.createElement("div");
      el.className = "threat-stat";
      el.innerHTML = `<span class="threat-dot" style="background:${item.color}"></span>${item.count} ${item.label}`;
      bd.appendChild(el);
    }
  });
}

// ============================================================
// 3. FINDINGS
// ============================================================

function showFindings(detection) {
  const { findings, summary } = detection;
  $("#findingsCard").style.display = "block";

  const summaryDiv = $("#findingsSummary");
  summaryDiv.innerHTML = "";
  ["CRITICAL", "HIGH", "MEDIUM", "LOW"].forEach((sev) => {
    const count = summary[sev] || 0;
    if (count > 0) {
      const badge = document.createElement("span");
      badge.className = `badge ${sev}`;
      badge.textContent = `${count} ${sev}`;
      summaryDiv.appendChild(badge);
    }
  });

  const listDiv = $("#findingsList");
  listDiv.innerHTML = "";
  findings.forEach((f) => {
    const item = document.createElement("div");
    item.className = `finding ${f.severity}`;
    let mitreBadge = "";
    if (f.mitre) {
      mitreBadge = `
        <a class="mitre-badge" href="${f.mitre.url}" target="_blank"
           title="${f.mitre.description}">
          <span class="mitre-id">${f.mitre.id}</span>
          <span class="mitre-name">${f.mitre.name}</span>
        </a>`;
    }
    item.innerHTML = `
      <div class="finding-title">${f.title} <span class="rule-tag">[${f.rule}]</span></div>
      <div class="finding-detail">${f.detail}</div>
      ${mitreBadge}`;
    listDiv.appendChild(item);
  });
}

// ============================================================
// 4. DATA TABLE
// ============================================================

const COLUMN_DEFS = {
  pslist:  [{ key: "pid", label: "PID" }, { key: "ppid", label: "PPID" }, { key: "name", label: "Process" }, { key: "create_time", label: "Created" }],
  netscan: [{ key: "pid", label: "PID" }, { key: "owner", label: "Owner" }, { key: "local_port", label: "Port" }, { key: "foreign_addr", label: "Foreign" }, { key: "state", label: "State" }],
  cmdline: [{ key: "pid", label: "PID" }, { key: "name", label: "Process" }, { key: "args", label: "Command Line" }],
  dlllist: [{ key: "pid", label: "PID" }, { key: "name", label: "Process" }, { key: "path", label: "DLL Path" }],
  malfind: [{ key: "pid", label: "PID" }, { key: "name", label: "Process" }, { key: "address", label: "Address" }, { key: "protection", label: "Protection" }],
  handles: [{ key: "pid", label: "PID" }, { key: "name", label: "Process" }, { key: "type", label: "Type" }, { key: "value", label: "Handle Value" }],
  privs:   [{ key: "pid", label: "PID" }, { key: "name", label: "Process" }, { key: "priv", label: "Privilege" }, { key: "enabled", label: "Enabled" }],
  envars:  [{ key: "pid", label: "PID" }, { key: "name", label: "Process" }, { key: "key", label: "Variable" }, { key: "value", label: "Value" }],
};

function showDataCard(uploaded) {
  $("#dataCard").style.display = "block";
  const tabsContainer = $("#pluginTabs");
  tabsContainer.innerHTML = "";
  uploaded.forEach((u, i) => {
    const tab = document.createElement("button");
    tab.className = "plugin-tab" + (i === 0 ? " active" : "");
    tab.textContent = u.plugin;
    tab.addEventListener("click", () => {
      $$(".plugin-tab").forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      renderTable(u.plugin, allData[u.plugin]);
    });
    tabsContainer.appendChild(tab);
  });
  if (uploaded.length > 0) renderTable(uploaded[0].plugin, allData[uploaded[0].plugin]);
}

function renderTable(plugin, data) {
  const thead = $("#dataHead");
  const tbody = $("#dataBody");
  thead.innerHTML = "";
  tbody.innerHTML = "";

  const columns = COLUMN_DEFS[plugin] || Object.keys(data[0] || {}).map((k) => ({ key: k, label: k }));
  const headerRow = document.createElement("tr");
  columns.forEach((col) => {
    const th = document.createElement("th");
    th.textContent = col.label;
    headerRow.appendChild(th);
  });
  thead.appendChild(headerRow);

  (data || []).forEach((row) => {
    const tr = document.createElement("tr");
    if (flaggedPids.has(row.pid)) tr.classList.add("row-flagged");
    columns.forEach((col) => {
      const td = document.createElement("td");
      td.textContent = row[col.key] !== undefined ? row[col.key] : "";
      td.title = String(row[col.key] || "");
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}

// ============================================================
// 5. PROCESS TREE
// ============================================================

function renderProcessTree(processes, flagged) {
  const container = $("#treeContainer");
  container.innerHTML = "";

  const nodeMap = {};
  processes.forEach((p) => { nodeMap[p.pid] = { ...p, children: [] }; });

  const roots = [];
  processes.forEach((p) => {
    const parent = nodeMap[p.ppid];
    if (parent && p.ppid !== p.pid) {
      parent.children.push(nodeMap[p.pid]);
    } else {
      roots.push(nodeMap[p.pid]);
    }
  });

  function buildNode(node, depth) {
    const wrapper = document.createElement("div");
    wrapper.className = "tree-node";
    wrapper.style.marginLeft = `${depth * 18}px`;

    const isFlagged = flagged.has(node.pid);
    const label = document.createElement("div");
    label.className = `tree-label${isFlagged ? " tree-flagged" : ""}`;
    label.innerHTML = `
      <span class="tree-icon">${node.children.length > 0 ? "▾" : "·"}</span>
      <span class="tree-name">${node.name}</span>
      <span class="tree-pid">PID ${node.pid}</span>
      ${isFlagged ? '<span class="tree-alert">flagged</span>' : ""}`;
    wrapper.appendChild(label);

    if (node.children.length > 0) {
      const childWrap = document.createElement("div");
      childWrap.className = "tree-children";
      node.children.forEach((child) => childWrap.appendChild(buildNode(child, depth + 1)));
      wrapper.appendChild(childWrap);
    }
    return wrapper;
  }

  roots.forEach((root) => container.appendChild(buildNode(root, 0)));
}

// ============================================================
// 6. ATTACK TIMELINE
// ============================================================

function renderTimeline(findings) {
  const container = $("#timelineContainer");
  container.innerHTML = "";

  // Sort: CRITICAL first, then HIGH, MEDIUM, LOW
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const sorted = [...findings].sort((a, b) => (order[a.severity] || 4) - (order[b.severity] || 4));

  sorted.forEach((f, i) => {
    const event = document.createElement("div");
    event.className = "timeline-event";
    event.style.animationDelay = `${i * 0.05}s`;

    const mitreTags = f.mitre
      ? `<span class="timeline-tag mitre">${f.mitre.id}</span>`
      : "";

    event.innerHTML = `
      <div class="timeline-marker">
        <div class="timeline-dot ${f.severity}"></div>
        ${i < sorted.length - 1 ? '<div class="timeline-line"></div>' : ""}
      </div>
      <div class="timeline-content">
        <div class="timeline-title">${f.title}</div>
        <div class="timeline-detail">${f.detail}</div>
        <div class="timeline-tags">
          <span class="timeline-tag sev">${f.severity}</span>
          <span class="timeline-tag rule">${f.rule}</span>
          ${mitreTags}
        </div>
      </div>`;
    container.appendChild(event);
  });
}

// ============================================================
// 7. RISK DASHBOARD
// ============================================================

function renderDashboard(detection, pluginsLoaded) {
  const container = $("#dashboardContainer");
  container.innerHTML = "";

  const { findings, summary } = detection;
  const total = findings.length;
  const crit = summary.CRITICAL || 0;
  const high = summary.HIGH || 0;
  const med  = summary.MEDIUM || 0;

  // ── Top stats grid
  const statsGrid = document.createElement("div");
  statsGrid.className = "dashboard-grid";

  const score = Math.min(100, crit * 25 + high * 10 + med * 4 + (summary.LOW || 0));
  const stats = [
    { value: total, label: "Total Findings", color: "var(--text)" },
    { value: crit, label: "Critical", color: "var(--red)" },
    { value: high, label: "High", color: "var(--orange)" },
    { value: score + "%", label: "Threat Score", color: score >= 70 ? "var(--red)" : score >= 40 ? "var(--orange)" : "var(--yellow)" },
    { value: pluginsLoaded.length, label: "Plugins Loaded", color: "var(--accent)" },
    { value: new Set(findings.map((f) => f.rule)).size, label: "Rules Triggered", color: "var(--cyan)" },
  ];

  stats.forEach((s) => {
    const card = document.createElement("div");
    card.className = "dash-card";
    card.innerHTML = `
      <div class="dash-value" style="color:${s.color}">${s.value}</div>
      <div class="dash-label">${s.label}</div>`;
    statsGrid.appendChild(card);
  });
  container.appendChild(statsGrid);

  // ── Severity distribution bars
  const sevTitle = document.createElement("div");
  sevTitle.className = "dash-section-title";
  sevTitle.textContent = "Severity Distribution";
  container.appendChild(sevTitle);

  const sevItems = [
    { label: "CRITICAL", count: crit, color: "var(--red)", max: total },
    { label: "HIGH", count: high, color: "var(--orange)", max: total },
    { label: "MEDIUM", count: med, color: "var(--yellow)", max: total },
    { label: "LOW", count: summary.LOW || 0, color: "var(--accent)", max: total },
  ];

  sevItems.forEach((s) => {
    const wrap = document.createElement("div");
    wrap.className = "severity-bar-wrap";
    const pct = total > 0 ? (s.count / total * 100) : 0;
    wrap.innerHTML = `
      <span class="severity-bar-label">${s.label}</span>
      <div class="severity-bar">
        <div class="severity-bar-fill" style="width:${pct}%;background:${s.color}"></div>
      </div>
      <span class="severity-bar-count">${s.count}</span>`;
    container.appendChild(wrap);
  });

  // ── MITRE ATT&CK coverage
  const mitreTitle = document.createElement("div");
  mitreTitle.className = "dash-section-title";
  mitreTitle.textContent = "MITRE ATT&CK Coverage";
  container.appendChild(mitreTitle);

  const mitreGrid = document.createElement("div");
  mitreGrid.className = "mitre-grid";

  const techniques = new Map();
  findings.forEach((f) => {
    if (f.mitre && !techniques.has(f.mitre.id)) {
      techniques.set(f.mitre.id, f.mitre);
    }
  });

  techniques.forEach((tech) => {
    const chip = document.createElement("a");
    chip.className = "mitre-chip";
    chip.href = tech.url;
    chip.target = "_blank";
    chip.title = tech.description;
    chip.innerHTML = `${tech.id} ${tech.name}${tech.tactic ? `<span class="chip-tactic">${tech.tactic}</span>` : ""}`;
    mitreGrid.appendChild(chip);
  });
  container.appendChild(mitreGrid);

  // ── Rules triggered
  const rulesTitle = document.createElement("div");
  rulesTitle.className = "dash-section-title";
  rulesTitle.textContent = "Detection Rules Triggered";
  container.appendChild(rulesTitle);

  const ruleCount = {};
  findings.forEach((f) => { ruleCount[f.rule] = (ruleCount[f.rule] || 0) + 1; });

  const rulesGrid = document.createElement("div");
  rulesGrid.className = "dashboard-grid";
  Object.entries(ruleCount)
    .sort((a, b) => b[1] - a[1])
    .forEach(([rule, count]) => {
      const card = document.createElement("div");
      card.className = "dash-card";
      card.innerHTML = `
        <div class="dash-value" style="color:var(--accent);font-size:20px">${rule}</div>
        <div class="dash-label">${count} finding${count > 1 ? "s" : ""}</div>`;
      rulesGrid.appendChild(card);
    });
  container.appendChild(rulesGrid);
}

// ============================================================
// 8. CHAT
// ============================================================

/**
 * Convert basic markdown from LLM output into HTML for display.
 * Handles: **bold**, *italic*, `code`, headings (##), bullet lists,
 * and paragraph breaks.
 */
function formatMarkdown(text) {
  if (!text) return "";
  let html = text
    // Escape HTML entities first (prevent XSS)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    // Headings: ## text → <strong class="chat-heading">text</strong>
    .replace(/^#{1,3}\s+(.+)$/gm, '<strong class="chat-heading">$1</strong>')
    // Bold: **text** → <strong>text</strong>
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    // Italic: *text* → <em>text</em>
    .replace(/(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)/g, "<em>$1</em>")
    // Inline code: `text` → <code>text</code>
    .replace(/`([^`]+)`/g, '<code class="chat-code">$1</code>')
    // Bullet lists: - item → styled div
    .replace(/^[\-\•]\s+(.+)$/gm, '<div class="chat-bullet">$1</div>')
    // Numbered lists: 1. item → styled div
    .replace(/^\d+\.\s+(.+)$/gm, '<div class="chat-bullet">$1</div>')
    // Double newlines → paragraph break
    .replace(/\n\n/g, '<div class="chat-break"></div>')
    // Single newlines → <br>
    .replace(/\n/g, "<br>");
  return html;
}

sendBtn.addEventListener("click", sendChat);
userInput.addEventListener("keydown", (e) => { if (e.key === "Enter") sendChat(); });

async function sendChat() {
  const text = userInput.value.trim();
  if (!text) return;
  addChatMessage("user", text);
  userInput.value = "";
  userInput.focus();

  const loadingSpan = addChatMessage("ai", "Analysing…");
  loadingSpan.classList.add("loading");

  try {
    const res = await fetch(API + "/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input: text }),
    });
    const data = await res.json();
    loadingSpan.classList.remove("loading");
    // Use innerHTML with markdown formatting for AI responses
    loadingSpan.innerHTML = formatMarkdown(data.result || data.error);
  } catch {
    loadingSpan.classList.remove("loading");
    loadingSpan.innerHTML = "Error: Cannot connect to backend.";
  }
  chatBox.scrollTop = chatBox.scrollHeight;
}

function addChatMessage(role, text) {
  const msg = document.createElement("div");
  msg.className = `message ${role}`;

  const avatarSvg = role === "user"
    ? `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`
    : `<svg width="14" height="14" viewBox="0 0 28 28" fill="none"><path d="M14 2L2 8v12l12 6 12-6V8L14 2z" stroke="#3b82f6" stroke-width="1.5" fill="none"/><circle cx="14" cy="14" r="2" fill="#3b82f6"/></svg>`;

  const label = role === "user" ? "You" : "Vipersist";
  // For AI role, format markdown; for user, use plain text (escaped)
  const rendered = role === "ai" ? formatMarkdown(text) : text.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");

  msg.innerHTML = `
    <div class="msg-avatar">${avatarSvg}</div>
    <div class="msg-content">
      <strong>${label}</strong>
      <span class="msg-text">${rendered}</span>
    </div>`;
  chatBox.appendChild(msg);
  chatBox.scrollTop = chatBox.scrollHeight;
  return msg.querySelector(".msg-content .msg-text");
}

// ============================================================
// 9. TAB TOGGLE
// ============================================================

const panels = {
  chat:      { panel: "chatPanel",      btn: "modeChat" },
  tree:      { panel: "treePanel",      btn: "modeTree" },
  timeline:  { panel: "timelinePanel",  btn: "modeTimeline" },
  dashboard: { panel: "dashboardPanel", btn: "modeDashboard" },
};

function switchPanel(name) {
  Object.values(panels).forEach((p) => {
    document.getElementById(p.panel).style.display = "none";
    document.getElementById(p.btn).classList.remove("active");
  });
  const target = panels[name];
  document.getElementById(target.panel).style.display = name === "chat" ? "flex" : "block";
  document.getElementById(target.btn).classList.add("active");

  // Re-render tree on switch (in case data changed)
  if (name === "tree" && currentProcesses.length > 0) {
    renderProcessTree(currentProcesses, flaggedPids);
    $("#treeHint").style.display = "none";
  }
}

$("#modeChat").addEventListener("click", () => switchPanel("chat"));
$("#modeTree").addEventListener("click", () => switchPanel("tree"));
$("#modeTimeline").addEventListener("click", () => switchPanel("timeline"));
$("#modeDashboard").addEventListener("click", () => switchPanel("dashboard"));

// ============================================================
// 10. EXPORT
// ============================================================

function downloadFromUrl(url, fallbackName) {
  const a = document.createElement("a");
  a.href = url;
  a.download = fallbackName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

$("#exportJsonBtn").addEventListener("click", () => downloadFromUrl(API + "/api/export/json", "vipersist_export.json"));
$("#exportCsvBtn").addEventListener("click", () => downloadFromUrl(API + "/api/export/csv", "vipersist_findings.csv"));
$("#exportHtmlBtn").addEventListener("click", () => downloadFromUrl(API + "/api/export/html", "vipersist_report.html"));

// ============================================================
// 11. RESET
// ============================================================

$("#resetBtn").addEventListener("click", async () => {
  if (!confirm("Clear all uploaded data and analysis?")) return;
  await fetch(API + "/api/reset", { method: "POST" });

  allData = {};
  currentProcesses = [];
  flaggedPids = new Set();
  currentDetection = null;

  // Hide cards
  ["findingsCard", "dataCard", "threatCard"].forEach((id) => {
    document.getElementById(id).style.display = "none";
  });

  // Clear content
  $("#uploadStatus").textContent = "";
  $("#uploadList").innerHTML = "";
  $("#pluginBadges").innerHTML = "";
  $("#treeContainer").innerHTML = "";
  $("#timelineContainer").innerHTML = "";
  $("#dashboardContainer").innerHTML = "";
  $("#treeHint").style.display = "block";
  $("#timelineHint").style.display = "block";
  $("#dashboardHint").style.display = "block";

  // Disable exports
  ["exportJsonBtn", "exportCsvBtn", "exportHtmlBtn"].forEach((id) => {
    document.getElementById(id).disabled = true;
  });

  // Reset gauge
  const arc = document.getElementById("gaugeArc");
  const needle = document.getElementById("gaugeNeedle");
  if (arc) { arc.style.strokeDashoffset = "251.2"; }
  if (needle) { needle.setAttribute("transform", "rotate(-90, 100, 100)"); }

  // Reset chat
  chatBox.innerHTML = "";
  addChatMessage("ai", "Session cleared. Upload new files to begin analysis.");

  switchPanel("chat");
});