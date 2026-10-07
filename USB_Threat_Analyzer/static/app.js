/**
 * USB Threat Analyzer - frontend controller.
 * Polls the Flask JSON API and drives every live element of the
 * single-page Glassmorphism dashboard: USB status, per-level counters,
 * the results table, quarantine actions, sandbox launches, and history.
 */

const POLL_INTERVAL_MS = 1500;
let currentScanId = null;
let currentSandboxItemId = null;

function $(id) { return document.getElementById(id); }

function showToast(message, isError = false) {
  const toast = $("toast");
  toast.textContent = message;
  toast.style.color = isError ? "#ff5470" : "";
  toast.classList.remove("hidden");
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => toast.classList.add("hidden"), 3500);
}

function fmtBytes(n) {
  if (!n && n !== 0) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(1)} ${units[i]}`;
}

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function levelForScore(score) {
  return score >= 80 ? "Critical" : score >= 60 ? "High" : score >= 30 ? "Medium" : "Low";
}

// ---------------------------------------------------------------------
// "Why was this flagged?" panels (shared by Scan Results and Quarantine)
// ---------------------------------------------------------------------
const CATEGORY_CLASS = {
  "Signature match": "sig", "Heuristic": "heur", "Behavior indicator": "beh", "Note": "note",
};

/**
 * Builds the explanation panel for one file. `item` needs risk_score and, ideally,
 * explanations[] (structured) - rows saved by older versions only have reasons[].
 * Every string is escaped: names inside evidence come from the scanned drive.
 */
function renderWhyPanel(item) {
  const score = item.risk_score ?? 0;
  const level = item.risk_level || levelForScore(score);
  const ex = item.explanations || [];
  const scored = ex.filter(e => e.points > 0);

  let intro;
  if (scored.length) {
    const total = scored.reduce((n, e) => n + e.points, 0);
    intro = `Rated <strong>${escapeHtml(level)}</strong> (${score}/100) because ${scored.length} `
      + `indicator${scored.length === 1 ? "" : "s"} matched`
      + (total > 100 ? " (score is capped at 100)" : "")
      + `. These are risk indicators, not a confirmed malware verdict.`;
  } else if (ex.length || (item.reasons || []).length) {
    intro = `Rated <strong>${escapeHtml(level)}</strong> (${score}/100).`;
  } else {
    intro = `Rated <strong>${escapeHtml(level)}</strong> (${score}/100). No risk indicators were found.`;
  }
  if (item.quarantined || item.status === "quarantined") {
    intro += " This file was moved to quarantine automatically because its score reached 60 or more.";
  }

  let body;
  if (ex.length) {
    body = ex.map(e => `
      <div class="why-item">
        <div class="why-head">
          <span class="why-cat ${CATEGORY_CLASS[e.category] || "heur"}">${escapeHtml(e.category)}</span>
          <strong>${escapeHtml(e.title)}</strong>
          ${e.points ? `<span class="why-points">+${e.points}</span>` : ""}
        </div>
        ${e.detail ? `<p class="why-detail">${escapeHtml(e.detail)}</p>` : ""}
        ${(e.evidence || []).length
          ? `<ul class="why-evidence">${e.evidence.map(x => `<li>${escapeHtml(x)}</li>`).join("")}</ul>` : ""}
        ${e.why ? `<p class="why-meaning">${escapeHtml(e.why)}</p>` : ""}
      </div>`).join("");
  } else {
    // Scan saved before structured explanations existed: show the plain reasons.
    body = (item.reasons || []).map(r => `<div class="why-item"><p class="why-detail">${escapeHtml(r)}</p></div>`).join("");
  }
  return `<div class="why-panel"><p class="why-intro">${intro}</p>${body}</div>`;
}

/** One-line headline reason: the highest-scoring indicator. */
function primaryReason(item) {
  const scored = (item.explanations || []).filter(e => e.points > 0);
  if (!scored.length) return "";
  const top = scored.reduce((a, b) => (b.points > a.points ? b : a));
  return `${top.title}${top.detail ? " - " + top.detail : ""}`;
}

// ---------------------------------------------------------------------
// USB status + scan progress
// ---------------------------------------------------------------------
async function pollStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    renderUsbList(data.connected_devices || []);
    renderMonitorPill(data.active_scan);

    if (data.active_scan) {
      currentScanId = data.active_scan;
      renderProgress(data.progress);
      loadFindings(currentScanId);
    } else {
      $("scanProgressWrap").classList.add("hidden");
      if (currentScanId) {
        $("genReportBtn").disabled = false;
      }
    }
  } catch (err) {
    console.error("status poll failed", err);
  }
}

function renderMonitorPill(activeScan) {
  const pill = $("monitorState");
  if (activeScan) {
    pill.classList.add("scanning");
    pill.querySelector(".label").textContent = "Scan in progress\u2026";
  } else {
    pill.classList.remove("scanning");
    pill.querySelector(".label").textContent = "Watching for USB devices\u2026";
  }
}

function renderUsbList(devices) {
  const el = $("usbList");
  if (!devices.length) {
    el.innerHTML = `<p class="empty-hint">No removable drive connected. Insert a USB device to begin an automatic scan.</p>`;
    return;
  }
  el.innerHTML = devices.map(d => `
    <div class="usb-item">
      <div><span>USB Name</span>${escapeHtml(d.label)}</div>
      <div><span>Drive</span>${escapeHtml(d.drive_letter)}</div>
      <div><span>Capacity</span>${escapeHtml(d.capacity_human)}</div>
      <div><span>File System</span>${escapeHtml(d.file_system)}</div>
      <div><span>Connected</span>${escapeHtml(d.connected_time)}</div>
    </div>
  `).join("");
}

function renderProgress(progress) {
  const wrap = $("scanProgressWrap");
  if (!progress || !progress.total) { wrap.classList.add("hidden"); return; }
  wrap.classList.remove("hidden");
  const pct = progress.total ? Math.round((progress.done / progress.total) * 100) : 0;
  $("progressBar").style.width = pct + "%";
  $("progressCount").textContent = `${progress.done} / ${progress.total}`;
  $("progressFile").textContent = progress.current_file || "";
}

// ---------------------------------------------------------------------
// Findings / results table + per-level counters
// ---------------------------------------------------------------------
async function loadFindings(scanId) {
  try {
    const res = await fetch(`/api/scan/${scanId}/findings`);
    const data = await res.json();
    renderResults(data.findings || []);
  } catch (err) {
    console.error("findings load failed", err);
  }
}

function riskBadge(level, score) {
  const safeLevel = level || "Low";
  return `<span class="risk-badge ${safeLevel}">${score} \u00b7 ${safeLevel}</span>`;
}

let lastFindings = [];
const expandedFindings = new Set();   // keys of rows whose "Why?" panel is open (survives polling)
const findingKey = f => f.absolute_path || f.file_name;

function renderResults(findings) {
  lastFindings = findings;
  const body = $("resultsBody");
  if (!findings.length) {
    body.innerHTML = `<tr><td colspan="5" class="empty-hint">No files scanned yet.</td></tr>`;
    return;
  }

  let l1 = 0, l1f = 0, l2 = 0, l2f = 0, l3 = 0, l3f = 0;
  findings.forEach(f => {
    if (f.level === 1) { l1++; if (f.risk_score >= 30) l1f++; }
    if (f.level === 2) { l2++; if (f.risk_score >= 30) l2f++; }
    if (f.level === 3) { l3++; if (f.risk_score >= 30) l3f++; }
  });
  $("l1Count").textContent = l1; $("l1Flagged").textContent = l1f;
  $("l2Count").textContent = l2; $("l2Flagged").textContent = l2f;
  $("l3Count").textContent = l3; $("l3Flagged").textContent = l3f;

  const sorted = [...findings].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
  body.innerHTML = sorted.slice(0, 200).map(f => {
    const key = findingKey(f);
    const open = expandedFindings.has(key);
    const hasWhy = (f.explanations || []).length || (f.reasons || []).length;
    const flagged = (f.risk_score || 0) >= 30;
    const chips = (f.explanations || []).filter(e => e.points > 0).map(e =>
      `<span class="reason-chip">${escapeHtml(e.title)} <em>+${e.points}</em></span>`).join("");
    const headline = flagged ? primaryReason(f) : "";
    const reasonsCell = chips
      ? `<div class="chip-row">${chips}</div>${headline ? `<div class="why-headline">${escapeHtml(headline)}</div>` : ""}`
      : escapeHtml((f.reasons || []).slice(0, 3).join("; ") || "None");
    return `
    <tr class="${flagged ? "flagged-row" : ""}">
      <td>${escapeHtml(f.file_name)}<br><span class="reasons-cell">${escapeHtml(fmtBytes(f.size_bytes))}</span></td>
      <td>L${f.level ?? "-"}</td>
      <td>${riskBadge(f.risk_level, f.risk_score)}</td>
      <td class="reasons-cell">${reasonsCell}
        ${hasWhy ? `<button class="why-btn" data-key="${escapeHtml(key)}">${open ? "Hide details" : (flagged ? "Why flagged?" : "Details")}</button>` : ""}
      </td>
      <td>${f.quarantined ? '<span class="reasons-cell">Quarantined</span>' : ""}</td>
    </tr>
    ${open ? `<tr class="why-row"><td colspan="5">${renderWhyPanel(f)}</td></tr>` : ""}`;
  }).join("");
}

$("resultsBody").addEventListener("click", ev => {
  const btn = ev.target.closest(".why-btn");
  if (!btn) return;
  const key = btn.dataset.key;
  if (expandedFindings.has(key)) expandedFindings.delete(key); else expandedFindings.add(key);
  renderResults(lastFindings);
});

// ---------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------
async function loadQuarantine() {
  try {
    const res = await fetch("/api/quarantine");
    const items = await res.json();
    renderQuarantine(items);
  } catch (err) {
    console.error("quarantine load failed", err);
  }
}

let lastQuarantine = [];
const expandedQuarantine = new Set();   // quarantine ids whose panel is open

function renderQuarantine(items) {
  lastQuarantine = items;
  const body = $("quarantineBody");
  if (!items.length) {
    body.innerHTML = `<tr><td colspan="5" class="empty-hint">No files quarantined yet.</td></tr>`;
    return;
  }
  body.innerHTML = items.map(it => {
    const open = expandedQuarantine.has(it.id);
    const hasWhy = (it.explanations || []).length || (it.reasons || []).length;
    return `
    <tr>
      <td class="reasons-cell">${escapeHtml(it.original_path)}
        ${hasWhy ? `<br><button class="why-btn" data-qid="${it.id}">${open ? "Hide details" : "Why quarantined?"}</button>` : ""}
      </td>
      <td class="reasons-cell">${escapeHtml((it.sha256 || "").slice(0, 16))}&hellip;</td>
      <td>${riskBadge(it.risk_score >= 80 ? "Critical" : it.risk_score >= 60 ? "High" : "Medium", it.risk_score)}</td>
      <td class="reasons-cell">${escapeHtml(it.status)}</td>
      <td>
        <button class="btn btn-sm btn-ghost" onclick="restoreItem(${it.id})">Restore</button>
        <button class="btn btn-sm btn-ghost" onclick="exportItem(${it.id})">Export</button>
        <button class="btn btn-sm btn-primary sandbox-btn" data-id="${it.id}" data-path="${escapeHtml(it.original_path)}">Sandbox</button>
        <button class="btn btn-sm btn-danger" onclick="deleteItem(${it.id})">Delete</button>
      </td>
    </tr>
    ${open ? `<tr class="why-row"><td colspan="5">${renderWhyPanel({ ...it, status: "quarantined" })}</td></tr>` : ""}`;
  }).join("");
}

// Delegated handlers: the path is read from a data attribute, never spliced into JS source.
$("quarantineBody").addEventListener("click", ev => {
  const why = ev.target.closest(".why-btn");
  if (why) {
    const id = Number(why.dataset.qid);
    if (expandedQuarantine.has(id)) expandedQuarantine.delete(id); else expandedQuarantine.add(id);
    renderQuarantine(lastQuarantine);
    return;
  }
  const sb = ev.target.closest(".sandbox-btn");
  if (sb) openSandboxModal(Number(sb.dataset.id), sb.dataset.path);
});

async function restoreItem(id) {
  const res = await fetch(`/api/quarantine/${id}/restore`, { method: "POST" });
  const data = await res.json();
  if (res.ok) { showToast("File restored to original location."); loadQuarantine(); }
  else showToast(data.error || "Restore failed", true);
}

async function deleteItem(id) {
  if (!confirm("Permanently delete this quarantined file? This cannot be undone.")) return;
  const res = await fetch(`/api/quarantine/${id}/delete`, { method: "POST" });
  const data = await res.json();
  if (res.ok) { showToast("File permanently deleted."); loadQuarantine(); }
  else showToast(data.error || "Delete failed", true);
}

async function exportItem(id) {
  const res = await fetch(`/api/quarantine/${id}/export`, { method: "POST" });
  const data = await res.json();
  if (res.ok) showToast(`Sample exported to ${data.path}`);
  else showToast(data.error || "Export failed", true);
}

// ---------------------------------------------------------------------
// Sandbox modal
// ---------------------------------------------------------------------
async function openSandboxModal(itemId, filePath) {
  currentSandboxItemId = itemId;
  $("sandboxModalFile").textContent = filePath;
  $("sandboxModal").classList.remove("hidden");

  const res = await fetch("/api/sandbox/available");
  const avail = await res.json();
  const select = $("sandboxSelect");
  select.innerHTML = "";
  Object.entries(avail).forEach(([key, info]) => {
    const opt = document.createElement("option");
    opt.value = key;
    opt.textContent = `${info.name}${info.ready ? " (Ready)" : " (Not installed)"}`;
    opt.disabled = !info.ready;
    select.appendChild(opt);
  });
  select.onchange = () => {
    $("vmNameWrap").classList.toggle("hidden", select.value === "windows_sandbox");
  };
  select.onchange();
}

function closeSandboxModal() {
  $("sandboxModal").classList.add("hidden");
  currentSandboxItemId = null;
}

async function runSandboxAnalysis() {
  const sandboxType = $("sandboxSelect").value;
  const vmName = $("vmNameInput").value;
  showToast("Launching sandbox analysis\u2026 this can take up to two minutes.");
  closeSandboxModal();

  try {
    const res = await fetch(`/api/quarantine/${currentSandboxItemId}/sandbox`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sandbox_type: sandboxType, vm_name: vmName || null }),
    });
    const data = await res.json();
    if (data.status === "completed") {
      showToast(`Sandbox run complete: ${data.verdict_notes || "see report"}`);
    } else {
      showToast(data.message || "Sandbox run did not complete.", true);
    }
  } catch (err) {
    showToast("Sandbox request failed.", true);
  }
}

// ---------------------------------------------------------------------
// Sandbox availability card
// ---------------------------------------------------------------------
async function loadSandboxAvailability() {
  try {
    const res = await fetch("/api/sandbox/available");
    const avail = await res.json();
    setSandboxStatus("wsStatus", avail.windows_sandbox?.ready);
    setSandboxStatus("vmwareStatus", avail.vmware?.ready);
    setSandboxStatus("vboxStatus", avail.virtualbox?.ready);
  } catch (err) {
    console.error("sandbox availability failed", err);
  }
}

function setSandboxStatus(elId, ready) {
  const el = $(elId);
  el.textContent = ready ? "Ready" : "Not installed";
  el.className = ready ? "ready" : "missing";
}

// ---------------------------------------------------------------------
// History
// ---------------------------------------------------------------------
async function loadHistory() {
  try {
    const res = await fetch("/api/history");
    const scans = await res.json();
    renderHistory(scans);
  } catch (err) {
    console.error("history load failed", err);
  }
}

function renderHistory(scans) {
  const body = $("historyBody");
  if (!scans.length) {
    body.innerHTML = `<tr><td colspan="6" class="empty-hint">No previous scans.</td></tr>`;
    return;
  }
  body.innerHTML = scans.map(s => `
    <tr>
      <td>${escapeHtml(s.usb_name || "Unknown")}</td>
      <td class="reasons-cell">${escapeHtml((s.started_at || "").replace("T", " ").slice(0, 19))}</td>
      <td>${s.files_scanned ?? 0}</td>
      <td>${s.suspicious_files ?? 0}</td>
      <td>${riskBadge(s.highest_risk >= 80 ? "Critical" : s.highest_risk >= 60 ? "High" : s.highest_risk >= 30 ? "Medium" : "Low", s.highest_risk ?? 0)}</td>
      <td>${s.report_path
        ? `<a class="btn btn-sm btn-ghost" href="/api/report/${s.scan_id}/download">Download</a>`
        : `<button class="btn btn-sm btn-ghost" onclick="generateReport('${s.scan_id}')">Generate</button>`}</td>
    </tr>
  `).join("");
}

async function generateReport(scanId) {
  showToast("Generating forensic PDF report\u2026");
  const res = await fetch(`/api/scan/${scanId}/report`, { method: "POST" });
  const data = await res.json();
  if (res.ok) {
    showToast("Report generated.");
    loadHistory();

    // Auto-Download Report: re-check the live preference (not just the
    // cached value) so a change made in another tab/session is honored,
    // then trigger the download immediately with no further click.
    try {
      const prefRes = await fetch("/api/settings/preferences");
      const pref = await prefRes.json();
      if (pref.auto_download_report) {
        triggerBrowserDownload(`/api/report/${scanId}/download`);
      }
    } catch (err) {
      console.error("auto-download preference check failed", err);
    }
  } else {
    showToast(data.error || "Report generation failed.", true);
  }
}

$("genReportBtn").addEventListener("click", () => {
  if (currentScanId) generateReport(currentScanId);
});

// ---------------------------------------------------------------------
// Sidebar navigation
// ---------------------------------------------------------------------
function initSidebarNav() {
  const navItems = document.querySelectorAll(".nav-item");
  navItems.forEach(btn => {
    btn.addEventListener("click", () => {
      navItems.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const view = btn.dataset.view;
      $("view-dashboard").classList.toggle("hidden", view !== "dashboard");
      $("view-settings").classList.toggle("hidden", view !== "settings");
      if (view === "settings") { loadStartupStatus(); loadAutoDownloadPreference(); }
    });
  });
}

// ---------------------------------------------------------------------
// Settings: Start with Windows (HKCU Run key, user-controlled)
// ---------------------------------------------------------------------
function renderStartupStatus(status) {
  const enabled = !!status.enabled;
  $("startupCheckbox").checked = enabled;
  const label = $("startupStatusLabel");
  label.textContent = enabled ? "Enabled" : "Disabled";
  label.className = `status-pill ${enabled ? "enabled" : "disabled"}`;

  const pathEl = $("startupRegisteredPath");
  if (enabled && status.registered_path) {
    pathEl.textContent = `Registered path: ${status.registered_path}`;
  } else {
    pathEl.textContent = `Key: HKCU\\${status.key_path ? status.key_path.replace("HKCU\\", "") : ""}  \u00b7  Value name: ${status.value_name || "USBThreatAnalyzer"}`;
  }

  if (status.platform_supported === false) {
    showToast("Registry startup control is only available on Windows.", true);
  }
}

async function loadStartupStatus() {
  try {
    const res = await fetch("/api/settings/startup");
    const status = await res.json();
    renderStartupStatus(status);
  } catch (err) {
    console.error("startup status load failed", err);
  }
}

async function applyStartupSetting() {
  const enabled = $("startupCheckbox").checked;
  const btn = $("startupApplyBtn");
  btn.disabled = true;
  btn.textContent = "Applying\u2026";
  try {
    const res = await fetch("/api/settings/startup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled }),
    });
    const data = await res.json();
    if (data.success) {
      showToast(data.message || "Settings applied.");
    } else {
      showToast(data.message || "Could not apply startup setting.", true);
    }
    if (data.status) renderStartupStatus(data.status);
  } catch (err) {
    showToast("Request failed. Please try again.", true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Apply Changes";
  }
}

$("startupApplyBtn").addEventListener("click", applyStartupSetting);

// ---------------------------------------------------------------------
// Settings: Auto-Download Report
// ---------------------------------------------------------------------
let autoDownloadEnabled = false; // cached; re-synced on Settings view load and on toggle apply

function renderAutoDownloadStatus(enabled) {
  autoDownloadEnabled = !!enabled;
  $("autoDownloadCheckbox").checked = autoDownloadEnabled;
  const label = $("autoDownloadStatusLabel");
  label.textContent = autoDownloadEnabled ? "Enabled" : "Disabled";
  label.className = `status-pill ${autoDownloadEnabled ? "enabled" : "disabled"}`;
}

async function loadAutoDownloadPreference() {
  try {
    const res = await fetch("/api/settings/preferences");
    const data = await res.json();
    renderAutoDownloadStatus(data.auto_download_report);
  } catch (err) {
    console.error("preferences load failed", err);
  }
}

async function applyAutoDownloadSetting() {
  const enabled = $("autoDownloadCheckbox").checked;
  const btn = $("autoDownloadApplyBtn");
  btn.disabled = true;
  btn.textContent = "Applying\u2026";
  try {
    const res = await fetch("/api/settings/preferences", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ auto_download_report: enabled }),
    });
    const data = await res.json();
    renderAutoDownloadStatus(data.auto_download_report);
    showToast(enabled
      ? "Reports will now download automatically when generated."
      : "Auto-download turned off. Use the Download button in History instead.");
  } catch (err) {
    showToast("Request failed. Please try again.", true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Apply Changes";
  }
}

$("autoDownloadApplyBtn").addEventListener("click", applyAutoDownloadSetting);

/**
 * Triggers a same-origin file download without any user click, via a
 * hidden <a download> element. Used right after a report finishes
 * generating when Auto-Download Report is enabled.
 */
function triggerBrowserDownload(url) {
  const link = document.createElement("a");
  link.href = url;
  link.download = "";
  link.style.display = "none";
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

// ---------------------------------------------------------------------
// Drag-and-drop scanning (desktop app)
//
// This page never sees real file paths (the browser hides them) and never
// decides what gets scanned. The native window in desktop.py receives the drop,
// reads the Windows paths itself, runs the scan, and reports back through
// window.onNativeDrop() below. The code here only (a) cancels the browser's
// default "open the dropped file" behaviour, (b) shows the drop overlay, and
// (c) displays the outcome.
// ---------------------------------------------------------------------
function dragHasFiles(ev) {
  const types = ev.dataTransfer && ev.dataTransfer.types;
  return !!types && Array.from(types).includes("Files");
}

function initDropScan() {
  const overlay = $("dropOverlay");
  let hideTimer = null;
  const hideOverlay = () => { clearTimeout(hideTimer); overlay.classList.add("hidden"); };

  // Capture phase so the native drop handler's propagation rules can't starve us.
  window.addEventListener("dragover", ev => {
    if (!dragHasFiles(ev)) return;
    ev.preventDefault();                  // without this the drop is refused / the window navigates
    ev.dataTransfer.dropEffect = "copy";
    overlay.classList.remove("hidden");
    clearTimeout(hideTimer);              // dragover repeats while hovering; stops when the pointer leaves
    hideTimer = setTimeout(hideOverlay, 700);
  }, true);

  window.addEventListener("drop", ev => {
    if (!dragHasFiles(ev)) return;
    ev.preventDefault();
    hideOverlay();
    if (!window.pywebview) {
      showToast("Drag-and-drop scanning is only available in the desktop app.", true);
    }
  }, true);

  window.addEventListener("dragend", hideOverlay, true);
}

/** Called by desktop.py (via evaluate_js) with the state of a dropped-file scan. */
window.onNativeDrop = function (info) {
  if (!info) return;
  if (info.event === "started") {
    document.querySelector('.nav-item[data-view="dashboard"]')?.click();  // leave Settings if open
    currentScanId = info.scan_id;
    $("genReportBtn").disabled = true;
    showToast(`Scanning ${info.total} file${info.total === 1 ? "" : "s"}\u2026`);
    loadFindings(info.scan_id);
  } else if (info.event === "finished") {
    currentScanId = info.scan_id;
    loadFindings(info.scan_id);
    loadQuarantine();
    loadHistory();
    $("genReportBtn").disabled = false;
    let msg = `Scan complete: ${info.files_scanned} file${info.files_scanned === 1 ? "" : "s"}, `
      + `${info.suspicious} suspicious`;
    if (info.quarantined) msg += `, ${info.quarantined} quarantined`;
    if (info.skipped) msg += ` (${info.skipped} skipped)`;
    showToast(msg + ".", info.highest_risk >= 60);
  } else if (info.event === "rejected" || info.event === "error") {
    showToast(info.message || "Could not scan the dropped items.", true);
  }
};

document.addEventListener("DOMContentLoaded", initDropScan);

// ---------------------------------------------------------------------
// Modal wiring + boot
// ---------------------------------------------------------------------
$("sandboxCancelBtn").addEventListener("click", closeSandboxModal);
$("sandboxRunBtn").addEventListener("click", runSandboxAnalysis);

function bootPolling() {
  initSidebarNav();
  loadStartupStatus();           // sync checkbox/status on launch, per spec
  loadAutoDownloadPreference();  // so auto-download works even before opening Settings
  pollStatus();
  loadQuarantine();
  loadHistory();
  loadSandboxAvailability();
  setInterval(pollStatus, POLL_INTERVAL_MS);
  setInterval(loadQuarantine, 6000);
  setInterval(loadHistory, 8000);
}

document.addEventListener("DOMContentLoaded", bootPolling);
