/* ===================================================================
   Agent Trace Observatory – Frontend
   HTML/SVG graph rendering with dagre layout, vertical scrolling,
   smooth zoom, file-activity panel, breadcrumb navigation.
   =================================================================== */

// ─── State ────────────────────────────────────────────────────────
let selectedTraceId = null;
let currentMode = "high"; // "high" | "tool" | "process" | "internal"
let currentToolCallId = null;
let currentProcessPid = null;
let processTrail = [];
let currentInternalRange = null;
let cachedTraces = [];
let latestVersion = -1;
let zoomLevel = 1;
let selectedNodeId = null;
let cachedTraceFiles = []; // trace-level files cache
let cachedTraceTools = [];
let currentSyscallMode = false; // true when showing syscall-only (no trajectory)
let activeTab = "trace"; // "trace" | "taint" | "blast"
let taintReportCache = null;
let selectedBlastBaselines = new Set();

// ─── DOM refs ─────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);
const traceListEl = $("traceList");
const breadcrumbsEl = $("breadcrumbs");
const graphWrapper = $("graphWrapper");
const graphCanvas = $("graphCanvas");
const emptyState = $("emptyState");
const detailsEl = $("details");
const filesListEl = $("filesList");
const fileScopeLabel = $("fileScopeLabel");
const fileCountBadge = $("fileCountBadge");
const fileFilterEl = $("fileFilter");
const toolsListEl = $("toolsList");
const toolsCountBadge = $("toolsCountBadge");
const toolsToggle = $("toolsToggle");
const toolsSectionBody = $("toolsSectionBody");
const toolsCaret = $("toolsCaret");
const fileToggle = $("fileToggle");
const fileSectionBody = $("fileSectionBody");
const fileCaret = $("fileCaret");
const selectionToggle = $("selectionToggle");
const selectionSectionBody = $("selectionSectionBody");
const selectionCaret = $("selectionCaret");
const zoomInBtn = $("zoomInBtn");
const zoomOutBtn = $("zoomOutBtn");
const fitBtn = $("fitBtn");
const zoomDisplay = $("zoomDisplay");
const traceTabBtn = $("traceTabBtn");
const taintTabBtn = $("taintTabBtn");
const blastTabBtn = $("blastTabBtn");

const sumPromptsEl = $("sumPrompts");
const sumToolsEl = $("sumTools");
const sumResponsesEl = $("sumResponses");
const sumStatusEl = $("sumStatus");

// ─── Utilities ────────────────────────────────────────────────────
function truncate(text, max = 220) {
  if (!text) return "";
  const s = String(text).replace(/\n/g, " ").trim();
  return s.length > max ? s.slice(0, max) + "…" : s;
}

function formatDuration(ms) {
  if (ms == null) return "";
  const n = Number(ms);
  if (n < 1000) return `${Math.round(n)}ms`;
  return `${(n / 1000).toFixed(1)}s`;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

let toolsExpanded = true;
let filesExpanded = false;
let selectionExpanded = false;
async function openToolDrilldown(toolCallId, toolName) {
  if (!selectedTraceId || !toolCallId) return;
  currentMode = "tool";
  currentToolCallId = toolCallId;
  zoomLevel = 1;
  applyZoom();
  renderBreadcrumbs();
  await loadToolGraph(toolCallId);

  try {
    const summary = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/tool-summary/${encodeURIComponent(toolCallId)}`);
    const files = summary.files || [];
    const net = summary.network || [];
    window._lastToolFiles = files;
    window._lastToolNetwork = net;
    if (files.length > 0 || net.length > 0) {
      renderFiles(files, `Files for: ${toolName || toolCallId}`, files.length, net);
    } else {
      renderFiles(cachedTraceFiles, "No tool-specific files - showing trace-level activity", cachedTraceFiles.length, window._cachedTraceNetwork);
    }
  } catch (_) {
    renderFiles(cachedTraceFiles, "Trace-level file activity", cachedTraceFiles.length, window._cachedTraceNetwork);
  }
}

async function openProcessDrilldown(pid) {
  if (!selectedTraceId || !pid) return;
  currentMode = "process";
  currentProcessPid = Number(pid);
  if (processTrail.length === 0 || processTrail[processTrail.length - 1] !== currentProcessPid) {
    processTrail.push(currentProcessPid);
  }
  zoomLevel = 1;
  applyZoom();
  renderBreadcrumbs();
  await loadProcessGraph(currentProcessPid);
}

async function openInternalDrilldown(lineStart, lineEnd) {
  if (!selectedTraceId || lineStart == null || lineEnd == null) return;
  currentMode = "internal";
  currentInternalRange = { start: Number(lineStart), end: Number(lineEnd) };
  zoomLevel = 1;
  applyZoom();
  renderBreadcrumbs();
  await loadInternalGraph(currentInternalRange.start, currentInternalRange.end);
}

function renderTools(tools) {
  cachedTraceTools = Array.isArray(tools) ? tools : [];
  toolsCountBadge.textContent = `${cachedTraceTools.length}`;
  toolsListEl.innerHTML = "";

  if (cachedTraceTools.length === 0) {
    toolsListEl.innerHTML = '<div class="tools-empty">No tool metadata captured yet.</div>';
    return;
  }

  for (const name of cachedTraceTools) {
    const row = document.createElement("div");
    row.className = "tool-item";
    row.textContent = name;
    toolsListEl.appendChild(row);
  }
}

function setActiveTab(tabName) {
  activeTab = tabName;
  traceTabBtn.classList.toggle("active", tabName === "trace");
  taintTabBtn.classList.toggle("active", tabName === "taint");
  blastTabBtn.classList.toggle("active", tabName === "blast");
}

function setToolsExpanded(expanded) {
  toolsExpanded = expanded;
  toolsSectionBody.style.display = expanded ? "block" : "none";
  toolsCaret.textContent = expanded ? "▼" : "▶";
}

function setFilesExpanded(expanded) {
  filesExpanded = expanded;
  fileSectionBody.style.display = expanded ? "block" : "none";
  fileCaret.textContent = expanded ? "▼" : "▶";
}

function setSelectionExpanded(expanded) {
  selectionExpanded = expanded;
  selectionSectionBody.style.display = expanded ? "block" : "none";
  selectionCaret.textContent = expanded ? "▼" : "▶";
}

// ─── API ──────────────────────────────────────────────────────────
async function api(path) {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

// ─── Trace List ───────────────────────────────────────────────────
function renderTraceList(traces) {
  cachedTraces = traces;
  traceListEl.innerHTML = "";
  for (const t of traces) {
    const div = document.createElement("div");
    div.className = "trace-item" + (t.trace_id === selectedTraceId ? " active" : "");
    const statusCls = t.status === "completed" ? "completed" : "active";
    div.innerHTML = `
      <div class="trace-row">
        <div class="trace-main">
          <div class="trace-name">${escapeHtml(t.trace_id)}</div>
          <div class="trace-meta">
            <span class="trace-status ${statusCls}">${t.status}</span>
            &nbsp;agent: ${t.agent_event_count} &nbsp;sys: ${t.sys_event_count}
          </div>
        </div>
        <button class="trace-delete-btn" title="Delete trace">&times;</button>
      </div>`;
    div.onclick = () => selectTrace(t.trace_id);

    const delBtn = div.querySelector(".trace-delete-btn");
    if (delBtn) {
      delBtn.addEventListener("click", async (e) => {
        e.stopPropagation();
        await deleteTrace(t.trace_id);
      });
    }

    traceListEl.appendChild(div);
  }
}

function clearSelectionView() {
  graphCanvas.innerHTML = '<div class="empty-state" id="emptyState"><h3>No trace selected</h3><p>Select a trace from the sidebar, or run an agent with eBPF capture to begin.</p></div>';
  renderBreadcrumbs();
  renderFiles([], "Select a trace to view file activity.");
  renderTools([]);
  detailsEl.innerHTML = '<div class="details-empty">Click a node to inspect its metadata.</div>';
  updateSummaryCards({ prompts: 0, tool_steps: 0, responses: 0, trace_status: "-" });
}

async function deleteTrace(traceId) {
  if (!traceId) return;
  try {
    const res = await fetch(`/api/traces/${encodeURIComponent(traceId)}`, { method: "DELETE" });
    if (!res.ok) throw new Error(`API ${res.status}`);
  } catch (_) {
    return;
  }

  if (selectedTraceId === traceId) {
    selectedTraceId = null;
    currentMode = "high";
    currentToolCallId = null;
    currentProcessPid = null;
    processTrail = [];
    currentInternalRange = null;
    selectedNodeId = null;
    cachedTraceFiles = [];
    cachedTraceTools = [];
    window._cachedTraceNetwork = [];
  }

  await refreshTraces(false, true);
}

async function selectTrace(traceId) {
  selectedTraceId = traceId;
  currentMode = "high";
  currentToolCallId = null;
  currentProcessPid = null;
  processTrail = [];
  currentInternalRange = null;
  selectedNodeId = null;
  zoomLevel = 1;
  applyZoom();
  renderTraceList(cachedTraces);
  if (activeTab === "trace") {
    await loadHighLevelGraph();
  } else if (activeTab === "taint") {
    await loadTaintAnalysis();
  } else {
    await loadBlastAnalysis();
  }
  await loadTraceSummary();
}

// ─── Summary cards ────────────────────────────────────────────────
function updateSummaryCards(summary) {
  if (currentSyscallMode) {
    // Syscall-only mode: show system-level stats
    const strip = document.getElementById("summaryStrip");
    strip.innerHTML = `
      <div class="summary-card"><div class="k">Commands</div><div class="v">${summary.commands ?? 0}</div></div>
      <div class="summary-card"><div class="k">Files Touched</div><div class="v">${summary.files_touched ?? 0}</div></div>
      <div class="summary-card"><div class="k">Net Endpoints</div><div class="v">${summary.net_endpoints ?? 0}</div></div>
      <div class="summary-card"><div class="k">Status</div><div class="v">${summary.trace_status ?? "-"}</div></div>`;
    return;
  }
  // Restore original cards if needed
  const strip = document.getElementById("summaryStrip");
  strip.innerHTML = `
    <div class="summary-card"><div class="k">Prompts</div><div class="v" id="sumPrompts">${summary.prompts ?? 0}</div></div>
    <div class="summary-card"><div class="k">Tool Steps</div><div class="v" id="sumTools">${summary.tool_steps ?? 0}</div></div>
    <div class="summary-card"><div class="k">Responses</div><div class="v" id="sumResponses">${summary.responses ?? 0}</div></div>
    <div class="summary-card"><div class="k">Status</div><div class="v" id="sumStatus">${summary.trace_status ?? "-"}</div></div>`;
}

function updateSummaryCardsTaint(report) {
  const counts = report.finding_counts || {};
  const strip = document.getElementById("summaryStrip");
  strip.innerHTML = `
    <div class="summary-card"><div class="k">Critical</div><div class="v">${counts.critical ?? 0}</div></div>
    <div class="summary-card"><div class="k">Warnings</div><div class="v">${counts.warning ?? 0}</div></div>
    <div class="summary-card"><div class="k">Info</div><div class="v">${counts.info ?? 0}</div></div>
    <div class="summary-card"><div class="k">Trust Policy</div><div class="v" style="font-size:13px;line-height:1.3;padding-top:6px;">${escapeHtml(report.trust_policy || "nondeterministic")}</div></div>`;
}

function updateSummaryCardsBlast(report) {
  const summary = report.summary || {};
  const strip = document.getElementById("summaryStrip");
  strip.innerHTML = `
    <div class="summary-card"><div class="k">Baselines</div><div class="v">${(report.baseline_ids || []).length}</div></div>
    <div class="summary-card"><div class="k">Rows</div><div class="v">${summary.rows ?? 0}</div></div>
    <div class="summary-card"><div class="k">Deviations</div><div class="v">${summary.deviations ?? 0}</div></div>
    <div class="summary-card"><div class="k">Risk Score</div><div class="v">${summary.deviation_score ?? 0}</div></div>`;
}

// ─── Breadcrumbs ──────────────────────────────────────────────────
function renderBreadcrumbs() {
  breadcrumbsEl.innerHTML = "";
  if (!selectedTraceId) {
    breadcrumbsEl.innerHTML = '<span class="crumb current">No trace selected</span>';
    return;
  }
  const traceCrumb = document.createElement("span");
  traceCrumb.className = "crumb" + (currentMode === "high" ? " current" : "");
  traceCrumb.textContent = selectedTraceId;
  traceCrumb.onclick = () => { if (currentMode !== "high") goBackToHighLevel(); };
  breadcrumbsEl.appendChild(traceCrumb);

  if (currentMode === "tool" && currentToolCallId) {
    const sep = document.createElement("span");
    sep.className = "sep";
    sep.textContent = "›";
    breadcrumbsEl.appendChild(sep);
    const toolCrumb = document.createElement("span");
    toolCrumb.className = "crumb current";
    toolCrumb.textContent = `Tool: ${currentToolCallId.slice(0, 20)}`;
    breadcrumbsEl.appendChild(toolCrumb);
  }

  if (currentMode === "process" && processTrail.length > 0) {
    const sep = document.createElement("span");
    sep.className = "sep";
    sep.textContent = "›";
    breadcrumbsEl.appendChild(sep);

    const procCrumb = document.createElement("span");
    procCrumb.className = "crumb current";
    procCrumb.textContent = `Process: ${processTrail[processTrail.length - 1]}`;
    breadcrumbsEl.appendChild(procCrumb);
  }

  if (currentMode === "internal" && currentInternalRange) {
    const sep = document.createElement("span");
    sep.className = "sep";
    sep.textContent = "›";
    breadcrumbsEl.appendChild(sep);

    const internalCrumb = document.createElement("span");
    internalCrumb.className = "crumb current";
    internalCrumb.textContent = `Internal: L${currentInternalRange.start}-L${currentInternalRange.end}`;
    breadcrumbsEl.appendChild(internalCrumb);
  }
}

async function goBackToHighLevel() {
  currentMode = "high";
  currentToolCallId = null;
  currentProcessPid = null;
  processTrail = [];
  currentInternalRange = null;
  selectedNodeId = null;
  zoomLevel = 1;
  applyZoom();
  await loadHighLevelGraph();
  renderFiles(cachedTraceFiles, "Trace-level file activity", cachedTraceFiles.length, window._cachedTraceNetwork);
}

// ─── Zoom ─────────────────────────────────────────────────────────
function applyZoom() {
  graphCanvas.style.transform = `scale(${zoomLevel})`;
  zoomDisplay.textContent = `${Math.round(zoomLevel * 100)}%`;
}

function changeZoom(delta) {
  zoomLevel = Math.max(0.3, Math.min(2.5, zoomLevel + delta));
  applyZoom();
}

zoomInBtn.addEventListener("click", () => changeZoom(0.1));
zoomOutBtn.addEventListener("click", () => changeZoom(-0.1));
fitBtn.addEventListener("click", () => { zoomLevel = 1; applyZoom(); graphWrapper.scrollTo({ top: 0, behavior: "smooth" }); });

graphWrapper.addEventListener("wheel", (e) => {
  if (e.ctrlKey || e.metaKey) {
    e.preventDefault();
    const delta = e.deltaY > 0 ? -0.06 : 0.06;
    changeZoom(delta);
  }
  // else: natural scroll (vertical & horizontal)
}, { passive: false });

// Keyboard shortcuts
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && currentMode === "tool") {
    goBackToHighLevel();
  }
});

if (toolsToggle) {
  toolsToggle.addEventListener("click", () => setToolsExpanded(!toolsExpanded));
}
if (fileToggle) {
  fileToggle.addEventListener("click", () => setFilesExpanded(!filesExpanded));
}
if (selectionToggle) {
  selectionToggle.addEventListener("click", () => setSelectionExpanded(!selectionExpanded));
}

// ─── Linear File Compression ───────────────────────────────────────
function renderLinearFiles(files) {
  const sorted = [...files].sort((a, b) => String(a.path || "").localeCompare(String(b.path || "")));
  const maxShownPerDir = 4;
  const byDir = new Map();

  for (const f of sorted) {
    const path = String(f.path || "");
    const idx = path.lastIndexOf("/");
    const dir = idx >= 0 ? path.slice(0, idx) : ".";
    if (!byDir.has(dir)) byDir.set(dir, []);
    byDir.get(dir).push(f);
  }

  for (const [dir, entries] of byDir.entries()) {
    const hdr = document.createElement("div");
    hdr.className = "file-row tree-root-prefix";
    hdr.innerHTML = `<div class="file-path" style="color:var(--text-muted);font-size:11px;">${escapeHtml(dir || ".")}</div>`;
    filesListEl.appendChild(hdr);

    const visible = entries.slice(0, maxShownPerDir);
    for (const f of visible) {
      const row = document.createElement("div");
      row.className = "file-row";
      const base = String(f.path || "").split("/").pop() || String(f.path || "");
      const opsHtml = (f.ops || []).map((op) => `<span class="op-badge op-${op}">${op}</span>`).join("");
      row.innerHTML = `
        <div class="file-path">${escapeHtml(base)}</div>
        <div class="file-ops">${opsHtml}<span class="file-count">×${f.count || 0}</span></div>`;
      filesListEl.appendChild(row);
    }

    if (entries.length > maxShownPerDir) {
      const more = document.createElement("div");
      more.className = "file-row grouped-files-row";
      more.innerHTML = `<div class="file-path grouped-path">+ ${entries.length - maxShownPerDir} more files</div>`;
      filesListEl.appendChild(more);
    }
  }
}

// ─── File Activity Panel ──────────────────────────────────────────
function renderFiles(files, scopeLabel, totalCount, network) {
  fileScopeLabel.textContent = scopeLabel || "";
  fileCountBadge.textContent = totalCount != null ? `${totalCount} files` : "";
  filesListEl.innerHTML = "";

  const hasFiles = files && files.length > 0;
  const hasNet = network && network.length > 0;

  if (!hasFiles && !hasNet) {
    fileFilterEl.style.display = "none";
    filesListEl.innerHTML = '<div style="padding:16px;text-align:center;color:var(--text-muted);font-size:12px;">No user-space files detected in this scope.</div>';
    return;
  }

  fileFilterEl.style.display = "block";
  const filterVal = fileFilterEl.value.toLowerCase();

  // Render network endpoints first
  if (hasNet) {
    const filteredNet = filterVal
      ? network.filter((n) => n.dest.toLowerCase().includes(filterVal))
      : network;
    if (filteredNet.length > 0) {
      const netHeader = document.createElement("div");
      netHeader.className = "file-row";
      netHeader.style.background = "var(--emerald-50)";
      netHeader.style.fontWeight = "700";
      netHeader.style.fontSize = "11px";
      netHeader.style.textTransform = "uppercase";
      netHeader.style.letterSpacing = "0.04em";
      netHeader.style.color = "var(--emerald-600)";
      netHeader.textContent = `Network Endpoints (${filteredNet.length})`;
      filesListEl.appendChild(netHeader);

      for (const n of filteredNet.slice(0, 50)) {
        const row = document.createElement("div");
        row.className = "file-row";
        const opsHtml = (n.ops || [])
          .map((op) => `<span class="op-badge op-${op}">${op}</span>`)
          .join("");
        const metaBadges = [];
        if (n.transport && n.transport !== "other") metaBadges.push(`<span class="file-count">${escapeHtml(n.transport)}</span>`);
        if (n.family && n.family !== "other") metaBadges.push(`<span class="file-count">${escapeHtml(n.family)}</span>`);
        if ((n.failed || 0) > 0) metaBadges.push(`<span class="file-count" style="color:var(--orange-600);">fail:${n.failed}</span>`);
        if (Array.isArray(n.errors) && n.errors.length > 0) {
          const err = n.errors.slice(0, 2).join(",");
          metaBadges.push(`<span class="file-count" title="${escapeHtml(n.errors.join(", "))}">${escapeHtml(err)}</span>`);
        }
        const bytesStr = n.bytes > 1024 ? `${(n.bytes / 1024).toFixed(1)}KB` : (n.bytes > 0 ? `${n.bytes}B` : "");
        row.innerHTML = `
          <div class="file-path" style="color:var(--emerald-600);">${escapeHtml(n.dest)}</div>
          <div class="file-ops">
            ${opsHtml}
            ${metaBadges.join("")}
            ${bytesStr ? `<span class="file-count">${bytesStr}</span>` : ""}
            <span class="file-count">×${n.count || 0}</span>
          </div>`;
        filesListEl.appendChild(row);
      }
    }
  }

  // File rows — tree view
  if (hasFiles) {
    const filtered = filterVal
      ? files.filter((f) => f.path.toLowerCase().includes(filterVal))
      : files;

    if (hasNet && filtered.length > 0) {
      const fileHeader = document.createElement("div");
      fileHeader.className = "file-row";
      fileHeader.style.background = "var(--cyan-50)";
      fileHeader.style.fontWeight = "700";
      fileHeader.style.fontSize = "11px";
      fileHeader.style.textTransform = "uppercase";
      fileHeader.style.letterSpacing = "0.04em";
      fileHeader.style.color = "var(--cyan-600)";
      fileHeader.textContent = `Files (${filtered.length})`;
      filesListEl.appendChild(fileHeader);
    }

    if (filtered.length > 0) {
      renderLinearFiles(filtered);
    }
  }
}

// Wire up file filter
fileFilterEl.addEventListener("input", () => {
  const files = currentMode === "tool" ? (window._lastToolFiles || cachedTraceFiles) : cachedTraceFiles;
  const net = currentMode === "tool" ? (window._lastToolNetwork || window._cachedTraceNetwork || []) : (window._cachedTraceNetwork || []);
  const scope = currentMode === "tool" ? "Tool-scope file activity" : "Trace-level file activity";
  renderFiles(files, scope, (files || []).length, net);
});

// ─── Selection Details ────────────────────────────────────────────
function renderDetails(nodeData) {
  if (!nodeData) {
    detailsEl.innerHTML = '<div class="details-empty">Click a node to inspect its metadata.</div>';
    return;
  }
  const meta = nodeData.metadata || {};
  const folderTree = meta.folder_tree;
  const metaForView = { ...meta };
  delete metaForView.folder_tree;
  const metaStr = JSON.stringify(meta, null, 2);

  const renderFolderTree = (node, level = 0) => {
    if (!node || typeof node !== "object") return "";
    const kind = String(node.kind || "");
    const name = String(node.name || "");
    if (kind === "file") {
      const ops = Array.isArray(node.ops) ? node.ops : [];
      const opsHtml = ops.map((op) => `<span class="op-badge op-${escapeHtml(op)}">${escapeHtml(op)}</span>`).join("");
      const count = Number(node.count || 0);
      return `<div class="details-tree-file" style="margin-left:${level * 14}px;"><span class="folder-icon">📄</span><span>${escapeHtml(name)}</span>${opsHtml}${count > 1 ? `<span class="file-count">x${count}</span>` : ""}</div>`;
    }
    const children = Array.isArray(node.children) ? node.children : [];
    const openAttr = level < 2 ? " open" : "";
    const childrenHtml = children.map((child) => renderFolderTree(child, level + 1)).join("");
    return `
      <details class="details-tree-folder"${openAttr}>
        <summary><span class="folder-icon">📁</span>${escapeHtml(name || "/")}</summary>
        <div class="details-tree-children">${childrenHtml}</div>
      </details>`;
  };

  const treeHtml = folderTree ? `<div class="details-tree-wrap">${renderFolderTree(folderTree)}</div>` : "";
  const metaViewStr = JSON.stringify(metaForView, null, 2);
  detailsEl.innerHTML = `
    <div class="detail-title">${escapeHtml(nodeData.label || nodeData.id)}</div>
    ${treeHtml}
    <pre>${escapeHtml(treeHtml ? metaViewStr : metaStr)}</pre>`;
}

// ─── Git-Style Tree Renderer ──────────────────────────────────────
function renderGitTreeGraph(payload) {
  graphCanvas.innerHTML = "";
  emptyState.style.display = "none";

  const nodes = Array.isArray(payload.nodes) ? [...payload.nodes] : [];
  if (nodes.length === 0) {
    graphCanvas.innerHTML = '<div class="empty-state"><h3>No trace events</h3><p>Waiting for process and agent activity...</p></div>';
    return;
  }

  nodes.sort((a, b) => {
    const la = Number(a.line_no || 0);
    const lb = Number(b.line_no || 0);
    if (la !== lb) return la - lb;
    return Number(a.lane || 0) - Number(b.lane || 0);
  });

  const maxLane = nodes.reduce((m, n) => Math.max(m, Number(n.lane || 0)), 0);
  const laneSpacing = 24;
  const graphWidth = (maxLane + 1) * laneSpacing + 16;

  const rangeByLane = new Map();
  for (const branch of payload.branch_ranges || []) {
    const lane = Number(branch.lane || 0);
    if (!rangeByLane.has(lane)) rangeByLane.set(lane, []);
    rangeByLane.get(lane).push({
      start: Number(branch.start_line || 0),
      end: branch.end_line == null ? null : Number(branch.end_line),
      pid: branch.pid,
      parentPid: branch.parent_pid,
    });
  }

  const root = document.createElement("div");
  root.className = "git-tree";

  const kindLabel = {
    process_start: "Process Start",
    process_spawn: "Spawn",
    process_exec: "Exec",
    process_exit: "Exit",
    internal: "Internal",
    prompt: "Prompt",
    prompt_batch: "Prompts",
    assistant_response: "Response",
    file_read: "File Read",
    file_write: "File Write",
    file_delete: "Delete",
    file_rename: "Rename",
    net_connect: "Connect",
    net_send: "Net Send",
    net_recv: "Net Recv",
    folder_group: "Folder View",
  };

  const processDrilldownPid = (node) => {
    const kind = String(node.kind || "");
    if (!(kind === "process_spawn" || kind === "process_exit" || kind === "process_exec")) return null;
    const targetPid = Number(node.pid || 0);
    if (!(targetPid > 0)) return null;
    if (targetPid === Number(payload.root_pid || 0)) return null;
    return targetPid;
  };

  let selectedEl = null;

  const isLaneActiveAt = (lane, lineNo) => {
    const ranges = rangeByLane.get(lane);
    if (!ranges || ranges.length === 0) return false;
    for (const r of ranges) {
      if (lineNo < r.start) continue;
      if (r.end == null || lineNo <= r.end) return true;
    }
    return false;
  };

  for (const node of nodes) {
    const lineNo = Number(node.line_no || 0);
    const lane = Number(node.lane || 0);

    const row = document.createElement("div");
    row.className = "git-row";

    const graph = document.createElement("div");
    graph.className = "git-graph";
    graph.style.width = `${graphWidth}px`;

    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "git-svg");
    svg.setAttribute("width", graphWidth);
    svg.setAttribute("height", 54);
    graph.appendChild(svg);

    for (let i = 0; i <= maxLane; i++) {
      const laneEl = document.createElement("div");
      laneEl.className = "git-lane";
      laneEl.style.left = `${8 + i * laneSpacing}px`;
      if (isLaneActiveAt(i, lineNo)) {
        laneEl.classList.add("active");
      }
      graph.appendChild(laneEl);
    }

    const marker = document.createElement("div");
    const kind = String(node.kind || "event");
    marker.className = `git-marker kind-${kind}`;
    marker.style.left = `${8 + lane * laneSpacing}px`;
    marker.addEventListener("click", async (e) => {
      e.stopPropagation();
      const meta = node.metadata || {};
      const targetPid = processDrilldownPid(node);
      if (targetPid != null) {
        await openProcessDrilldown(targetPid);
        return;
      }
      if (kind === "internal" && meta.line_start != null && meta.line_end != null) {
        await openInternalDrilldown(Number(meta.line_start), Number(meta.line_end));
      }
    });
    graph.appendChild(marker);

    const branchFrom = node.branch_from_lane;
    if (branchFrom != null && Number(branchFrom) !== lane) {
      const x1 = 8 + Number(branchFrom) * laneSpacing;
      const x2 = 8 + lane * laneSpacing;
      const mid = (x1 + x2) / 2;
      const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      path.setAttribute("class", "git-curve branch");
      path.setAttribute("d", `M ${x1} 27 C ${mid} 8, ${mid} 46, ${x2} 27`);
      svg.appendChild(path);
    }

    const mergeTo = node.merge_to_lane;
    if (mergeTo != null && Number(mergeTo) !== lane) {
      const x1 = 8 + lane * laneSpacing;
      const x2 = 8 + Number(mergeTo) * laneSpacing;
      const mid = (x1 + x2) / 2;
      const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      path.setAttribute("class", "git-curve merge");
      path.setAttribute("d", `M ${x1} 27 C ${mid} 46, ${mid} 8, ${x2} 27`);
      svg.appendChild(path);
    }

    const card = document.createElement("div");
    card.className = "git-card";
    card.dataset.nodeId = String(node.id || "");

    const shortLabel = String(node.label || kind);
    const tag = kindLabel[kind] || kind;
    const pid = node.pid != null ? `pid ${node.pid}` : "";
    const lineLabel = Number.isInteger(lineNo) ? `${lineNo}` : lineNo.toFixed(3);

    card.innerHTML = `
      <div class="git-card-head">
        <span class="git-kind">${escapeHtml(tag)}</span>
        <span class="git-line">L${lineLabel}</span>
      </div>
      <div class="git-title">${escapeHtml(shortLabel)}</div>
      <div class="git-meta">${escapeHtml([pid, node.source].filter(Boolean).join(" • "))}</div>
    `;
    card.title = shortLabel;

    card.addEventListener("click", async (e) => {
      e.stopPropagation();
      if (selectedEl) selectedEl.classList.remove("selected");
      selectedEl = card;
      card.classList.add("selected");
      renderDetails(node);

      const targetPid = processDrilldownPid(node);
      if (targetPid != null) {
        await openProcessDrilldown(targetPid);
      }
    });

    card.addEventListener("dblclick", async (e) => {
      e.stopPropagation();
      const meta = node.metadata || {};
      if ((kind === "tool_step" || kind === "tool_call") && meta.tool_call_id) {
        await openToolDrilldown(meta.tool_call_id, meta.tool_name || meta.tool_call_id);
        return;
      }
      if (kind === "internal" && meta.line_start != null && meta.line_end != null) {
        await openInternalDrilldown(Number(meta.line_start), Number(meta.line_end));
        return;
      }
      if ((kind === "process_spawn" || kind === "process_exit" || kind === "process_exec") && node.pid) {
        const targetPid = Number(node.pid);
        if (targetPid > 0 && targetPid !== Number(payload.root_pid || 0)) {
          await openProcessDrilldown(targetPid);
        }
      }
    });

    row.appendChild(graph);
    row.appendChild(card);
    root.appendChild(row);
  }

  graphCanvas.appendChild(root);
}

// ─── High-Level Timeline Renderer ─────────────────────────────────
function renderHighLevelGraph(payload) {
  graphCanvas.innerHTML = "";
  emptyState.style.display = "none";

  const nodes = payload.nodes || [];
  if (nodes.length === 0) {
    graphCanvas.innerHTML = '<div class="empty-state"><h3>No agent events yet</h3><p>Waiting for agent activity…</p></div>';
    return;
  }

  const timeline = document.createElement("div");
  timeline.className = "timeline";

  nodes.forEach((node, idx) => {
    // Connector (except before first node)
    if (idx > 0) {
      const conn = document.createElement("div");
      conn.className = "timeline-connector";
      conn.innerHTML = '<div class="connector-arrow"></div>';
      timeline.appendChild(conn);
    }

    const meta = node.metadata || {};
    const kind = node.kind || "unknown";
    const statusClass = meta.status === "error" ? " status-error" : "";

    const el = document.createElement("div");
    el.className = `timeline-node kind-${kind}${statusClass}`;
    el.dataset.nodeId = node.id;

    // Header
    const kindLabels = {
      api_call: "API Call",
      system_instruction: "System Prompt",
      prompt: "User Prompt",
      prompt_batch: "User Prompts",
      reasoning: "Reasoning",
      tool_step: "Tool Call",
      tool_output: "Tool Output",
      assistant_response: "Agent Response",
    };
    const kindLabel = kindLabels[kind] || kind;
    const duration = formatDuration(meta.duration_ms);

    let titleText = "";
    let bodyText = "";

    if (kind === "api_call") {
      titleText = `${meta.method || "POST"} ${meta.endpoint || "API"}`;
      const lineBits = [];
      if (meta.model) lineBits.push(`model=${meta.model}`);
      if (meta.reasoning) lineBits.push(`reasoning=${meta.reasoning}`);
      if (meta.status_code != null) lineBits.push(`status=${meta.status_code}`);
      bodyText = lineBits.join(" | ");
    } else if (kind === "system_instruction") {
      titleText = "System Instructions";
      bodyText = truncate(meta.content, 420);
    } else if (kind === "prompt") {
      titleText = "User Prompt";
      bodyText = truncate(meta.content);
    } else if (kind === "prompt_batch") {
      titleText = `User Prompts (${meta.count || 0})`;
      const prompts = Array.isArray(meta.prompts) ? meta.prompts : [];
      const preview = prompts.length > 0 ? truncate(prompts[0], 200) : "";
      bodyText = preview || `${meta.count || 0} prompts captured. Double-click to expand.`;
    } else if (kind === "tool_step") {
      titleText = meta.tool_name || "Tool";
      const args = meta.arguments || {};
      if (args.command) {
        bodyText = args.command;
      } else {
        bodyText = truncate(JSON.stringify(args));
      }
    } else if (kind === "tool_output") {
      titleText = `${meta.tool_name || "Tool"} Output`;
      bodyText = truncate(JSON.stringify(meta.result || {}), 420);
    } else if (kind === "reasoning") {
      titleText = "Reasoning Summary";
      bodyText = truncate(meta.content, 420);
    } else if (kind === "assistant_response") {
      titleText = "Agent Response";
      bodyText = truncate(meta.content);
    }

    let footerHtml = "";
    if (kind === "tool_step" || kind === "tool_output") {
      const statusBadge = meta.status === "error"
        ? '<span class="status-badge error">✗ Error</span>'
        : '<span class="status-badge ok">✓ Success</span>';
      footerHtml = `
        <div class="tnode-footer">
          ${statusBadge}
          <span class="drilldown-hint">Double-click to drill down</span>
        </div>`;
    }

    el.innerHTML = `
      <div class="tnode-header">
        <span class="tnode-step">Step ${idx + 1}</span>
        <span class="tnode-kind">${escapeHtml(kindLabel)}</span>
        ${duration ? `<span class="tnode-duration">${duration}</span>` : ""}
      </div>
      <div class="tnode-title">${escapeHtml(titleText)}</div>
      <div class="tnode-body">${kind === "prompt_batch" ? escapeHtml(bodyText) : `<code>${escapeHtml(bodyText)}</code>`}</div>
      ${footerHtml}`;

    // Click → show details + tool files
    el.addEventListener("click", async (e) => {
      e.stopPropagation();
      document.querySelectorAll(".timeline-node.selected").forEach((n) => n.classList.remove("selected"));
      el.classList.add("selected");
      selectedNodeId = node.id;
      renderDetails(node);

      // Show tool-specific files if available
      if (selectedTraceId && meta.tool_call_id) {
        try {
          const summary = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/tool-summary/${encodeURIComponent(meta.tool_call_id)}`);
          const files = summary.files || [];
          const net = summary.network || [];
          window._lastToolFiles = files;
          window._lastToolNetwork = net;
          if (files.length > 0 || net.length > 0) {
            renderFiles(files, `Files for: ${meta.tool_name || meta.tool_call_id}`, files.length, net);
          } else {
            // Fallback to trace-level files
            renderFiles(cachedTraceFiles, "No tool-specific files found — showing trace-level activity", cachedTraceFiles.length, window._cachedTraceNetwork);
          }
        } catch (_) {
          renderFiles(cachedTraceFiles, "Trace-level file activity", cachedTraceFiles.length, window._cachedTraceNetwork);
        }
      }
    });

    // Double-click → drill down into tool
    el.addEventListener("dblclick", async (e) => {
      e.stopPropagation();
      if (kind === "prompt_batch") {
        const prompts = Array.isArray(meta.prompts) ? meta.prompts : [];
        const bodyEl = el.querySelector(".tnode-body");
        if (!bodyEl) return;
        const expanded = el.classList.toggle("expanded");
        if (!expanded) {
          bodyEl.textContent = `${meta.count || 0} prompts captured. Double-click to expand.`;
          return;
        }
        const lines = prompts.map((p, i) => `${i + 1}. ${p}`).join("\n\n");
        bodyEl.innerHTML = `<code>${escapeHtml(lines || "No prompts")}</code>`;
        return;
      }

      if ((kind === "tool_step" || kind === "tool_call") && meta.tool_call_id) {
        await openToolDrilldown(meta.tool_call_id, meta.tool_name || meta.tool_call_id);
      }
    });

    timeline.appendChild(el);
  });

  graphCanvas.appendChild(timeline);
}


// ─── DAG Renderer (Tool Drilldown) ────────────────────────────────
function renderDAGGraph(payload) {

  graphCanvas.innerHTML = "";
  emptyState.style.display = "none";

  const nodes = payload.nodes || [];
  const edges = payload.edges || [];

  if (nodes.length === 0) {
    graphCanvas.innerHTML = '<div class="empty-state"><h3>No data</h3><p>No low-level events for this tool call.</p></div>';
    return;
  }

  // Node dimensions based on kind
  const nodeSizes = {
    tool_call: { w: 520, h: 80 },
    action: { w: 500, h: 72 },
    resource: { w: 480, h: 64 },
    folder_group: { w: 520, h: 80 },
    network: { w: 460, h: 64 },
    placeholder: { w: 420, h: 56 },
  };
  const defaultSize = { w: 460, h: 68 };

  // Build dagre graph
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: "TB", ranksep: 80, nodesep: 50, marginx: 40, marginy: 40 });
  g.setDefaultEdgeLabel(() => ({}));

  const nodeMap = {};
  for (const n of nodes) {
    const size = nodeSizes[n.kind] || defaultSize;
    g.setNode(n.id, { width: size.w, height: size.h, label: n.label });
    nodeMap[n.id] = n;
  }
  for (const e of edges) {
    g.setEdge(e.source, e.target, { label: e.label || "" });
  }

  dagre.layout(g);

  // Compute bounds
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  g.nodes().forEach((id) => {
    const n = g.node(id);
    const size = nodeSizes[nodeMap[id]?.kind] || defaultSize;
    minX = Math.min(minX, n.x - size.w / 2);
    minY = Math.min(minY, n.y - size.h / 2);
    maxX = Math.max(maxX, n.x + size.w / 2);
    maxY = Math.max(maxY, n.y + size.h / 2);
  });

  const pad = 60;
  const canvasW = maxX - minX + pad * 2;
  const canvasH = maxY - minY + pad * 2;
  const offX = -minX + pad;
  const offY = -minY + pad;

  const container = document.createElement("div");
  container.className = "dag-container";
  container.style.width = canvasW + "px";
  container.style.height = canvasH + "px";

  // SVG edges layer
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.classList.add("dag-edges");
  svg.setAttribute("width", canvasW);
  svg.setAttribute("height", canvasH);

  // Arrowhead marker
  const defs = document.createElementNS(ns, "defs");
  const marker = document.createElementNS(ns, "marker");
  marker.setAttribute("id", "arrowhead");
  marker.setAttribute("viewBox", "0 0 10 10");
  marker.setAttribute("refX", "9");
  marker.setAttribute("refY", "5");
  marker.setAttribute("markerWidth", "7");
  marker.setAttribute("markerHeight", "7");
  marker.setAttribute("orient", "auto-start-reverse");
  const arrow = document.createElementNS(ns, "path");
  arrow.setAttribute("d", "M 0 0 L 10 5 L 0 10 z");
  arrow.classList.add("dag-arrowhead");
  marker.appendChild(arrow);
  defs.appendChild(marker);
  svg.appendChild(defs);

  // Draw edges
  g.edges().forEach((e) => {
    const edgeData = g.edge(e);
    const srcNode = g.node(e.v);
    const tgtNode = g.node(e.w);
    const srcSize = nodeSizes[nodeMap[e.v]?.kind] || defaultSize;
    const tgtSize = nodeSizes[nodeMap[e.w]?.kind] || defaultSize;

    const sx = srcNode.x + offX;
    const sy = srcNode.y + offY + srcSize.h / 2;
    const tx = tgtNode.x + offX;
    const ty = tgtNode.y + offY - tgtSize.h / 2;

    const midY = (sy + ty) / 2;
    const d = `M ${sx} ${sy} C ${sx} ${midY}, ${tx} ${midY}, ${tx} ${ty}`;

    const path = document.createElementNS(ns, "path");
    path.setAttribute("d", d);
    path.classList.add("dag-edge-path");
    path.setAttribute("marker-end", "url(#arrowhead)");
    svg.appendChild(path);

    // Edge label
    if (edgeData.label) {
      const lx = (sx + tx) / 2;
      const ly = midY;
      const labelText = edgeData.label;

      // Background rect (approximate)
      const bgWidth = labelText.length * 6.5 + 10;
      const bg = document.createElementNS(ns, "rect");
      bg.setAttribute("x", lx - bgWidth / 2);
      bg.setAttribute("y", ly - 8);
      bg.setAttribute("width", bgWidth);
      bg.setAttribute("height", 16);
      bg.setAttribute("rx", 3);
      bg.classList.add("dag-edge-label-bg");
      svg.appendChild(bg);

      const text = document.createElementNS(ns, "text");
      text.setAttribute("x", lx);
      text.setAttribute("y", ly + 4);
      text.classList.add("dag-edge-label");
      text.textContent = labelText;
      svg.appendChild(text);
    }
  });

  container.appendChild(svg);

  // Render nodes
  g.nodes().forEach((id) => {
    const pos = g.node(id);
    const data = nodeMap[id];
    if (!data) return;
    const size = nodeSizes[data.kind] || defaultSize;

    const el = document.createElement("div");
    el.className = `dag-node kind-${data.kind || "unknown"}`;
    el.style.width = size.w + "px";
    el.style.height = size.h + "px";
    el.style.left = (pos.x + offX - size.w / 2) + "px";
    el.style.top = (pos.y + offY - size.h / 2) + "px";
    el.dataset.nodeId = id;

    const kindLabels = { tool_call: "Tool Call", action: "Command", resource: "File", folder_group: "📁 Folder", network: "🌐 Network", placeholder: "Info" };
    const kindLabel = kindLabels[data.kind] || data.kind;

    const displayLabel = (data.label || "").length > 100 ? data.label.slice(0, 100) + "…" : (data.label || id);

    const meta = data.metadata || {};
    let extraHtml = "";
    if (data.kind === "folder_group" && meta.children) {
      extraHtml = `<div class="expand-hint">▶ Click to expand ${meta.children.length} items</div>`;
    }

    el.innerHTML = `
      <div class="dag-node-kind">${escapeHtml(kindLabel)}</div>
      <div class="dag-node-label">${escapeHtml(displayLabel)}</div>
      ${extraHtml}`;

    el.addEventListener("click", (ev) => {
      ev.stopPropagation();
      document.querySelectorAll(".dag-node.selected").forEach((n) => n.classList.remove("selected"));
      el.classList.add("selected");
      selectedNodeId = id;

      if (data.kind === "folder_group" && meta.children && meta.children.length > 0) {
        expandFolderGroup(data, payload);
        return;
      }
      renderDetails(data);
    });

    container.appendChild(el);
  });

  graphCanvas.appendChild(container);
}

// ─── Folder Group Expansion ───────────────────────────────────────
function expandFolderGroup(folderNode, payload) {
  const meta = folderNode.metadata || {};
  const children = meta.children || [];
  if (children.length === 0) return;

  // Build new node/edge lists replacing the folder group with its children
  const newNodes = [];
  const newEdges = [];
  const folderNodeId = folderNode.id;

  // Copy existing nodes, skip the folder group being expanded
  for (const n of payload.nodes) {
    if (n.id !== folderNodeId) {
      newNodes.push(n);
    }
  }

  // Determine effective children: if > 3 folders, sub-group; if > 3 files, group files
  let effectiveChildren = children;

  if (children.length > 6) {
    const folders = children.filter((c) => c.kind === "folder_group");
    const resources = children.filter((c) => c.kind !== "folder_group");

    effectiveChildren = [...folders];

    if (resources.length > 3) {
      const first = resources[0];
      const remaining = resources.length - 1;
      effectiveChildren.push({
        kind: "folder_group",
        label: `📄 ${first.label || first.path || "file"} + ${remaining} other file${remaining !== 1 ? "s" : ""}`,
        metadata: {
          file_count: resources.length,
          children: resources.map((r) => ({
            kind: r.kind || "resource",
            label: r.label,
            metadata: r.metadata || {},
          })),
        },
      });
    } else {
      effectiveChildren.push(...resources);
    }
  }

  // Add child nodes (can be resource or folder_group)
  const childIds = [];
  for (let i = 0; i < effectiveChildren.length; i++) {
    const child = effectiveChildren[i];
    const childId = `${folderNodeId}_child_${i}`;
    childIds.push(childId);
    newNodes.push({
      id: childId,
      kind: child.kind || "resource",
      label: child.label || child.path || `child_${i}`,
      metadata: child.metadata || child,
    });
  }

  // Rewire edges: edges that pointed to/from the folder group now point to/from children
  for (const e of payload.edges) {
    if (e.target === folderNodeId) {
      // Edge coming into the folder → fan out to all children
      for (const cid of childIds) {
        newEdges.push({ source: e.source, target: cid, label: "" });
      }
    } else if (e.source === folderNodeId) {
      // Edge going out of the folder → fan in from all children
      for (const cid of childIds) {
        newEdges.push({ source: cid, target: e.target, label: "" });
      }
    } else {
      newEdges.push(e);
    }
  }

  const newPayload = { nodes: newNodes, edges: newEdges, _preprocessed: true };
  renderDAGGraph(newPayload);
}

// ─── Syscall-Only Timeline Renderer ────────────────────────────────
function renderSyscallTimeline(payload) {
  graphCanvas.innerHTML = "";
  emptyState.style.display = "none";

  const nodes = payload.nodes || [];
  if (nodes.length === 0) {
    graphCanvas.innerHTML = '<div class="empty-state"><h3>No system events</h3><p>No recognizable syscall command events were found.</p></div>';
    return;
  }

  // Banner
  const banner = document.createElement("div");
  banner.className = "syscall-mode-banner";
  banner.textContent = "System-call-only mode - no agent trajectory available. Showing system-level command timeline.";

  const timeline = document.createElement("div");
  timeline.className = "timeline";

  nodes.forEach((node, idx) => {
    // Connector
    if (idx > 0) {
      const conn = document.createElement("div");
      conn.className = "timeline-connector";
      conn.innerHTML = '<div class="connector-arrow"></div>';
      timeline.appendChild(conn);
    }

    const meta = node.metadata || {};
    const kind = node.kind || "unknown";

    const el = document.createElement("div");
    el.className = `timeline-node kind-${kind}`;
    el.dataset.nodeId = node.id;

    const kindLabel = kind === "sys_command" ? "System Command" : (kind === "placeholder" ? "Info" : kind);

    let titleText = "";
    let bodyText = "";

    if (kind === "sys_command") {
      const execPath = meta.exec_path || "";
      const base = execPath.split("/").pop() || "exec";
      titleText = base;
      const argv = meta.argv || [];
      bodyText = argv.length > 0 ? argv.join(" ") : (meta.command || node.label || "");
      if (bodyText.length > 200) bodyText = bodyText.slice(0, 200) + "…";
    } else {
      titleText = node.label || node.id;
      bodyText = "";
    }

    // Badges for files & network
    let badgesHtml = "";
    if (kind === "sys_command") {
      const badges = [];
      if (meta.pid) badges.push(`<span class="tnode-badge pid">PID ${meta.pid}</span>`);
      if (meta.file_count > 0) badges.push(`<span class="tnode-badge files">📄 ${meta.file_count} file${meta.file_count !== 1 ? "s" : ""}</span>`);
      if (meta.net_count > 0) badges.push(`<span class="tnode-badge net">🌐 ${meta.net_count} endpoint${meta.net_count !== 1 ? "s" : ""}</span>`);
      if (badges.length > 0) {
        badgesHtml = `<div class="tnode-badges">${badges.join("")}</div>`;
      }
    }

    el.innerHTML = `
      <div class="tnode-header">
        <span class="tnode-step">${kind === "placeholder" ? "" : "Cmd " + (idx + 1)}</span>
        <span class="tnode-kind">${escapeHtml(kindLabel)}</span>
      </div>
      <div class="tnode-title">${escapeHtml(titleText)}</div>
      ${bodyText ? `<div class="tnode-body"><code>${escapeHtml(bodyText)}</code></div>` : ""}
      ${badgesHtml}`;

    // Click → show details
    el.addEventListener("click", (e) => {
      e.stopPropagation();
      document.querySelectorAll(".timeline-node.selected").forEach((n) => n.classList.remove("selected"));
      el.classList.add("selected");
      selectedNodeId = node.id;
      renderDetails(node);
    });

    timeline.appendChild(el);
  });

  graphCanvas.appendChild(banner);
  graphCanvas.appendChild(timeline);
}

function renderTaintAnalysis(report) {
  graphCanvas.innerHTML = "";
  emptyState.style.display = "none";

  const findings = Array.isArray(report.findings) ? report.findings : [];
  const entities = Array.isArray(report.tainted_entities) ? report.tainted_entities : [];
  const flows = Array.isArray(report.taint_flows) ? report.taint_flows : [];

  const sevBadge = (sev) => {
    const safe = String(sev || "info");
    return `<span class="sev sev-${escapeHtml(safe)}">${escapeHtml(safe)}</span>`;
  };

  const wrap = document.createElement("div");
  wrap.className = "taint-wrap";

  const summaryCard = document.createElement("section");
  summaryCard.className = "taint-card";
  summaryCard.innerHTML = `
    <div class="taint-card-head">
      <span>Analysis Summary</span>
      <span class="tag">Trace: ${escapeHtml(report.trace_id || selectedTraceId || "")}</span>
    </div>
    <div class="taint-card-body">
      <div class="taint-summary">${escapeHtml(String(report.summary || "No summary available."))}</div>
    </div>`;
  wrap.appendChild(summaryCard);

  const findingsCard = document.createElement("section");
  findingsCard.className = "taint-card";
  let findingsBody = '<div class="taint-empty">No taint findings detected.</div>';
  if (findings.length > 0) {
    findingsBody = `
      <div class="taint-table-wrap">
        <table class="taint-table">
          <thead>
            <tr><th>Severity</th><th>Title</th><th>Description</th><th>Source Seq</th><th>Sink Seq</th></tr>
          </thead>
          <tbody>
            ${findings.map((f) => `
              <tr>
                <td>${sevBadge(f.severity)}</td>
                <td>${escapeHtml(String(f.title || ""))}</td>
                <td>${escapeHtml(String(f.description || ""))}</td>
                <td>${escapeHtml(String(f.source_event_seq ?? "-"))}</td>
                <td>${escapeHtml(String(f.sink_event_seq ?? "-"))}</td>
              </tr>`).join("")}
          </tbody>
        </table>
      </div>`;
  }
  findingsCard.innerHTML = `<div class="taint-card-head">Findings <span class="tag">${findings.length}</span></div><div class="taint-card-body">${findingsBody}</div>`;
  wrap.appendChild(findingsCard);

  const entitiesCard = document.createElement("section");
  entitiesCard.className = "taint-card";
  let entitiesBody = '<div class="taint-empty">No tainted entities recorded.</div>';
  if (entities.length > 0) {
    entitiesBody = `<div class="taint-list">${entities.map((e) => {
      const title = e.type === "file" ? (e.path || "file") : (e.id || "tool_result");
      const meta = [
        `type=${String(e.type || "-")}`,
        `label=${String(e.label || "-")}`,
        e.provenance ? `provenance=${String(e.provenance)}` : "",
      ].filter(Boolean).join(" | ");
      return `<div class="taint-item"><div class="name">${escapeHtml(String(title))}</div><div class="meta">${escapeHtml(meta)}</div></div>`;
    }).join("")}</div>`;
  }
  entitiesCard.innerHTML = `<div class="taint-card-head">Tainted Entities <span class="tag">${entities.length}</span></div><div class="taint-card-body">${entitiesBody}</div>`;
  wrap.appendChild(entitiesCard);

  const flowsCard = document.createElement("section");
  flowsCard.className = "taint-card";
  let flowsBody = '<div class="taint-empty">No taint flows captured.</div>';
  if (flows.length > 0) {
    flowsBody = `
      <div class="taint-table-wrap">
        <table class="taint-table">
          <thead>
            <tr><th>From</th><th>To</th><th>Reason</th></tr>
          </thead>
          <tbody>
            ${flows.map((f) => `
              <tr>
                <td>${escapeHtml(String(f.from || ""))}</td>
                <td>${escapeHtml(String(f.to || ""))}</td>
                <td>${escapeHtml(String(f.reason || ""))}</td>
              </tr>`).join("")}
          </tbody>
        </table>
      </div>`;
  }
  flowsCard.innerHTML = `<div class="taint-card-head">Taint Flows <span class="tag">${flows.length}</span></div><div class="taint-card-body">${flowsBody}</div>`;
  wrap.appendChild(flowsCard);

  graphCanvas.appendChild(wrap);
}

function ensureBlastBaselines() {
  const traceIds = (cachedTraces || []).map((t) => t.trace_id).filter(Boolean);
  const filtered = new Set();
  for (const id of selectedBlastBaselines) {
    if (traceIds.includes(id) && id !== selectedTraceId) filtered.add(id);
  }
  selectedBlastBaselines = filtered;

  if (selectedBlastBaselines.size === 0) {
    for (const id of traceIds) {
      if (id !== selectedTraceId) selectedBlastBaselines.add(id);
    }
  }
}

function renderBlastAnalysis(report) {
  graphCanvas.innerHTML = "";

  const wrap = document.createElement("div");
  wrap.className = "taint-wrap";

  const controls = document.createElement("section");
  controls.className = "taint-card";
  const candidateOptions = (cachedTraces || [])
    .map((t) => {
      const selected = t.trace_id === selectedTraceId ? "selected" : "";
      return `<option value="${escapeHtml(t.trace_id)}" ${selected}>${escapeHtml(t.trace_id)}</option>`;
    })
    .join("");
  const options = (cachedTraces || [])
    .filter((t) => t.trace_id !== selectedTraceId)
    .map((t) => {
      const checked = selectedBlastBaselines.has(t.trace_id) ? "checked" : "";
      return `<label style="display:inline-flex;align-items:center;gap:6px;margin:4px 10px 4px 0;font-size:12px;color:var(--text-secondary);"><input type="checkbox" data-baseline-id="${escapeHtml(t.trace_id)}" ${checked}/> ${escapeHtml(t.trace_id)}</label>`;
    })
    .join("");

  controls.innerHTML = `
    <div class="taint-card-head">Blast Radius Controls <span class="tag">Candidate: ${escapeHtml(selectedTraceId || "-")}</span></div>
    <div class="taint-card-body">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
        <label for="blastCandidateSelect" style="font-size:12px;color:var(--text-secondary);font-weight:600;">Candidate trace</label>
        <select id="blastCandidateSelect" class="file-filter" style="margin:0;max-width:520px;display:block;">
          ${candidateOptions}
        </select>
      </div>
      <div style="font-size:12px;color:var(--text-secondary);margin-bottom:8px;">Choose baseline training traces used to build the semantic template.</div>
      <div>${options || '<div class="taint-empty" style="padding:0;text-align:left;">No other traces available as baselines.</div>'}</div>
    </div>`;
  wrap.appendChild(controls);

  const candidateSelect = controls.querySelector("#blastCandidateSelect");
  if (candidateSelect) {
    candidateSelect.addEventListener("change", async (ev) => {
      const id = String(ev.target.value || "").trim();
      if (!id || id === selectedTraceId) return;
      await selectTrace(id);
    });
  }

  controls.querySelectorAll("input[data-baseline-id]").forEach((el) => {
    el.addEventListener("change", async (ev) => {
      const id = ev.target.getAttribute("data-baseline-id");
      if (!id) return;
      if (ev.target.checked) selectedBlastBaselines.add(id);
      else selectedBlastBaselines.delete(id);
      await loadBlastAnalysis();
    });
  });

  const deviations = report.deviations || [];
  const rows = report.rows || [];

  const card = document.createElement("section");
  card.className = "taint-card";
  let body = '<div class="taint-empty">No diff rows available.</div>';
  if (rows.length > 0) {
    body = `
      <div class="taint-table-wrap">
        <table class="taint-table">
          <thead>
            <tr><th>#</th><th>Status</th><th>Expected</th><th>Observed</th><th>Evidence</th></tr>
          </thead>
          <tbody>
            ${rows.map((r) => {
              const expected = r.expected?.label || r.expected?.key || "-";
              const observed = r.observed?.label || r.observed?.key || "-";
              const sev = r.severity || "info";
              const statusCls = sev === "high" ? "sev-critical" : sev === "medium" ? "sev-warning" : "sev-info";
              const evidence = r.observed ? `line ${Number(r.observed.line_no || 0)} · ${escapeHtml(String(r.observed.source || ""))}` : "-";
              return `<tr>
                <td>${Number(r.index) + 1}</td>
                <td><span class="sev ${statusCls}">${escapeHtml(String(r.status || "match"))}</span></td>
                <td>${escapeHtml(String(expected))}</td>
                <td>${escapeHtml(String(observed))}<div class="muted" style="font-size:11px;margin-top:2px;">${escapeHtml(String(r.reason || ""))}</div></td>
                <td>${evidence}</td>
              </tr>`;
            }).join("")}
          </tbody>
        </table>
      </div>`;
  }
  card.innerHTML = `<div class="taint-card-head">Template Diff <span class="tag">${deviations.length} deviations</span></div><div class="taint-card-body">${body}</div>`;
  wrap.appendChild(card);

  graphCanvas.appendChild(wrap);
}

// ─── Loaders ──────────────────────────────────────────────────────
async function loadHighLevelGraph() {
  if (!selectedTraceId) return;
  renderBreadcrumbs();
  const payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/high-level-graph`);

  if (payload.mode === "git_tree") {
    currentSyscallMode = false;
    updateSummaryCards(payload.summary || {});
    renderGitTreeGraph(payload);
  } else if (payload.mode === "syscall_only") {
    currentSyscallMode = true;
    updateSummaryCards(payload.summary || {});
    renderSyscallTimeline(payload);
  } else {
    currentSyscallMode = false;
    updateSummaryCards(payload.summary || {});
    renderHighLevelGraph(payload);
  }
}

async function loadProcessGraph(pid) {
  if (!selectedTraceId || !pid) return;
  renderBreadcrumbs();
  const payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/process-graph/${encodeURIComponent(pid)}`);
  currentSyscallMode = false;
  updateSummaryCards(payload.summary || {});
  renderGitTreeGraph(payload);
}

async function loadInternalGraph(lineStart, lineEnd) {
  if (!selectedTraceId) return;
  renderBreadcrumbs();
  const payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/internal-graph/${encodeURIComponent(lineStart)}/${encodeURIComponent(lineEnd)}`);
  currentSyscallMode = false;
  updateSummaryCards(payload.summary || {});
  renderGitTreeGraph(payload);
}

async function loadToolGraph(toolCallId) {
  if (!selectedTraceId) return;
  renderBreadcrumbs();
  const payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/tool-graph/${encodeURIComponent(toolCallId)}`);
  if (payload.mode === "git_tree") {
    renderGitTreeGraph(payload);
    return;
  }
  renderDAGGraph(payload);
}

async function loadTaintAnalysis() {
  if (!selectedTraceId) return;
  renderBreadcrumbs();
  const report = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/taint-analysis`);
  taintReportCache = report;
  currentSyscallMode = false;
  updateSummaryCardsTaint(report);
  renderTaintAnalysis(report);
}

async function loadBlastAnalysis() {
  if (!selectedTraceId) return;
  renderBreadcrumbs();
  ensureBlastBaselines();
  const baselineIds = Array.from(selectedBlastBaselines);
  if (baselineIds.length === 0) {
    graphCanvas.innerHTML = `<div class="empty-state"><h3>Not enough training traces</h3><p>Select at least one baseline trace to compare against <code>${escapeHtml(selectedTraceId)}</code>.</p></div>`;
    updateSummaryCardsBlast({ baseline_ids: [], summary: { rows: 0, deviations: 0, deviation_score: 0 } });
    return;
  }
  const params = new URLSearchParams({
    candidate_id: selectedTraceId,
    baseline_ids: baselineIds.join(","),
  });
  const report = await api(`/api/blast-radius/compare?${params.toString()}`);
  currentSyscallMode = false;
  updateSummaryCardsBlast(report);
  renderBlastAnalysis(report);
}

async function loadTraceSummary() {
  if (!selectedTraceId) return;
  try {
    const summary = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/summary`);
    cachedTraceFiles = summary.files || [];
    renderTools(summary.tools || []);
    window._cachedTraceNetwork = summary.network || [];
    const total = summary.totals?.unique_files ?? cachedTraceFiles.length;
    renderFiles(cachedTraceFiles, "Trace-level file activity", total, window._cachedTraceNetwork);
  } catch {
    cachedTraceFiles = [];
    renderTools([]);
    window._cachedTraceNetwork = [];
    renderFiles([], "Unable to load file summary.");
  }
}

// ─── Refresh / Polling ────────────────────────────────────────────
async function refreshTraces(keepView = true, force = false) {
  const payload = await api("/api/traces");
  const version = payload.version ?? 0;

  if (keepView && !force && version === latestVersion) return;
  latestVersion = version;

  const traces = payload.traces || [];
  const selectedExists = selectedTraceId && traces.some((t) => t.trace_id === selectedTraceId);
  if (selectedTraceId && !selectedExists) {
    selectedTraceId = null;
  }
  if (!selectedTraceId && traces.length > 0) {
    selectedTraceId = traces[0].trace_id;
  }

  renderTraceList(traces);
  if (!selectedTraceId) {
    clearSelectionView();
    return;
  }

  if (activeTab === "trace") {
    if (!keepView || currentMode === "high") {
      await loadHighLevelGraph();
    } else if (currentToolCallId) {
      await loadToolGraph(currentToolCallId);
    } else if (currentMode === "internal" && currentInternalRange) {
      await loadInternalGraph(currentInternalRange.start, currentInternalRange.end);
    } else if (currentMode === "process" && currentProcessPid) {
      await loadProcessGraph(currentProcessPid);
    }
  } else if (activeTab === "taint") {
    await loadTaintAnalysis();
  } else {
    await loadBlastAnalysis();
  }
  await loadTraceSummary();
}

// ─── Init ─────────────────────────────────────────────────────────
async function init() {
  setToolsExpanded(false);
  setFilesExpanded(false);
  setSelectionExpanded(false);
  traceTabBtn.addEventListener("click", async () => {
    if (activeTab === "trace") return;
    setActiveTab("trace");
    await loadHighLevelGraph();
    await loadTraceSummary();
  });
  taintTabBtn.addEventListener("click", async () => {
    if (activeTab === "taint") return;
    setActiveTab("taint");
    await loadTaintAnalysis();
    await loadTraceSummary();
  });
  blastTabBtn.addEventListener("click", async () => {
    if (activeTab === "blast") return;
    setActiveTab("blast");
    await loadBlastAnalysis();
    await loadTraceSummary();
  });

  await refreshTraces(false);

  // Polling fallback
  setInterval(async () => {
    try { await refreshTraces(true); } catch (_) { }
  }, 3000);

  // WebSocket for live updates
  try {
    const protocol = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${protocol}://${location.host}/ws`);
    ws.onmessage = async (evt) => {
      const msg = JSON.parse(evt.data);
      if (msg.type === "version" && typeof msg.version === "number" && msg.version !== latestVersion) {
        await refreshTraces(true, true);
      }
    };
    ws.onerror = () => ws.close();
  } catch (_) { }
}

init();
