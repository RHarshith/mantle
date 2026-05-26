/* Agent Trace Observatory - Turn-first dashboard */

let selectedTraceId = null;
let cachedTraces = [];
let latestVersion = -1;
let activeTab = "profiler";
let tokenProfileChart = null;
let replayOverview = null;
let currentReplayTurnId = null;
let currentReplayPaneTab = "context";
let replayViewMode = "turn";
let replayStateDiffData = null;
let replayStateDiffFilePath = "";
let replayStateDiffFromTurnId = null;
let replayStateDiffToTurnId = null;
let currentReplayToolSourceIndex = [];
let replaySourceByToolCallId = new Map();
let replaySourceByResultText = new Map();
let replaySourceMapTraceId = null;
let replayRawTraceViewerState = { turnId: null, pid: null, stack: [] };
let popupTraceViewerState = {
  turnId: null,
  pid: null,
  stack: [],
  startTimestamp: null,
  endTimestamp: null,
  title: "tool output",
  anomaly: null,
};
const TRACE_HIDDEN_EVENT_TYPES_STORAGE_KEY = "mantle.trace.hiddenEventTypes";
const DEFAULT_COMPACT_TRACE_HIDDEN_EVENT_TYPES = ["fd_open", "fd_close", "fd_write", "fd_write_ret"];
let compactTraceHiddenEventTypes = [];
let detailedTraceViewEnabled = false;

let traceProcessMap = {};
let processNames = ["default"];

let turnsOverview = null;
let currentTurnId = null;
let viewStack = [];

const $ = (id) => document.getElementById(id);
const traceListEl = $("traceList");
const breadcrumbsEl = $("breadcrumbs");
const graphWrapper = $("graphWrapper");
const graphCanvas = $("graphCanvas");
const detailsEl = $("details");
const profilerTabBtn = $("profilerTabBtn");
const replayTabBtn = $("replayTabBtn");
const addProcessBtn = $("addProcessBtn");
const fileToggle = $("fileToggle");
const toolsToggle = $("toolsToggle");
const selectionToggle = $("selectionToggle");
const fileSectionBody = $("fileSectionBody");
const toolsSectionBody = $("toolsSectionBody");
const selectionSectionBody = $("selectionSectionBody");
const fileCaret = $("fileCaret");
const toolsCaret = $("toolsCaret");
const selectionCaret = $("selectionCaret");
const zoomInBtn = $("zoomInBtn");
const zoomOutBtn = $("zoomOutBtn");
const fitBtn = $("fitBtn");

function postFrontendRuntimeLog(level, message, details) {
  const payload = {
    level: String(level || "error"),
    message: String(message || "frontend runtime error"),
    request_id: `${Date.now()}`,
    details: details || {},
  };

  fetch("/api/frontend-log", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  }).catch(() => {
    // Avoid recursive logging on network failures.
  });
}

window.addEventListener("error", (event) => {
  postFrontendRuntimeLog("error", event.message || "window.error", {
    file: event.filename || "",
    line: event.lineno || 0,
    column: event.colno || 0,
  });
});

window.addEventListener("unhandledrejection", (event) => {
  const reason = event.reason;
  const message = reason && reason.message ? reason.message : String(reason || "unhandled rejection");
  postFrontendRuntimeLog("error", message, { source: "unhandledrejection" });
});

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = String(value ?? "");
  return div.innerHTML;
}

function truncateLines(value, maxLines = 3) {
  const lines = String(value ?? "").split("\n");
  const short = lines.slice(0, maxLines).join("\n");
  return {
    short,
    long: lines.join("\n"),
    truncated: lines.length > maxLines,
  };
}

function formatNumber(n) {
  return Number(n || 0).toLocaleString();
}

function formatMs(ms) {
  if (ms == null) return "-";
  const n = Number(ms);
  if (!Number.isFinite(n)) return "-";
  if (n < 1000) return `${Math.round(n)}ms`;
  return `${(n / 1000).toFixed(2)}s`;
}

function normalizeAnomaly(anomaly) {
  const fallback = {
    verdict: "CLEAN",
    has_anomaly: false,
    summary: "verified tool call",
    total_violations: 0,
    severity_counts: { LOW: 0, MEDIUM: 0, HIGH: 0 },
  };
  if (!anomaly || typeof anomaly !== "object") {
    return fallback;
  }

  const verdict = String(anomaly.verdict || anomaly.anomaly_verdict || "CLEAN").toUpperCase();
  const hasAnomaly = ("has_anomaly" in anomaly)
    ? Boolean(anomaly.has_anomaly)
    : (("anomaly_detected" in anomaly) ? Boolean(anomaly.anomaly_detected) : verdict !== "CLEAN");
  const severityCounts = anomaly.severity_counts && typeof anomaly.severity_counts === "object"
    ? {
        LOW: Number(anomaly.severity_counts.LOW || 0),
        MEDIUM: Number(anomaly.severity_counts.MEDIUM || 0),
        HIGH: Number(anomaly.severity_counts.HIGH || 0),
      }
    : { LOW: 0, MEDIUM: 0, HIGH: 0 };

  return {
    verdict,
    has_anomaly: hasAnomaly,
    summary: String(anomaly.summary || (hasAnomaly ? "anomaly detected" : "verified tool call")),
    total_violations: Number(anomaly.total_violations || 0),
    severity_counts: severityCounts,
  };
}

function anomalyIndicatorHtml(anomaly, extraClass = "") {
  const normalized = normalizeAnomaly(anomaly);
  const isAnomaly = Boolean(normalized.has_anomaly || normalized.verdict !== "CLEAN");
  const title = isAnomaly ? "anomaly detected" : "verified tool call";
  const tone = isAnomaly ? "anomaly" : "verified";
  const classes = ["anomaly-indicator", tone, extraClass].filter(Boolean).join(" ");
  return `<span class="${classes}" title="${title}" aria-label="${title}"></span>`;
}

function loadCompactTraceHiddenEventTypes() {
  try {
    const raw = localStorage.getItem(TRACE_HIDDEN_EVENT_TYPES_STORAGE_KEY);
    if (!raw) {
      return [...DEFAULT_COMPACT_TRACE_HIDDEN_EVENT_TYPES];
    }
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [...DEFAULT_COMPACT_TRACE_HIDDEN_EVENT_TYPES];
    }
    const normalized = parsed
      .map((value) => String(value || "").trim().toLowerCase())
      .filter((value) => value.length > 0);
    return normalized.length ? normalized : [];
  } catch (_err) {
    return [...DEFAULT_COMPACT_TRACE_HIDDEN_EVENT_TYPES];
  }
}

function saveCompactTraceHiddenEventTypes(values) {
  compactTraceHiddenEventTypes = Array.isArray(values)
    ? values.map((value) => String(value || "").trim().toLowerCase()).filter((value) => value.length > 0)
    : [];
  localStorage.setItem(TRACE_HIDDEN_EVENT_TYPES_STORAGE_KEY, JSON.stringify(compactTraceHiddenEventTypes));
}

function activeHiddenTraceEventTypes() {
  if (detailedTraceViewEnabled) {
    return new Set();
  }
  return new Set(compactTraceHiddenEventTypes.map((value) => String(value || "").trim().toLowerCase()).filter(Boolean));
}

function compactHiddenEventsLabel() {
  if (!compactTraceHiddenEventTypes.length) {
    return "none";
  }
  return compactTraceHiddenEventTypes.join(", ");
}

function editCompactTraceHiddenEventTypes() {
  const current = compactTraceHiddenEventTypes.join(", ");
  const next = window.prompt(
    "Compact mode hidden event types (comma-separated). Example: fd_open, fd_close",
    current
  );
  if (next == null) {
    return false;
  }
  const parsed = String(next)
    .split(",")
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
  saveCompactTraceHiddenEventTypes(parsed);
  return true;
}

function entryEventType(entry) {
  if (!entry || entry.entry_type !== "system_group" || entry.category !== "other") {
    return "";
  }
  const event = entry.event || {};
  return String(event.type || event.event_type || "").trim().toLowerCase();
}

function filterDisplayTraceTimeline(timeline, hiddenEventTypes) {
  const hidden = hiddenEventTypes instanceof Set ? hiddenEventTypes : new Set();
  if (!hidden.size) {
    return Array.isArray(timeline) ? timeline : [];
  }
  const rows = Array.isArray(timeline) ? timeline : [];
  return rows.filter((entry) => {
    const type = entryEventType(entry);
    if (!type) {
      return true;
    }
    return !hidden.has(type);
  });
}

function isFileSystemGroupEntry(entry) {
  return Boolean(entry && entry.entry_type === "system_group" && entry.category === "file");
}

function mergeFileState(current, incoming) {
  const a = String(current || "").trim();
  const b = String(incoming || "").trim();
  if (!a) return b || "read";
  if (!b) return a;
  if (a === b) return a;
  if (a === "read_write" || b === "read_write") return "read_write";
  if ((a === "read" && b === "write") || (a === "write" && b === "read")) return "read_write";
  return a;
}

function cloneFileTreeNode(node) {
  if (!node || typeof node !== "object") {
    return node;
  }
  const cloned = { ...node };
  if (node.counts && typeof node.counts === "object") {
    cloned.counts = { ...node.counts };
  }
  if (Array.isArray(node.children)) {
    cloned.children = node.children.map((child) => cloneFileTreeNode(child));
  }
  return cloned;
}

function mergeCountObjects(baseCounts, incomingCounts) {
  const out = { ...(baseCounts || {}) };
  const source = incomingCounts && typeof incomingCounts === "object" ? incomingCounts : {};
  for (const [key, value] of Object.entries(source)) {
    out[key] = Number(out[key] || 0) + Number(value || 0);
  }
  return out;
}

function mergeFileTreeInto(targetNode, sourceNode) {
  if (!targetNode || !sourceNode || sourceNode.kind !== "dir") {
    return;
  }
  targetNode.counts = mergeCountObjects(targetNode.counts, sourceNode.counts);
  if (!Array.isArray(targetNode.children)) {
    targetNode.children = [];
  }

  for (const child of sourceNode.children || []) {
    if (!child || typeof child !== "object") {
      continue;
    }

    if (child.kind === "file") {
      const childPath = String(child.path || "");
      const childName = String(child.name || "");
      const existingFile = targetNode.children.find((node) =>
        node && node.kind === "file" && (
          (childPath && String(node.path || "") === childPath) ||
          (!childPath && String(node.name || "") === childName)
        )
      );
      if (!existingFile) {
        targetNode.children.push(cloneFileTreeNode(child));
      } else {
        existingFile.state = mergeFileState(existingFile.state, child.state);
      }
      continue;
    }

    if (child.kind === "dir") {
      const childName = String(child.name || "");
      let existingDir = targetNode.children.find((node) =>
        node && node.kind === "dir" && String(node.name || "") === childName
      );
      if (!existingDir) {
        existingDir = {
          kind: "dir",
          name: childName,
          counts: {},
          children: [],
        };
        targetNode.children.push(existingDir);
      }
      mergeFileTreeInto(existingDir, child);
    }
  }

  targetNode.children.sort((a, b) => {
    const aIsDir = a && a.kind === "dir";
    const bIsDir = b && b.kind === "dir";
    if (aIsDir !== bIsDir) {
      return aIsDir ? -1 : 1;
    }
    return String((a && a.name) || "").localeCompare(String((b && b.name) || ""));
  });
}

function mergeFileTrees(trees) {
  const validTrees = Array.isArray(trees) ? trees.filter((node) => node && node.kind === "dir") : [];
  if (!validTrees.length) {
    return null;
  }
  const mergedRoot = {
    kind: "dir",
    name: String(validTrees[0].name || "/"),
    counts: {},
    children: [],
  };
  for (const tree of validTrees) {
    mergeFileTreeInto(mergedRoot, tree);
  }
  return mergedRoot;
}

function countFilesInTree(tree) {
  if (!tree || typeof tree !== "object") {
    return 0;
  }
  if (tree.kind === "file") {
    return 1;
  }
  if (!Array.isArray(tree.children)) {
    return 0;
  }
  let total = 0;
  for (const child of tree.children) {
    total += countFilesInTree(child);
  }
  return total;
}

function openDebugInfoPopup(title, data) {
  openReplayMetricsPopup(String(title || "Debug Info"), "Rendered event payload", (body) => {
    const pre = document.createElement("pre");
    pre.className = "mono-block";
    pre.textContent = JSON.stringify(data ?? {}, null, 2);
    body.appendChild(pre);
  });
}

function mergeConsecutiveFileGroups(groups) {
  const entries = Array.isArray(groups) ? groups.filter(Boolean) : [];
  if (!entries.length) {
    return null;
  }
  if (entries.length === 1) {
    return entries[0];
  }

  const first = entries[0];
  const merged = {
    ...first,
    title: String(first.title || "File activity"),
    counts: {},
    tree: mergeFileTrees(entries.map((entry) => entry.tree).filter(Boolean)),
    standalone: false,
  };
  for (const entry of entries) {
    merged.counts = mergeCountObjects(merged.counts, entry.counts);
  }
  const mergedFileCount = countFilesInTree(merged.tree);
  if (mergedFileCount > 0) {
    merged.title = `${mergedFileCount} ${mergedFileCount === 1 ? "file" : "files"} touched`;
  }
  return merged;
}

function coalesceConsecutiveFileGroups(timeline) {
  const rows = Array.isArray(timeline) ? timeline : [];
  const out = [];
  let run = [];

  const flush = () => {
    if (!run.length) return;
    out.push(mergeConsecutiveFileGroups(run));
    run = [];
  };

  for (const entry of rows) {
    if (isFileSystemGroupEntry(entry)) {
      run.push(entry);
      continue;
    }
    flush();
    out.push(entry);
  }
  flush();
  return out;
}

function toneClass(tag) {
  if (tag === "read and plan") return "pill-amber";
  if (tag === "edit") return "pill-red";
  if (tag === "execute") return "pill-gray";
  if (tag === "network") return "pill-blue";
  if (tag === "response") return "pill-teal";
  return "pill-gray";
}

compactTraceHiddenEventTypes = loadCompactTraceHiddenEventTypes();

function systemTone(category) {
  if (category === "file") return "row-file";
  if (category === "network") return "row-network";
  if (category === "process") return "row-process";
  return "row-process";
}

function api(path) {
  return fetch(path).then((res) => {
    if (!res.ok) {
      throw new Error(`API ${res.status}`);
    }
    return res.json();
  });
}

function setCollapsed(sectionBody, caret, collapsed) {
  sectionBody.style.display = collapsed ? "none" : "block";
  caret.textContent = collapsed ? "▶" : "▼";
}

function loadProcessState() {
  try {
    const rawMap = localStorage.getItem("mantle.traceProcessMap");
    const parsedMap = rawMap ? JSON.parse(rawMap) : {};
    traceProcessMap = parsedMap && typeof parsedMap === "object" ? parsedMap : {};
  } catch (_) {
    traceProcessMap = {};
  }

  try {
    const rawNames = localStorage.getItem("mantle.processNames");
    const parsedNames = rawNames ? JSON.parse(rawNames) : ["default"];
    processNames = Array.isArray(parsedNames) ? parsedNames.map((n) => String(n || "").trim()).filter(Boolean) : ["default"];
  } catch (_) {
    processNames = ["default"];
  }

  if (!processNames.includes("default")) processNames.unshift("default");
}

function saveProcessState() {
  localStorage.setItem("mantle.traceProcessMap", JSON.stringify(traceProcessMap));
  localStorage.setItem("mantle.processNames", JSON.stringify(processNames));
}

function getTraceProcess(traceId) {
  const raw = String(traceProcessMap[traceId] || "").trim();
  if (!raw) return "default";
  return raw;
}

function setTraceProcess(traceId, processName) {
  const value = String(processName || "default").trim() || "default";
  traceProcessMap[traceId] = value;
  if (!processNames.includes(value)) {
    processNames.push(value);
  }
  saveProcessState();
}

function normalizeProcessAssignments(traces) {
  const traceIds = new Set((traces || []).map((t) => String(t.trace_id || "")));
  for (const key of Object.keys(traceProcessMap)) {
    if (!traceIds.has(key)) {
      delete traceProcessMap[key];
    }
  }
  for (const t of traces || []) {
    const tid = String(t.trace_id || "");
    if (!tid) continue;
    if (!traceProcessMap[tid]) traceProcessMap[tid] = "default";
  }
  processNames = Array.from(new Set(["default", ...processNames, ...Object.values(traceProcessMap).map((n) => String(n || "default"))]));
  processNames.sort((a, b) => {
    if (a === "default") return -1;
    if (b === "default") return 1;
    return a.localeCompare(b);
  });
  saveProcessState();
}

function createProcess() {
  const name = window.prompt("New process name", "");
  if (!name) return;
  const normalized = String(name || "").trim();
  if (!normalized) return;
  if (!processNames.includes(normalized)) {
    processNames.push(normalized);
    processNames.sort((a, b) => {
      if (a === "default") return -1;
      if (b === "default") return 1;
      return a.localeCompare(b);
    });
    saveProcessState();
  }
  renderTraceList(cachedTraces);
}

function renderTraceList(traces) {
  normalizeProcessAssignments(traces || []);
  traceListEl.innerHTML = "";

  if (selectedTraceId) {
    const clearBtn = document.createElement("button");
    clearBtn.className = "btn";
    clearBtn.style.margin = "8px 12px";
    clearBtn.textContent = "Clear Selection";
    clearBtn.addEventListener("click", async () => {
      selectedTraceId = null;
      currentReplayTurnId = null;
      renderTraceList(cachedTraces);
      renderBreadcrumbs();
      graphWrapper.classList.toggle("replay-mode", false);
      graphCanvas.innerHTML = `<div class="empty-state"><h3>Token Profiler</h3><p>Select a trace to view its token consumption profile.</p></div>`;
    });
    traceListEl.appendChild(clearBtn);
  }

  const grouped = new Map();
  for (const name of processNames) {
    grouped.set(name, []);
  }
  for (const t of traces || []) {
    const pname = getTraceProcess(t.trace_id);
    if (!grouped.has(pname)) grouped.set(pname, []);
    grouped.get(pname).push(t);
  }

  for (const [processName, items] of grouped.entries()) {
    const section = document.createElement("div");
    section.className = "trace-process-group";

    const header = document.createElement("div");
    header.className = "trace-process-header";
    header.innerHTML = `<span class="trace-process-name">${escapeHtml(processName)}</span><span class="trace-process-count">${formatNumber(items.length)}</span>`;
    section.appendChild(header);

    if (!items.length) {
      const empty = document.createElement("div");
      empty.className = "trace-process-empty";
      empty.textContent = "No traces";
      section.appendChild(empty);
      traceListEl.appendChild(section);
      continue;
    }

    for (const t of items) {
      const row = document.createElement("div");
      row.className = `trace-item${t.trace_id === selectedTraceId ? " active" : ""}`;
      const statusClass = t.status === "completed" ? "completed" : "active";
      const anomalyMeta = normalizeAnomaly(t.anomaly || {
        anomaly_verdict: t.anomaly_verdict,
        anomaly_detected: t.anomaly_detected,
      });
      const anomalyHtml = anomalyIndicatorHtml(anomalyMeta, "trace-anomaly-indicator");
      const moveOptions = processNames
        .map((name) => `<option value="${escapeHtml(name)}" ${name === processName ? "selected" : ""}>${escapeHtml(name)}</option>`)
        .join("");
      row.innerHTML = `
        <div class="trace-row">
          <div class="trace-main">
            <div class="trace-name">${escapeHtml(t.trace_id)}</div>
            <div class="trace-meta"><span class="trace-status ${statusClass}">${escapeHtml(t.status)}</span> agent: ${formatNumber(t.agent_event_count)} sys: ${formatNumber(t.sys_event_count)}</div>
            <div class="trace-meta">Move to: <select class="trace-move-select">${moveOptions}</select></div>
          </div>
          <div class="trace-row-actions">
            ${anomalyHtml}
            <button class="trace-delete-btn" title="Delete trace">×</button>
          </div>
        </div>`;

      row.addEventListener("click", () => selectTrace(t.trace_id));

      const moveSelect = row.querySelector(".trace-move-select");
      moveSelect.addEventListener("click", (e) => e.stopPropagation());
      moveSelect.addEventListener("change", (e) => {
        e.stopPropagation();
        setTraceProcess(t.trace_id, moveSelect.value);
        renderTraceList(cachedTraces);
      });

      const deleteBtn = row.querySelector(".trace-delete-btn");
      deleteBtn.addEventListener("click", async (e) => {
        e.stopPropagation();
        try {
          await fetch(`/api/traces/${encodeURIComponent(t.trace_id)}`, { method: "DELETE" });
        } catch (err) {
          console.error("Failed to delete trace", err);
        }
      });

      section.appendChild(row);
    }

    traceListEl.appendChild(section);
  }
}

function renderBreadcrumbs() {
  breadcrumbsEl.innerHTML = "";
  if (!selectedTraceId) {
    const label = activeTab.charAt(0).toUpperCase() + activeTab.slice(1);
    breadcrumbsEl.innerHTML = `<span class="crumb current">${escapeHtml(label)} Overview</span>`;
    return;
  }

  const root = document.createElement("span");
  root.className = "crumb";
  root.textContent = selectedTraceId;
  root.addEventListener("click", async () => {
    viewStack = [];
    await loadReplayOverview();
  });
  breadcrumbsEl.appendChild(root);

  const full = [...viewStack];
  if (full.length === 0) {
    const cur = document.createElement("span");
    cur.className = "crumb current";
    cur.textContent = "Replay";
    const sep = document.createElement("span");
    sep.className = "sep";
    sep.textContent = "›";
    breadcrumbsEl.appendChild(sep);
    breadcrumbsEl.appendChild(cur);
    return;
  }

  for (let i = 0; i < full.length; i += 1) {
    const sep = document.createElement("span");
    sep.className = "sep";
    sep.textContent = "›";
    breadcrumbsEl.appendChild(sep);

    const crumb = document.createElement("span");
    const isLast = i === full.length - 1;
    crumb.className = `crumb${isLast ? " current" : ""}`;
    crumb.textContent = full[i].label;
    if (!isLast) {
      crumb.addEventListener("click", async () => {
        viewStack = full.slice(0, i + 1);
        await restoreFromStack();
      });
    }
    breadcrumbsEl.appendChild(crumb);
  }
}

function mean(values) {
  if (!values.length) return 0;
  return values.reduce((a, b) => a + Number(b || 0), 0) / values.length;
}

function variance(values) {
  if (!values.length) return 0;
  const m = mean(values);
  return mean(values.map((v) => (Number(v || 0) - m) ** 2));
}

function pct(numerator, denominator) {
  if (!denominator) return 0;
  return (Number(numerator || 0) / Number(denominator || 1)) * 100;
}

function formatBytes(bytes) {
  const n = Number(bytes || 0);
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

async function loadTokenProfile(traceId) {
  if (!traceId) return;
  const payload = await api(`/api/traces/${encodeURIComponent(traceId)}/token-profile`);
  const profile = payload.profile || [];
  renderTokenProfileChart(profile);
}

function renderTokenProfileChart(profile) {
  const strip = $("summaryStrip");

  if (!profile.length) {
    strip.style.gridTemplateColumns = "repeat(3, 1fr)";
    strip.innerHTML = `
      <div class="summary-card"><div class="k">Turns</div><div class="v">0</div></div>
      <div class="summary-card"><div class="k">Total Request</div><div class="v">—</div></div>
      <div class="summary-card"><div class="k">Total Response</div><div class="v">—</div></div>`;
    graphCanvas.innerHTML = `<div class="empty-state"><h3>No Proxy Data</h3><p>This trace has no LLM proxy capture data. Token profiling requires proxy request/response payloads.</p></div>`;
    return;
  }

  const totalReq = profile.reduce((a, p) => a + p.request_bytes, 0);
  const totalResp = profile.reduce((a, p) => a + p.response_bytes, 0);
  const maxReq = Math.max(...profile.map((p) => p.request_bytes));
  const avgDelta = profile.length ? profile.reduce((a, p) => a + p.delta_bytes, 0) / profile.length : 0;

  strip.style.gridTemplateColumns = "repeat(5, 1fr)";
  strip.innerHTML = `
    <div class="summary-card"><div class="k">Turns</div><div class="v">${formatNumber(profile.length)}</div></div>
    <div class="summary-card"><div class="k">Total Request</div><div class="v">${formatBytes(totalReq)}</div></div>
    <div class="summary-card"><div class="k">Total Response</div><div class="v">${formatBytes(totalResp)}</div></div>
    <div class="summary-card"><div class="k">Max Context</div><div class="v">${formatBytes(maxReq)}</div></div>
    <div class="summary-card"><div class="k">Avg Tool Output</div><div class="v">${formatBytes(avgDelta)}</div></div>`;

  // Destroy previous chart instance
  if (tokenProfileChart) {
    tokenProfileChart.destroy();
    tokenProfileChart = null;
  }

  graphCanvas.innerHTML = `<div style="padding:24px;max-width:1100px;margin:0 auto;"><canvas id="tokenProfileCanvas" style="width:100%;height:420px;"></canvas></div>`;
  const canvas = $("tokenProfileCanvas");
  if (!canvas) return;

  const labels = profile.map((p) => `T${p.turn_index}`);
  const reqData = profile.map((p) => p.request_bytes / 1024);
  const respData = profile.map((p) => p.response_bytes / 1024);
  const deltaData = profile.map((p) => p.delta_bytes / 1024);

  tokenProfileChart = new Chart(canvas, {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          type: "line",
          label: "request_bytes (KB) — context size",
          data: reqData,
          borderColor: "rgba(99, 102, 241, 1)",
          backgroundColor: "rgba(99, 102, 241, 0.12)",
          fill: true,
          tension: 0.25,
          pointRadius: 3,
          pointHoverRadius: 6,
          borderWidth: 2.5,
          yAxisID: "y",
          order: 1,
        },
        {
          type: "line",
          label: "response_bytes (KB)",
          data: respData,
          borderColor: "rgba(16, 185, 129, 1)",
          backgroundColor: "rgba(16, 185, 129, 0.08)",
          fill: false,
          tension: 0.25,
          pointRadius: 3,
          pointHoverRadius: 6,
          borderWidth: 2,
          yAxisID: "y2",
          order: 2,
        },
        {
          type: "bar",
          label: "delta (KB) — tool outputs",
          data: deltaData,
          backgroundColor: "rgba(245, 158, 11, 0.5)",
          borderColor: "rgba(245, 158, 11, 1)",
          borderWidth: 1,
          borderRadius: 3,
          yAxisID: "y2",
          order: 3,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: {
          position: "top",
          labels: { usePointStyle: true, padding: 16, font: { size: 12, family: "Inter, system-ui, sans-serif" } },
        },
        tooltip: {
          backgroundColor: "rgba(15, 23, 42, 0.92)",
          titleFont: { size: 13, family: "Inter, system-ui, sans-serif" },
          bodyFont: { size: 12, family: "'SF Mono', monospace" },
          padding: 12,
          cornerRadius: 8,
          callbacks: {
            label: (ctx) => {
              const raw = profile[ctx.dataIndex];
              if (!raw) return "";
              if (ctx.datasetIndex === 0) return ` request: ${formatBytes(raw.request_bytes)}`;
              if (ctx.datasetIndex === 1) return ` response: ${formatBytes(raw.response_bytes)}`;
              return ` delta: ${raw.delta_bytes >= 0 ? "+" : ""}${formatBytes(raw.delta_bytes)}`;
            },
          },
        },
      },
      scales: {
        x: {
          title: { display: true, text: "Turn", font: { size: 12, weight: "600" } },
          grid: { display: false },
          ticks: { font: { size: 11 } },
        },
        y: {
          type: "linear",
          position: "left",
          title: { display: true, text: "Context Size (KB)", font: { size: 12, weight: "600" } },
          grid: { color: "rgba(148, 163, 184, 0.15)" },
          ticks: { font: { size: 11 } },
          beginAtZero: true,
        },
        y2: {
          type: "linear",
          position: "right",
          title: { display: true, text: "Response / Delta (KB)", font: { size: 12, weight: "600" } },
          grid: { drawOnChartArea: false },
          ticks: { font: { size: 11 } },
        },
      },
    },
  });
}

function updateExecutiveSummary(summary) {
  const strip = $("summaryStrip");
  strip.innerHTML = `
    <div class="summary-card"><div class="k">Turns</div><div class="v">${formatNumber(summary.turns)}</div></div>
    <div class="summary-card"><div class="k">Tool Calls</div><div class="v">${formatNumber(summary.tool_calls)}</div></div>
    <div class="summary-card"><div class="k">Files Read</div><div class="v">${formatNumber(summary.files_read)}</div></div>
    <div class="summary-card"><div class="k">Files Written</div><div class="v">${formatNumber(summary.files_written)}</div></div>
    <div class="summary-card"><div class="k">Network Calls</div><div class="v">${formatNumber(summary.network_calls)}</div></div>
    <div class="summary-card"><div class="k">Subprocesses</div><div class="v">${formatNumber(summary.subprocesses_spawned)}</div></div>`;
  strip.style.gridTemplateColumns = "repeat(6, 1fr)";
}

function renderTurnTabs(turns) {
  const wrap = document.createElement("div");
  wrap.className = "turn-tabs";
  for (const turn of turns) {
    const btn = document.createElement("button");
    btn.className = `turn-tab${turn.turn_id === currentTurnId ? " active" : ""}`;
    const anomalyHtml = anomalyIndicatorHtml(turn.anomaly || null, "turn-anomaly-indicator");
    const tags = (turn.tags || []).map((tag) => `<span class="tag-pill ${toneClass(tag)}">${escapeHtml(tag)}</span>`).join("");
    btn.innerHTML = `
      <div class="turn-tab-top">
        <span class="turn-id">${escapeHtml(turn.label)}</span>
        <span class="turn-tab-meta"><span class="turn-tools">${formatNumber(turn.tool_call_count)} tools</span>${anomalyHtml}</span>
      </div>
      <div class="turn-tags">${tags}</div>
      <div class="turn-summary">${escapeHtml(turn.dominant_summary || "")}</div>`;
    btn.addEventListener("click", async () => {
      currentTurnId = turn.turn_id;
      viewStack = [{ kind: "turn", turnId: turn.turn_id, label: turn.label }];
      renderBreadcrumbs();
      await loadTurnDetail(turn.turn_id);
    });
    wrap.appendChild(btn);
  }
  return wrap;
}

function jsonBlock(value) {
  return `<pre class="mono-block">${escapeHtml(JSON.stringify(value ?? {}, null, 2))}</pre>`;
}

function normalizeForMatch(value) {
  return String(value || "").toLowerCase().replace(/\s+/g, " ").trim();
}

function collectResultTexts(value, out, depth = 0) {
  if (depth > 4) return;
  if (typeof value === "string") {
    const v = normalizeForMatch(value);
    if (v) out.push(v);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      collectResultTexts(item, out, depth + 1);
    }
    return;
  }
  if (value && typeof value === "object") {
    for (const key of Object.keys(value)) {
      collectResultTexts(value[key], out, depth + 1);
      const k = normalizeForMatch(key);
      if (k) out.push(k);
    }
  }
}

function extractToolCallIdFromValue(value) {
  if (!value) return "";
  if (typeof value === "object") {
    const direct = value.tool_call_id || value.call_id || value.id;
    return typeof direct === "string" ? direct : "";
  }
  if (typeof value !== "string") return "";
  const text = value;
  const patterns = [
    /"tool_call_id"\s*:\s*"([^"]+)"/i,
    /"call_id"\s*:\s*"([^"]+)"/i,
    /\btool_call_id\s*=\s*([A-Za-z0-9_\-]+)/i,
    /\bcall_id\s*=\s*([A-Za-z0-9_\-]+)/i,
  ];
  for (const re of patterns) {
    const m = text.match(re);
    if (m && m[1]) return m[1];
  }
  return "";
}

function extractResultTextsForLookup(result) {
  const out = [];
  if (typeof result === "string") {
    const norm = normalizeForMatch(result);
    if (norm) out.push(norm);
    return out;
  }
  if (result == null) return out;

  const jsonNorm = normalizeForMatch(JSON.stringify(result));
  if (jsonNorm) out.push(jsonNorm);

  if (typeof result === "object") {
    const output = result.output;
    if (typeof output === "string") {
      const outputNorm = normalizeForMatch(output);
      if (outputNorm) out.push(outputNorm);
    }
  }
  return out;
}

function buildReplayToolSourceIndex(turnDetailPayload) {
  const timeline = (turnDetailPayload && turnDetailPayload.timeline) || [];
  const out = [];
  for (const entry of timeline) {
    if (!entry || entry.entry_type !== "tool_call") continue;
    const source = entry.source && typeof entry.source === "object" ? entry.source : {};
    const pid = Number(source.pid || 0);
    const sourceInfo = pid > 0 ? { status: "matched", pid } : { status: "source_not_found" };

    const texts = extractResultTextsForLookup(entry.result);

    const unique = [];
    const seen = new Set();
    for (const t of texts) {
      if (!t || seen.has(t)) continue;
      seen.add(t);
      unique.push(t);
    }

    for (const text of unique) {
      out.push({ text, source: sourceInfo });
    }
  }
  return out;
}

function findReplaySourceForValue(value) {
  const callId = extractToolCallIdFromValue(value);
  if (callId && replaySourceByToolCallId.has(callId)) {
    return replaySourceByToolCallId.get(callId);
  }

  const norm = normalizeForMatch(value);
  if (!norm) return { status: "source_not_found" };

  if (replaySourceByResultText.has(norm)) {
    return replaySourceByResultText.get(norm);
  }

  for (const item of currentReplayToolSourceIndex || []) {
    const text = String(item.text || "");
    if (!text) continue;
    if (norm === text) return item.source;
  }
  return { status: "source_not_found" };
}

function absorbReplayToolSourcesFromTurnDetail(turnDetailPayload) {
  const index = buildReplayToolSourceIndex(turnDetailPayload);
  for (const item of index) {
    const source = item && item.source ? item.source : { status: "source_not_found" };
    const pid = Number(source.pid || 0);
    if (pid <= 0) continue;

    const timeline = (turnDetailPayload && turnDetailPayload.timeline) || [];
    for (const entry of timeline) {
      if (!entry || entry.entry_type !== "tool_call") continue;
      if (entry.source && Number(entry.source.pid || 0) !== pid) continue;
      const tcid = String(entry.tool_call_id || "").trim();
      if (tcid) replaySourceByToolCallId.set(tcid, source);
    }

    const text = String(item.text || "").trim();
    if (text) replaySourceByResultText.set(text, source);
  }
}

async function primeReplaySourceMaps() {
  if (!selectedTraceId || !replayOverview) return;
  if (replaySourceMapTraceId === selectedTraceId) return;

  replaySourceByToolCallId = new Map();
  replaySourceByResultText = new Map();

  const turns = (replayOverview.turns || []).map((t) => t.turn_id).filter(Boolean);
  const results = await Promise.all(
    turns.map((turnId) =>
      api(`/api/traces/${encodeURIComponent(selectedTraceId)}/turns/${encodeURIComponent(turnId)}`).catch(() => null)
    )
  );
  for (const payload of results) {
    if (!payload) continue;
    absorbReplayToolSourcesFromTurnDetail(payload);
  }
  replaySourceMapTraceId = selectedTraceId;
}

function sectionValueBlock(value) {
  if (typeof value === "string") {
    return `<pre class="mono-block">${escapeHtml(value || "")}</pre>`;
  }
  return `<pre class="mono-block">${escapeHtml(JSON.stringify(value ?? null, null, 2))}</pre>`;
}

function renderSectionPanels(title, sections, emptyText) {
  const list = Array.isArray(sections) ? sections : [];
  if (list.length === 0) {
    return `<div class="mini-label">${escapeHtml(title)}</div><pre class="mono-block">${escapeHtml(emptyText)}</pre>`;
  }

  const items = list.map((section, idx) => {
    const label = String(section?.label || section?.id || `section_${idx + 1}`);
    const values = Array.isArray(section?.values) ? section.values : [];
    const blocks = values.map((v) => sectionValueBlock(v)).join("");
    return `
      <details class="section-panel" ${idx === 0 ? "open" : ""}>
        <summary>${escapeHtml(label)} <span class="section-count">(${formatNumber(values.length)})</span></summary>
        <div class="section-body">${blocks || `<pre class="mono-block">${escapeHtml("No values")}</pre>`}</div>
      </details>`;
  }).join("");

  return `<div class="mini-label">${escapeHtml(title)}</div><div class="section-panel-list">${items}</div>`;
}

function renderCountPills(counts) {
  const c = counts || {};
  const read = Number(c.read || 0);
  const write = Number(c.write || 0);
  const rename = Number(c.rename || 0);
  const pills = [];
  if (read > 0) pills.push(`<span class="op-pill op-read">R ${formatNumber(read)}</span>`);
  if (write > 0) pills.push(`<span class="op-pill op-write">W ${formatNumber(write)}</span>`);
  if (rename > 0) pills.push(`<span class="op-pill op-rename">Mv ${formatNumber(rename)}</span>`);
  return pills.join("");
}

function makeToggle(button, panel) {
  button.addEventListener("click", () => {
    const expanded = panel.style.display !== "none";
    panel.style.display = expanded ? "none" : "block";
    button.textContent = expanded ? "Expand" : "Collapse";
  });
}

function renderToolEntry(entry, turnId) {
  const card = document.createElement("div");
  card.className = "timeline-row tool-entry";

  const resultText = entry.result ? JSON.stringify(entry.result, null, 2) : "No result captured";
  const t = truncateLines(resultText, 3);
  const anomaly = entry && typeof entry.anomaly === "object" ? entry.anomaly : null;
  const anomalyHtml = anomalyIndicatorHtml(anomaly, "tool-anomaly-indicator");
  const source = entry && typeof entry.source === "object" ? entry.source : {};
  const sourcePid = Number(source.pid || 0);
  const hasSource = sourcePid > 0;
  const sourceHtml = hasSource
    ? `<button class="source-link" data-source-pid="${String(sourcePid)}">source: pid${String(sourcePid)}</button>`
    : '<span class="source-missing">source: not found</span>';

  card.innerHTML = `
    <div class="timeline-head">
      <span class="row-title">Tool: ${escapeHtml(entry.tool_name || "unknown")}</span>
      <span class="row-sub">${escapeHtml(entry.tool_call_id || "")}</span>
      ${sourceHtml}
      ${anomalyHtml}
    </div>
    <div class="row-content">
      <div><div class="mini-label">Input arguments</div>${jsonBlock(entry.arguments)}</div>
      <div>
        <div class="mini-label">Return value</div>
        <pre class="mono-block result-block">${escapeHtml(t.short)}</pre>
        ${t.truncated ? '<button class="inline-btn tool-expand-btn">Expand</button>' : ""}
      </div>
      <div class="replay-value-head"><button class="inline-btn debug-btn tool-debug-btn">Debug Info</button></div>
    </div>`;

  const btn = card.querySelector(".tool-expand-btn");
  if (btn) {
    const pre = card.querySelector(".result-block");
    btn.addEventListener("click", () => {
      const expanded = btn.textContent === "Collapse";
      pre.textContent = expanded ? t.short : t.long;
      btn.textContent = expanded ? "Expand" : "Collapse";
    });
  }

  const debugBtn = card.querySelector(".tool-debug-btn");
  if (debugBtn) {
    debugBtn.addEventListener("click", () => {
      openDebugInfoPopup(`Tool Event: ${String(entry.tool_name || "unknown")}`, entry);
    });
  }

  const sourceLink = card.querySelector(".source-link");
  if (sourceLink && turnId) {
    sourceLink.addEventListener("click", async () => {
      await openSourceTracePopup(turnId, sourcePid, entry.tool_name || "unknown", null, null, false, anomaly);
    });
  }

  return card;
}

function createFileTreeNode(node, turnId, options = {}) {
  if (!node) return document.createElement("div");
  const disableDrilldown = Boolean(options.disableDrilldown || options.disableResourceDrilldown);

  if (node.kind === "file") {
    const row = document.createElement("div");
    const state = String(node.state || "read");
    const stateText = state === "read_write" ? "read/write" : state;
    row.className = `tree-file tree-${state}`;
    row.innerHTML = `
      <span class="tree-name">${escapeHtml(node.name)}</span>
      <span class="tree-meta">
        <span class="tree-state">${escapeHtml(stateText)}</span>
        <button class="inline-btn debug-btn tree-debug-btn" type="button">Debug Info</button>
      </span>`;
    if (!disableDrilldown && turnId) {
      row.addEventListener("click", async () => {
        await loadRawResource(turnId, "file", node.path, `${node.path} (${stateText})`);
      });
    }
    const debugBtn = row.querySelector(".tree-debug-btn");
    if (debugBtn) {
      debugBtn.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        openDebugInfoPopup(`File Node: ${String(node.path || node.name || "file")}`, node);
      });
    }
    return row;
  }

  const details = document.createElement("details");
  details.className = "tree-dir";
  details.open = true;
  const summary = document.createElement("summary");
  summary.innerHTML = `<span>${escapeHtml(node.name || "/")}</span><span class="tree-pills">${renderCountPills(node.counts)}</span><button class="inline-btn debug-btn tree-debug-btn" type="button">Debug Info</button>`;
  details.appendChild(summary);

  const debugBtn = summary.querySelector(".tree-debug-btn");
  if (debugBtn) {
    debugBtn.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      openDebugInfoPopup(`Folder Node: ${String(node.name || "/")}`, node);
    });
  }

  for (const child of node.children || []) {
    details.appendChild(createFileTreeNode(child, turnId, options));
  }
  return details;
}

function renderSystemGroup(entry, turnId, options = {}) {
  const row = document.createElement("div");
  row.className = `timeline-row ${systemTone(entry.category)}`;
  const groupPills = entry.category === "file" ? renderCountPills(entry.counts) : "";
  const displayTraceContext = options.displayTraceContext || null;
  const disableResourceDrilldown = Boolean(options.disableResourceDrilldown);
  const disableProcessDrilldown = Boolean(options.disableProcessDrilldown);
  const recursiveProcessExpand = Boolean(options.recursiveProcessExpand);
  const fullLifecycle = Boolean(options.fullLifecycle);

  const hasExpand = entry.category === "process"
    ? Array.isArray(entry.process_tree) && entry.process_tree.length > 0
    : !entry.standalone;
  row.innerHTML = `
    <div class="timeline-head">
      <span class="row-title">${escapeHtml(entry.title)}</span>
      <span class="row-sub">${escapeHtml(entry.category)}</span>
      ${groupPills ? `<span class="group-pills">${groupPills}</span>` : ""}
      <button class="inline-btn debug-btn event-debug-btn">Debug Info</button>
      ${hasExpand ? '<button class="inline-btn group-toggle">Expand</button>' : ""}
    </div>
    <div class="row-content" style="display:${hasExpand ? "none" : "block"};"></div>`;

  const content = row.querySelector(".row-content");
  const debugBtn = row.querySelector(".event-debug-btn");
  if (debugBtn) {
    debugBtn.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      openDebugInfoPopup(`System Group: ${String(entry.category || "event")}`, entry);
    });
  }

  if (entry.category === "file") {
    const tree = createFileTreeNode(entry.tree, turnId, options);
    content.appendChild(tree);
  } else if (entry.category === "process") {
    const hints = document.createElement("div");
    hints.className = "mono-text";
    const cmds = (entry.commands || []).slice(0, 6).join("\n");
    hints.textContent = cmds || "No command strings captured";
    content.appendChild(hints);

    const childProcesses = Array.isArray(entry.process_tree) ? entry.process_tree : [];
    const list = document.createElement("div");
    list.className = "proc-list";
    content.appendChild(list);

    if (displayTraceContext) {
      if (!childProcesses.length) {
        const empty = document.createElement("div");
        empty.className = "mono-text";
        empty.textContent = "No spawned child processes in this scope.";
        list.appendChild(empty);
      }
      for (const p of childProcesses) {
        const pid = Number((p && p.pid) || 0);
        if (!pid) continue;
        const btn = document.createElement("button");
        btn.className = "proc-node";
        btn.innerHTML = `pid ${escapeHtml(String(pid))} · ${escapeHtml(String((p && p.command) || "(unknown)"))}`;
        btn.addEventListener("click", () => {
          if (typeof displayTraceContext.onSelectPid === "function") {
            displayTraceContext.onSelectPid(pid);
          }
        });
        list.appendChild(btn);
      }

      if (disableProcessDrilldown) {
        content.style.display = "block";
        const toggle = row.querySelector(".group-toggle");
        if (toggle) {
          toggle.style.display = "none";
        }
      } else if (recursiveProcessExpand) {
        content.style.display = "block";
        const toggle = row.querySelector(".group-toggle");
        if (toggle) {
          toggle.style.display = "none";
        }
      } else {
        const toggle = row.querySelector(".group-toggle");
        if (toggle) {
          toggle.addEventListener("click", () => {
            const expanded = content.style.display !== "none";
            content.style.display = expanded ? "none" : "block";
            toggle.textContent = expanded ? "Expand" : "Collapse";
          });
        }
      }
    } else {
      let loaded = false;
      const loadChildTimelines = async () => {
        if (loaded) return;
        loaded = true;

        for (const p of childProcesses) {
          const block = document.createElement("div");
          block.className = "proc-inline-body";
          block.innerHTML = `
            <div class="mini-label">PID ${escapeHtml(String(p.pid))} · ${escapeHtml(p.command || "(unknown)")}</div>
            <div class="proc-inline-timeline"><div class="mono-text">Loading process activity...</div></div>`;
          list.appendChild(block);

          const nested = block.querySelector(".proc-inline-timeline");
          try {
            const lifecycleQuery = fullLifecycle ? "?full_lifecycle=1" : "";
            const payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/process-subtrace/${encodeURIComponent(turnId)}/${encodeURIComponent(p.pid)}${lifecycleQuery}`);
            const s = payload.summary || {};
            nested.innerHTML = "";

            const summary = document.createElement("div");
            summary.className = "mono-text";
            summary.textContent = `pid=${String(s.pid || p.pid)} ppid=${String(s.parent_pid || "-")} files_read=${formatNumber(s.files_read)} files_written=${formatNumber(s.files_written)} child_spawns=${formatNumber(s.child_processes_spawned)} network_calls=${formatNumber(s.network_calls)} exit=${s.exit_code == null ? "-" : String(s.exit_code)}`;
            nested.appendChild(summary);

            for (const subEntry of payload.timeline || []) {
              nested.appendChild(renderSystemGroup(subEntry, turnId, options));
            }
          } catch (_err) {
            nested.innerHTML = '<div class="mono-text">Failed to load process activity for this PID.</div>';
          }
        }
      };

      if (disableProcessDrilldown) {
        content.style.display = "block";
        const toggle = row.querySelector(".group-toggle");
        if (toggle) {
          toggle.style.display = "none";
        }
      } else if (recursiveProcessExpand) {
        content.style.display = "block";
        const toggle = row.querySelector(".group-toggle");
        if (toggle) {
          toggle.style.display = "none";
        }
        loadChildTimelines();
      } else if (!hasExpand) {
        loadChildTimelines();
      } else {
        const toggle = row.querySelector(".group-toggle");
        toggle.addEventListener("click", async () => {
          const expanded = content.style.display !== "none";
          content.style.display = expanded ? "none" : "block";
          toggle.textContent = expanded ? "Expand" : "Collapse";
          if (!expanded) {
            await loadChildTimelines();
          }
        });
      }
    }
  } else if (entry.category === "network") {
    const calls = document.createElement("div");
    calls.className = "net-list";
    for (const call of entry.calls || []) {
      const btn = document.createElement("button");
      btn.className = "net-node";
      btn.innerHTML = `${escapeHtml(call.dest)} · tx ${formatNumber(call.bytes_sent)}B · rx ${formatNumber(call.bytes_recv)}B${call.full_capture ? ' · <span class="capture-flag">full capture available</span>' : ""}`;
      if (!disableResourceDrilldown && turnId) {
        btn.addEventListener("click", async () => {
          await loadRawResource(turnId, "network", call.dest, call.dest);
        });
      }
      calls.appendChild(btn);
    }
    content.appendChild(calls);
  } else if (entry.event) {
    content.innerHTML = jsonBlock(entry.event);
  }

  const toggle = row.querySelector(".group-toggle");
  if (toggle && entry.category !== "process") {
    makeToggle(toggle, content);
  }

  return row;
}

function ensureProcessTracePopup() {
  let overlay = document.getElementById("processTraceOverlay");
  if (overlay) {
    return overlay;
  }

  overlay = document.createElement("div");
  overlay.id = "processTraceOverlay";
  overlay.className = "process-trace-overlay";
  overlay.innerHTML = `
    <div class="process-trace-modal" role="dialog" aria-modal="true" aria-label="Process trace">
      <div class="process-trace-head">
        <div>
          <div class="process-trace-title" id="processTraceTitle">Process Trace</div>
          <div class="process-trace-subtitle" id="processTraceSubtitle"></div>
        </div>
        <button class="btn" id="processTraceCloseBtn">Close</button>
      </div>
      <div class="process-trace-body" id="processTraceBody"></div>
    </div>`;

  document.body.appendChild(overlay);

  const closeBtn = overlay.querySelector("#processTraceCloseBtn");
  closeBtn.addEventListener("click", () => {
    overlay.classList.remove("open");
  });
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) {
      overlay.classList.remove("open");
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      overlay.classList.remove("open");
    }
  });

  return overlay;
}

function renderDisplayTraceSummary(summary) {
  const direct = summary && typeof summary.direct === "object" ? summary.direct : {};
  const nested = summary && typeof summary.nested === "object" ? summary.nested : {};
  const totals = summary && typeof summary.totals === "object" ? summary.totals : {};
  const command = String((summary && summary.command) || "").trim();

  return `
    <div class="turn-exec-summary display-trace-summary">
      <div class="mini-card"><div class="k">Files Read</div><div class="v">${formatNumber(totals.files_read)} <span class="mono-small">(${formatNumber(direct.files_read)} direct · ${formatNumber(nested.files_read)} nested)</span></div></div>
      <div class="mini-card"><div class="k">Files Written</div><div class="v">${formatNumber(totals.files_written)} <span class="mono-small">(${formatNumber(direct.files_written)} direct · ${formatNumber(nested.files_written)} nested)</span></div></div>
      <div class="mini-card"><div class="k">Network Calls</div><div class="v">${formatNumber(totals.network_calls)} <span class="mono-small">(${formatNumber(direct.network_calls)} direct · ${formatNumber(nested.network_calls)} nested)</span></div></div>
      <div class="mini-card"><div class="k">Process Spawns</div><div class="v">${formatNumber(totals.process_spawns)} <span class="mono-small">(${formatNumber(direct.process_spawns)} direct · ${formatNumber(nested.process_spawns)} nested)</span></div></div>
      <div class="mini-card"><div class="k">Sys Events</div><div class="v">${formatNumber(summary.event_count || 0)}</div></div>
      ${command ? `<div class="mini-card"><div class="k">Command</div><div class="v mono-small">${escapeHtml(command)}</div></div>` : ""}
    </div>`;
}

function renderDisplayTracePayload(payload, container, options = {}) {
  const scope = payload && payload.scope ? payload.scope : {};
  const summary = payload && payload.summary ? payload.summary : {};

  const wrap = document.createElement("div");
  wrap.className = "process-trace-content";
  wrap.innerHTML = renderDisplayTraceSummary(summary);

  // --- Discovery Tabs (resource-centric view) ---
  const discoveryHost = document.createElement("div");
  discoveryHost.className = "discovery-host";
  renderDiscoveryTabs(payload, discoveryHost, {});
  wrap.appendChild(discoveryHost);

  container.innerHTML = "";
  container.appendChild(wrap);
}

/* ===================================================================
 * Discovery-Oriented Event Viewer (resource-centric tabs)
 * Replaces temporal timeline with Files / Network / Commands tabs
 * that aggregate all events across all PIDs in the scope.
 * =================================================================== */

function _buildAggregatedFileTree(node, options) {
  if (!node) return document.createElement("div");
  const onFileClick = typeof options.onFileClick === "function" ? options.onFileClick : null;
  const anomalyPaths = options.anomalyPaths instanceof Set ? options.anomalyPaths : new Set();

  if (node.kind === "file") {
    const row = document.createElement("div");
    const state = String(node.state || "read");
    const stateText = state === "read_write" ? "read/write" : state;
    const isAnomaly = anomalyPaths.has(String(node.path || ""));
    row.className = `tree-file tree-${state}${isAnomaly ? " tree-anomaly" : ""}`;

    const opsText = [];
    const rc = Number(node.read_count || 0);
    const wc = Number(node.write_count || 0);
    if (rc > 0) opsText.push(`${formatNumber(rc)} read${rc === 1 ? "" : "s"}`);
    if (wc > 0) opsText.push(`${formatNumber(wc)} write${wc === 1 ? "" : "s"}`);
    const tooltip = opsText.length ? opsText.join(", ") : "";

    row.innerHTML = `
      <span class="tree-name">${escapeHtml(node.name)}</span>
      <span class="tree-meta">
        <span class="tree-state">${escapeHtml(stateText)}</span>
        ${isAnomaly ? '<span class="anomaly-indicator anomaly tree-anomaly-icon" title="anomaly detected"></span>' : ""}
      </span>`;
    if (tooltip) row.title = tooltip;
    if (onFileClick) {
      row.style.cursor = "pointer";
      row.addEventListener("click", () => onFileClick(node));
    }
    return row;
  }

  // directory node
  const details = document.createElement("details");
  details.className = "tree-dir";
  // Collapse by default for discovered trees to reduce visual noise
  details.open = false;
  const summary = document.createElement("summary");
  summary.innerHTML = `<span>${escapeHtml(node.name || "/")}</span><span class="tree-pills">${renderCountPills(node.counts)}</span>`;
  details.appendChild(summary);
  for (const child of node.children || []) {
    details.appendChild(_buildAggregatedFileTree(child, options));
  }
  return details;
}

function _renderResourceDetailPanel(items, options) {
  const container = document.createElement("div");
  container.className = "discovery-detail-panel";
  if (!items || !items.length) {
    container.innerHTML = '<div class="replay-empty">No events found for this resource.</div>';
    return container;
  }

  const selectedTraceIdLocal = selectedTraceId;
  for (const item of items) {
    const pid = Number(item.pid || 0);
    const cmd = String(item.command || "(unknown)");
    const ts = item.timestamp != null ? new Date(Number(item.timestamp) * 1000).toISOString().replace("T", " ").slice(0, 19) : "";
    const op = String(item.operation || item.type || "");

    const row = document.createElement("div");
    row.className = "discovery-detail-row";
    row.innerHTML = `
      <div class="discovery-detail-meta">
        <span class="discovery-detail-pid">pid ${escapeHtml(String(pid))}</span>
        <span class="discovery-detail-op op-badge op-${escapeHtml(op.replace("file_", "").replace("net_", ""))}">${escapeHtml(op)}</span>
        ${ts ? `<span class="discovery-detail-ts">${escapeHtml(ts)}</span>` : ""}
      </div>
      <div class="discovery-detail-cmd mono-text" style="border:0;padding:2px 0;background:transparent;">${escapeHtml(cmd)}</div>
    `;

    if (pid > 0 && selectedTraceIdLocal) {
      const openBtn = document.createElement("button");
      openBtn.className = "inline-btn discovery-open-trace-btn";
      openBtn.textContent = "Open Full Trace";
      openBtn.title = `View all raw JSON events for PID ${pid} in a new tab`;
      openBtn.addEventListener("click", async () => {
        try {
          const params = new URLSearchParams();
          params.set("pid", String(pid));
          const data = await api(`/api/traces/${encodeURIComponent(selectedTraceIdLocal)}/display-trace?${params.toString()}`);
          const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          window.open(url, "_blank");
        } catch (_err) {
          alert("Failed to load full trace for this PID.");
        }
      });
      row.querySelector(".discovery-detail-meta").appendChild(openBtn);
    }

    container.appendChild(row);
  }
  return container;
}

function renderDiscoveryTabs(payload, container, options = {}) {
  const aggregated = payload && typeof payload.aggregated === "object" ? payload.aggregated : {};
  const files = Array.isArray(aggregated.files) ? aggregated.files : [];
  const fileTree = aggregated.file_tree || null;
  const network = Array.isArray(aggregated.network) ? aggregated.network : [];
  const commands = Array.isArray(aggregated.commands) ? aggregated.commands : [];
  const anomalyReport = options.anomaly && typeof options.anomaly === "object" ? options.anomaly : null;
  const scope = payload && payload.scope ? payload.scope : {};

  // Build anomaly path set from violations
  const anomalyPaths = new Set();
  const anomalyDests = new Set();
  if (anomalyReport) {
    const violations = Array.isArray(anomalyReport.violations) ? anomalyReport.violations : [];
    for (const v of violations) {
      const p = String(v.path || v.resource || "");
      if (p) anomalyPaths.add(p);
      const d = v.dest_ip ? `${String(v.dest_ip)}:${String(v.dest_port || 0)}` : "";
      if (d) anomalyDests.add(d);
    }
  }

  // Build pid->command map for detail events
  const pidCommandMap = {};
  for (const cmd of commands) {
    if (cmd.pid) pidCommandMap[cmd.pid] = String(cmd.command || "");
  }
  // Also from files.pids
  for (const f of files) {
    for (const p of f.pids || []) {
      if (p.pid && p.command) pidCommandMap[p.pid] = String(p.command);
    }
  }

  const wrap = document.createElement("div");
  wrap.className = "discovery-wrap";

  // --- Tab bar ---
  const tabBar = document.createElement("div");
  tabBar.className = "discovery-tab-bar";
  const tabs = [
    { id: "files", label: `Files (${formatNumber(files.length)})` },
    { id: "network", label: `Network (${formatNumber(network.length)})` },
    { id: "commands", label: `Commands (${formatNumber(commands.length)})` },
  ];
  let activeDiscoveryTab = "files";

  function renderActiveTab() {
    const contentEl = wrap.querySelector(".discovery-content");
    const detailEl = wrap.querySelector(".discovery-detail");
    if (!contentEl) return;
    contentEl.innerHTML = "";
    if (detailEl) {
      detailEl.innerHTML = '<div class="replay-empty">Select a file, network endpoint, or command above to view its timeline.</div>';
    }

    // Highlight active tab button
    tabBar.querySelectorAll(".discovery-tab").forEach((btn) => {
      btn.classList.toggle("active", btn.getAttribute("data-tab") === activeDiscoveryTab);
    });

    if (activeDiscoveryTab === "files") {
      if (!fileTree || !files.length) {
        contentEl.innerHTML = '<div class="replay-empty">No file activity in this scope.</div>';
        return;
      }
      const treeWrap = document.createElement("div");
      treeWrap.className = "discovery-file-tree";
      treeWrap.appendChild(_buildAggregatedFileTree(fileTree, {
        anomalyPaths,
        onFileClick: (node) => {
          if (!detailEl) return;
          const path = String(node.path || "");
          // Find all file events matching this path and build detail items
          const matchingFile = files.find((f) => f.path === path);
          if (!matchingFile) return;
          const items = (matchingFile.pids || []).map((p) => ({
            pid: p.pid,
            command: p.command || pidCommandMap[p.pid] || "(unknown)",
            operation: matchingFile.state === "read_write" ? "read+write" : matchingFile.state,
            type: matchingFile.state,
          }));
          detailEl.innerHTML = "";
          const heading = document.createElement("div");
          heading.className = "discovery-detail-heading";
          heading.innerHTML = `<span class="detail-title">${escapeHtml(path)}</span><span class="row-sub">${formatNumber(matchingFile.event_count || 0)} events across ${formatNumber(items.length)} process${items.length === 1 ? "" : "es"}</span>`;
          detailEl.appendChild(heading);
          detailEl.appendChild(_renderResourceDetailPanel(items, {}));
          // Highlight selected file in tree
          contentEl.querySelectorAll(".tree-file").forEach((el) => el.classList.remove("discovery-selected"));
          contentEl.querySelectorAll(".tree-file").forEach((el) => {
            if (el.querySelector(".tree-name") && el.querySelector(".tree-name").textContent === node.name) {
              el.classList.add("discovery-selected");
            }
          });
        },
      }));
      // Auto-expand anomalous folders
      if (anomalyPaths.size > 0) {
        treeWrap.querySelectorAll("details.tree-dir").forEach((det) => {
          // Check if any child is anomalous
          if (det.querySelector(".tree-anomaly")) {
            det.open = true;
          }
        });
      }
      contentEl.appendChild(treeWrap);

    } else if (activeDiscoveryTab === "network") {
      if (!network.length) {
        contentEl.innerHTML = '<div class="replay-empty">No network activity in this scope.</div>';
        return;
      }
      const list = document.createElement("div");
      list.className = "discovery-net-list";
      for (const ep of network) {
        const dest = String(ep.dest || "");
        const isAnomaly = anomalyDests.has(dest) || Array.from(anomalyDests).some((d) => dest.includes(d));
        const row = document.createElement("button");
        row.className = `discovery-net-row${isAnomaly ? " discovery-net-anomaly" : ""}`;
        row.innerHTML = `
          <div class="discovery-net-dest">
            ${escapeHtml(dest)}
            ${isAnomaly ? '<span class="anomaly-indicator anomaly" title="anomaly detected"></span>' : ""}
          </div>
          <div class="discovery-net-stats">
            <span class="row-sub">${formatNumber(ep.connect_count || 0)} connects · tx ${formatNumber(ep.bytes_sent || 0)}B · rx ${formatNumber(ep.bytes_recv || 0)}B</span>
          </div>`;
        row.addEventListener("click", () => {
          if (!detailEl) return;
          const items = (ep.pids || []).map((p) => ({
            pid: p.pid,
            command: p.command || pidCommandMap[p.pid] || "(unknown)",
            operation: "net_connect",
            type: "connect",
          }));
          detailEl.innerHTML = "";
          const heading = document.createElement("div");
          heading.className = "discovery-detail-heading";
          heading.innerHTML = `<span class="detail-title">${escapeHtml(dest)}</span><span class="row-sub">${formatNumber(ep.count || 0)} events across ${formatNumber(items.length)} process${items.length === 1 ? "" : "es"}</span>`;
          detailEl.appendChild(heading);
          detailEl.appendChild(_renderResourceDetailPanel(items, {}));
          // Highlight
          list.querySelectorAll(".discovery-net-row").forEach((el) => el.classList.remove("discovery-selected"));
          row.classList.add("discovery-selected");
        });
        list.appendChild(row);
      }
      contentEl.appendChild(list);

    } else if (activeDiscoveryTab === "commands") {
      if (!commands.length) {
        contentEl.innerHTML = '<div class="replay-empty">No commands spawned in this scope.</div>';
        return;
      }
      const list = document.createElement("div");
      list.className = "discovery-cmd-list";
      for (const cmd of commands) {
        const row = document.createElement("button");
        row.className = "discovery-cmd-row";
        row.innerHTML = `
          <div class="discovery-cmd-text">${escapeHtml(cmd.command || "")}</div>
          <div class="discovery-cmd-meta">
            <span class="row-sub">pid ${escapeHtml(String(cmd.pid || ""))}</span>
            ${cmd.ppid ? `<span class="row-sub">ppid ${escapeHtml(String(cmd.ppid))}</span>` : ""}
          </div>`;
        row.addEventListener("click", () => {
          if (!detailEl) return;
          const pid = Number(cmd.pid || 0);
          // Find all files touched by this PID
          const touchedFiles = files.filter((f) => (f.pids || []).some((p) => p.pid === pid));
          const touchedNet = network.filter((n) => (n.pids || []).some((p) => p.pid === pid));

          detailEl.innerHTML = "";
          const heading = document.createElement("div");
          heading.className = "discovery-detail-heading";
          heading.innerHTML = `<span class="detail-title">pid ${escapeHtml(String(pid))} · ${escapeHtml(cmd.command || "")}</span><span class="row-sub">${formatNumber(touchedFiles.length)} files · ${formatNumber(touchedNet.length)} network endpoints</span>`;
          detailEl.appendChild(heading);

          // Show files and network touched by this command
          const items = [
            ...touchedFiles.map((f) => ({ pid, command: cmd.command, operation: f.state, type: f.state, resource: f.path })),
            ...touchedNet.map((n) => ({ pid, command: cmd.command, operation: "connect", type: "connect", resource: n.dest })),
          ];
          if (items.length) {
            for (const item of items) {
              const el = document.createElement("div");
              el.className = "discovery-detail-row";
              el.innerHTML = `
                <div class="discovery-detail-meta">
                  <span class="discovery-detail-op op-badge op-${escapeHtml(String(item.type).replace("file_", "").replace("net_", ""))}">${escapeHtml(item.operation || "")}</span>
                  <span class="mono-text" style="border:0;padding:0;background:transparent;font-size:11px;">${escapeHtml(item.resource || "")}</span>
                </div>`;
              detailEl.appendChild(el);
            }
          } else {
            detailEl.appendChild(_renderResourceDetailPanel([], {}));
          }

          // Open Full Trace button
          if (pid > 0 && selectedTraceId) {
            const btnWrap = document.createElement("div");
            btnWrap.style.marginTop = "8px";
            const openBtn = document.createElement("button");
            openBtn.className = "inline-btn discovery-open-trace-btn";
            openBtn.textContent = "Open Full Trace for this PID";
            openBtn.addEventListener("click", async () => {
              try {
                const params = new URLSearchParams();
                params.set("pid", String(pid));
                const data = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/display-trace?${params.toString()}`);
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
                window.open(URL.createObjectURL(blob), "_blank");
              } catch (_err) {
                alert("Failed to load full trace for this PID.");
              }
            });
            btnWrap.appendChild(openBtn);
            detailEl.appendChild(btnWrap);
          }

          // Highlight
          list.querySelectorAll(".discovery-cmd-row").forEach((el) => el.classList.remove("discovery-selected"));
          row.classList.add("discovery-selected");
        });
        list.appendChild(row);
      }
      contentEl.appendChild(list);
    }
  }

  for (const tab of tabs) {
    const btn = document.createElement("button");
    btn.className = `discovery-tab${tab.id === activeDiscoveryTab ? " active" : ""}`;
    btn.setAttribute("data-tab", tab.id);
    btn.textContent = tab.label;
    btn.addEventListener("click", () => {
      activeDiscoveryTab = tab.id;
      renderActiveTab();
    });
    tabBar.appendChild(btn);
  }
  wrap.appendChild(tabBar);

  // --- Content area ---
  const contentArea = document.createElement("div");
  contentArea.className = "discovery-content";
  wrap.appendChild(contentArea);

  // --- Detail panel ---
  const detailPanel = document.createElement("div");
  detailPanel.className = "discovery-detail";
  detailPanel.innerHTML = '<div class="replay-empty">Select a file, network endpoint, or command above to view its timeline.</div>';
  wrap.appendChild(detailPanel);

  container.appendChild(wrap);
  renderActiveTab();
}

async function display_trace(pid = null, start_timestamp = null, end_timestamp = null, options = {}) {
  if (!selectedTraceId) return;

  const params = new URLSearchParams();
  if (pid != null) params.set("pid", String(pid));
  if (start_timestamp != null) params.set("start_timestamp", String(start_timestamp));
  if (end_timestamp != null) params.set("end_timestamp", String(end_timestamp));

  let targetEl = options.targetEl || null;
  if (options.popup) {
    const overlay = ensureProcessTracePopup();
    const titleEl = overlay.querySelector("#processTraceTitle");
    const subtitleEl = overlay.querySelector("#processTraceSubtitle");
    const bodyEl = overlay.querySelector("#processTraceBody");
    titleEl.textContent = String(options.title || "Process Trace");
    subtitleEl.textContent = String(options.subtitle || "");
    bodyEl.innerHTML = '<div class="mono-text">Loading process trace...</div>';
    overlay.classList.add("open");
    targetEl = bodyEl;
  }

  if (!targetEl) return;

  try {
    let payload;
    try {
      payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/display-trace?${params.toString()}`);
    } catch (err) {
      if (typeof options.fallbackFetch === "function") {
        payload = await options.fallbackFetch(err);
      } else {
        throw err;
      }
    }
    const controls = document.createElement("div");
    controls.className = "group-pills";
    if (typeof options.onBack === "function") {
      const backBtn = document.createElement("button");
      backBtn.className = "inline-btn";
      backBtn.textContent = "Back";
      backBtn.addEventListener("click", () => {
        options.onBack();
      });
      controls.appendChild(backBtn);
    }

    targetEl.innerHTML = "";
    if (controls.childElementCount > 0) {
      targetEl.appendChild(controls);
    }
    const body = document.createElement("div");
    targetEl.appendChild(body);
    renderDisplayTracePayload(payload, body, {
      onSelectPid: options.onSelectPid,
      hiddenEventTypes: options.hiddenEventTypes,
    });
  } catch (_err) {
    targetEl.innerHTML = '<div class="mono-text">Failed to load trace events for this scope.</div>';
  }
}

function renderProcessTracePopup(payload, turnId, toolName, options = {}) {
  const overlay = ensureProcessTracePopup();
  const titleEl = overlay.querySelector("#processTraceTitle");
  const subtitleEl = overlay.querySelector("#processTraceSubtitle");
  const bodyEl = overlay.querySelector("#processTraceBody");
  const s = payload.summary || {};
  const hiddenEventTypes = options.hiddenEventTypes instanceof Set ? options.hiddenEventTypes : new Set();
  const visibleTimeline = coalesceConsecutiveFileGroups(
    filterDisplayTraceTimeline(payload.timeline || [], hiddenEventTypes)
  );

  titleEl.textContent = `Process Trace · pid ${String(s.pid || payload.pid || "-")}`;
  subtitleEl.textContent = String(options.subtitle || `Source: ${String(toolName || "tool output")}`);

  const wrap = document.createElement("div");
  wrap.className = "process-trace-content";

  const controls = document.createElement("div");
  controls.className = "group-pills";
  if (typeof options.onBack === "function") {
    const backBtn = document.createElement("button");
    backBtn.className = "inline-btn";
    backBtn.textContent = "Back";
    backBtn.addEventListener("click", () => {
      options.onBack();
    });
    controls.appendChild(backBtn);
  }
  const detailBtn = document.createElement("button");
  detailBtn.className = "inline-btn";
  detailBtn.textContent = detailedTraceViewEnabled ? "Detailed: On" : "Detailed: Off";
  detailBtn.addEventListener("click", () => {
    if (typeof options.onToggleDetail === "function") {
      options.onToggleDetail();
    }
  });
  controls.appendChild(detailBtn);

  const filterBtn = document.createElement("button");
  filterBtn.className = "inline-btn";
  filterBtn.textContent = "Edit Hidden Events";
  filterBtn.addEventListener("click", () => {
    if (typeof options.onEditFilters === "function") {
      options.onEditFilters();
    }
  });
  controls.appendChild(filterBtn);

  const filterLabel = document.createElement("span");
  filterLabel.className = "row-sub";
  filterLabel.textContent = detailedTraceViewEnabled
    ? "Showing all event types"
    : `Hidden in compact: ${compactHiddenEventsLabel()}`;
  controls.appendChild(filterLabel);

  if (controls.childElementCount > 0) {
    wrap.appendChild(controls);
  }

  const anomalyReport = options.anomaly && typeof options.anomaly === "object" ? options.anomaly : null;
  const anomalyMeta = normalizeAnomaly(anomalyReport);
  if (anomalyReport && anomalyMeta.has_anomaly) {
    const panel = document.createElement("div");
    panel.className = "timeline-row anomaly-panel";
    const violations = Array.isArray(anomalyReport.violations) ? anomalyReport.violations : [];
    const items = violations.slice(0, 20).map((violation) => {
      const rule = String(violation?.rule || "unknown");
      const severity = String(violation?.severity || "LOW");
      const resource = String(
        violation?.resource
          || violation?.path
          || ((violation?.dest_ip || violation?.dest_port)
            ? `${String(violation?.dest_ip || "")}:${String(violation?.dest_port || 0)}`
            : (violation?.child_binary || ""))
      );
      const operation = String(violation?.operation || violation?.reason || "");
      return `
        <div class="anomaly-row">
          <div><span class="anomaly-rule">${escapeHtml(rule)}</span> <span class="row-sub">${escapeHtml(severity)}</span></div>
          <div class="anomaly-text">${escapeHtml(resource || "(resource unavailable)")}${operation ? ` · ${escapeHtml(operation)}` : ""}</div>
        </div>`;
    }).join("");

    panel.innerHTML = `
      <div class="timeline-head">
        <span class="row-title">Tool Anomaly</span>
        ${anomalyIndicatorHtml(anomalyMeta, "tool-anomaly-indicator")}
      </div>
      <div class="row-content">
        <div class="mono-text">${escapeHtml(String(anomalyMeta.summary || "anomaly detected"))}</div>
        <div class="anomaly-list">${items || '<div class="mono-text">No violation details captured.</div>'}</div>
      </div>`;
    wrap.appendChild(panel);
  }

  const meta = document.createElement("div");
  meta.className = "group-pills";
  const rootPills = [];
  if (Number(s.child_processes_spawned || 0) > 0) rootPills.push(`${formatNumber(s.child_processes_spawned)} process${Number(s.child_processes_spawned) === 1 ? "" : "es"} spawned`);
  if (Number(s.files_read || 0) > 0) rootPills.push(`reads ${formatNumber(s.files_read)}`);
  if (Number(s.files_written || 0) > 0) rootPills.push(`writes ${formatNumber(s.files_written)}`);
  if (Number(s.network_calls || 0) > 0) rootPills.push(`network ${formatNumber(s.network_calls)}`);
  meta.innerHTML = rootPills.map((label) => `<span class="op-pill op-rename">${escapeHtml(label)}</span>`).join("");
  wrap.appendChild(meta);

  // --- Discovery Tabs (resource-centric view) ---
  const discoveryHost = document.createElement("div");
  discoveryHost.className = "discovery-host";
  renderDiscoveryTabs(payload, discoveryHost, { anomaly: anomalyReport });
  wrap.appendChild(discoveryHost);

  bodyEl.innerHTML = "";
  bodyEl.appendChild(wrap);
  overlay.classList.add("open");
}

async function openSourceTracePopup(turnId, pid, toolName, startTimestamp = null, endTimestamp = null, retainStack = false, anomaly = null) {
  if (!selectedTraceId || !turnId || !pid) return;

  if (!retainStack) {
    popupTraceViewerState = {
      turnId,
      pid,
      stack: [],
      startTimestamp,
      endTimestamp,
      title: String(toolName || "tool output"),
      anomaly: anomaly && typeof anomaly === "object" ? anomaly : null,
    };
  } else {
    popupTraceViewerState.pid = pid;
    if (anomaly && typeof anomaly === "object") {
      popupTraceViewerState.anomaly = anomaly;
    }
  }

  const state = popupTraceViewerState;
  const overlay = ensureProcessTracePopup();
  const bodyEl = overlay.querySelector("#processTraceBody");
  bodyEl.innerHTML = '<div class="mono-text">Loading process trace...</div>';
  overlay.classList.add("open");

  const params = new URLSearchParams();
  params.set("pid", String(state.pid));
  if (state.startTimestamp != null) params.set("start_timestamp", String(state.startTimestamp));
  if (state.endTimestamp != null) params.set("end_timestamp", String(state.endTimestamp));

  try {
    let payload;
    try {
      payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/display-trace?${params.toString()}`);
    } catch (err) {
      // Fallback for server instances that have not reloaded display-trace route yet.
      payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/process-subtrace/${encodeURIComponent(turnId)}/${encodeURIComponent(state.pid)}?full_lifecycle=1`);
    }

    const scopeText = state.startTimestamp == null && state.endTimestamp == null ? "full lifecycle" : "turn window";
    renderProcessTracePopup(payload, turnId, state.title, {
      subtitle: `Source: ${String(state.title)} · ${scopeText}`,
      startTimestamp: state.startTimestamp,
      endTimestamp: state.endTimestamp,
      anomaly: state.anomaly,
      hiddenEventTypes: activeHiddenTraceEventTypes(),
      onToggleDetail: async () => {
        detailedTraceViewEnabled = !detailedTraceViewEnabled;
        await openSourceTracePopup(turnId, state.pid, state.title, state.startTimestamp, state.endTimestamp, true, state.anomaly);
      },
      onEditFilters: async () => {
        const changed = editCompactTraceHiddenEventTypes();
        if (!changed) return;
        await openSourceTracePopup(turnId, state.pid, state.title, state.startTimestamp, state.endTimestamp, true, state.anomaly);
      },
      onBack: state.stack.length
        ? async () => {
            const previousPid = state.stack.pop();
            if (!previousPid) return;
            await openSourceTracePopup(turnId, previousPid, state.title, state.startTimestamp, state.endTimestamp, true, state.anomaly);
          }
        : null,
      onSelectPid: async (childPid) => {
        if (!childPid || Number(childPid) <= 0) return;
        state.stack.push(state.pid);
        await openSourceTracePopup(turnId, childPid, state.title, state.startTimestamp, state.endTimestamp, true, state.anomaly);
      },
    });
  } catch (_err) {
    bodyEl.innerHTML = '<div class="mono-text">Failed to load process trace for this source PID.</div>';
  }
}

function renderTurnDetail(payload) {
  graphCanvas.innerHTML = "";

  const turnSummary = document.createElement("div");
  turnSummary.className = "turn-exec-summary";
  turnSummary.innerHTML = `
    <div class="mini-card"><div class="k">Tool Calls</div><div class="v">${formatNumber(payload.summary.tool_calls)}</div></div>
    <div class="mini-card"><div class="k">Files Read</div><div class="v">${formatNumber(payload.summary.files_read)}</div></div>
    <div class="mini-card"><div class="k">Files Written</div><div class="v">${formatNumber(payload.summary.files_written)}</div></div>
    <div class="mini-card"><div class="k">Subprocesses</div><div class="v">${formatNumber(payload.summary.subprocesses_spawned)}</div></div>
    <div class="mini-card"><div class="k">Network Calls</div><div class="v">${formatNumber(payload.summary.network_calls)}</div></div>`;

  const collapsible = document.createElement("details");
  collapsible.className = "prompt-response";
  collapsible.open = true;
  const promptPanels = renderSectionPanels(
    "Prompt",
    payload.prompt_sections || [],
    payload.prompt_text || "No prompt text captured"
  );
  const responsePanels = renderSectionPanels(
    "Response",
    payload.response_sections || [],
    payload.response_text || "No response text captured"
  );
  collapsible.innerHTML = `
    <summary>Prompt and model response</summary>
    <div class="pr-grid">
      <div>${promptPanels}</div>
      <div>${responsePanels}</div>
    </div>`;

  const timeline = document.createElement("div");
  timeline.className = "timeline-wrap";
  const rawTimeline = payload.timeline || [];
  for (const entry of rawTimeline) {
    if (entry.entry_type === "tool_call") {
      timeline.appendChild(renderToolEntry(entry, payload.turn_id));
    } else {
      timeline.appendChild(renderSystemGroup(entry, payload.turn_id));
    }
  }

  graphCanvas.appendChild(turnSummary);
  graphCanvas.appendChild(collapsible);
  graphCanvas.appendChild(timeline);
}

function replayValueBlock(value, options = {}) {
  const sneakLines = Number(options.sneakLines || 0);
  const showSource = Boolean(options.showSource);
  const source = options.source && typeof options.source === "object" ? options.source : { status: "source_not_found" };
  const sourcePid = Number(source.pid || 0);
  let sourceHtml = "";
  if (showSource) {
    sourceHtml = sourcePid > 0
      ? `<button class="replay-source-link" data-source-pid="${String(sourcePid)}">source: pid${String(sourcePid)}</button>`
      : '<span class="replay-source-missing">source: not found</span>';
  }

  const text = typeof value === "string" ? value : JSON.stringify(value ?? null, null, 2);
  const preview = sneakLines > 0 ? truncateLines(text, sneakLines) : { short: text, long: text, truncated: false };

  return `
    <div class="replay-value-wrap">
      ${showSource ? `<div class="replay-value-head">${sourceHtml}</div>` : ""}
      <div class="replay-value-body">
        <pre class="replay-pre replay-pre-short">${escapeHtml(preview.short)}</pre>
        <pre class="replay-pre replay-pre-full" style="display:none;">${escapeHtml(preview.long)}</pre>
        ${preview.truncated ? '<button class="inline-btn replay-expand-btn">Expand</button>' : ""}
      </div>
    </div>`;
}

function replaySectionCard(section, turnId, options = {}) {
  const values = Array.isArray(section.values) ? section.values : [];
  const sectionSources = Array.isArray(section.sources) ? section.sources : [];
  const isToolOutput = String(section.style || "") === "tool_output";
  const sneakLines = Number(options.sneakLines || 0);
  const openByDefault = Boolean(options.openByDefault);
  const blocks = values.map((v, idx) => {
    if (!isToolOutput) {
      return replayValueBlock(v, { sneakLines });
    }
    const preferredSource = sectionSources[idx];
    const source = preferredSource && typeof preferredSource === "object"
      ? preferredSource
      : findReplaySourceForValue(v);
    return replayValueBlock(v, { sneakLines, showSource: true, source, turnId });
  }).join("");
  return `
    <details class="replay-card replay-${escapeHtml(section.style || "generic")}" ${openByDefault ? "open" : ""}>
      <summary class="replay-band">
        <span class="replay-band-title">${escapeHtml(section.label || "Section")} (${formatNumber(values.length)})</span>
        <span class="replay-band-toggle" aria-hidden="true"></span>
      </summary>
      <div class="replay-card-body">${blocks || '<pre class="replay-pre">No content</pre>'}</div>
    </details>`;
}

function replayToolPairCard(pair, turnId) {
  const anomaly = pair && typeof pair.anomaly === "object" ? pair.anomaly : null;
  const anomalyHtml = anomalyIndicatorHtml(anomaly, "tool-anomaly-indicator");
  const source = pair && typeof pair.source === "object" ? pair.source : { status: "source_not_found" };
  const sourcePid = Number(source.pid || 0);
  const toolCallId = String(pair?.tool_call_id || "");
  const sourceHtml = sourcePid > 0
    ? `<button class="replay-source-link" data-source-pid="${String(sourcePid)}" data-source-tool-call-id="${escapeHtml(toolCallId)}">source: pid${String(sourcePid)}</button>`
    : '<span class="replay-source-missing">source: not found</span>';

  const responseText = typeof pair?.response === "string"
    ? pair.response
    : JSON.stringify(pair?.response ?? null, null, 2);
  const response = truncateLines(responseText, 4);

  return `
    <details class="replay-card replay-tool_pair replay-tool-call-pair" open>
      <summary class="replay-band">
        <span class="replay-band-title">${escapeHtml(pair?.tool_name || "tool")} (${escapeHtml(pair?.tool_call_id || "")})</span>
        ${anomalyHtml}
        <span class="replay-band-toggle" aria-hidden="true"></span>
      </summary>
      <div class="replay-card-body">
        <div class="replay-pair-block">
          <div class="mini-label">Tool call</div>
          <pre class="replay-pre">${escapeHtml(JSON.stringify(pair?.arguments ?? {}, null, 2))}</pre>
        </div>
        <div class="replay-pair-block">
          <div class="replay-value-head">${sourceHtml}</div>
          <div class="mini-label">Tool response</div>
          <pre class="replay-pre replay-pre-short">${escapeHtml(response.short)}</pre>
          <pre class="replay-pre replay-pre-full" style="display:none;">${escapeHtml(response.long)}</pre>
          ${response.truncated ? '<button class="inline-btn replay-expand-btn">Expand</button>' : ""}
        </div>
      </div>
    </details>`;
}

function wireReplayExpanders(container) {
  container.querySelectorAll(".replay-expand-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const body = btn.closest(".replay-value-body") || btn.closest(".replay-pair-block");
      if (!body) return;
      const shortPre = body.querySelector(".replay-pre-short");
      const fullPre = body.querySelector(".replay-pre-full");
      if (!shortPre || !fullPre) return;
      const expanded = fullPre.style.display !== "none";
      fullPre.style.display = expanded ? "none" : "block";
      shortPre.style.display = expanded ? "block" : "none";
      btn.textContent = expanded ? "Expand" : "Collapse";
    });
  });
}

function ensureReplayMetricsPopup() {
  let overlay = document.getElementById("replayMetricsOverlay");
  if (overlay) return overlay;

  overlay = document.createElement("div");
  overlay.id = "replayMetricsOverlay";
  overlay.className = "replay-metrics-overlay";
  overlay.innerHTML = `
    <div class="replay-metrics-modal" role="dialog" aria-modal="true" aria-label="Replay metrics">
      <div class="process-trace-head">
        <div>
          <div class="process-trace-title" id="replayMetricsTitle">Details</div>
          <div class="process-trace-subtitle" id="replayMetricsSubtitle"></div>
        </div>
        <button class="btn" id="replayMetricsCloseBtn">Close</button>
      </div>
      <div class="process-trace-body" id="replayMetricsBody"></div>
    </div>`;

  document.body.appendChild(overlay);
  overlay.querySelector("#replayMetricsCloseBtn").addEventListener("click", () => {
    overlay.classList.remove("open");
  });
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) {
      overlay.classList.remove("open");
    }
  });
  return overlay;
}

function openReplayMetricsPopup(title, subtitle, renderBody) {
  const overlay = ensureReplayMetricsPopup();
  overlay.querySelector("#replayMetricsTitle").textContent = title || "Details";
  overlay.querySelector("#replayMetricsSubtitle").textContent = subtitle || "";
  const body = overlay.querySelector("#replayMetricsBody");
  body.innerHTML = "";
  renderBody(body);
  overlay.classList.add("open");
}

function renderReplayDetail(payload) {
  const contextSections = (((payload || {}).context || {}).sections) || [];
  const actionSections = (((payload || {}).action || {}).sections) || [];
  const replaySummary = (payload || {}).summary || {};
  const isContext = currentReplayPaneTab === "context";
  const isAction = currentReplayPaneTab === "action";
  const isSummary = currentReplayPaneTab === "summary";
  const isRawEvents = currentReplayPaneTab === "raw_events";
  const rawEventsAnomaly = normalizeAnomaly((payload || {}).raw_events_anomaly || null);
  const rawEventsHasAnomaly = Boolean((payload || {}).raw_events_has_anomaly || rawEventsAnomaly.has_anomaly || rawEventsAnomaly.verdict !== "CLEAN");
  const rawEventsTabAnomalyHtml = rawEventsHasAnomaly ? anomalyIndicatorHtml(rawEventsAnomaly, "raw-events-tab-anomaly-indicator") : "";

  let title = "Summary";
  let contentHtml = "";

  if (isContext) {
    title = "Context";
    contentHtml = contextSections.length
      ? contextSections.map((s) => replaySectionCard(s, payload.turn_id, { sneakLines: 4, openByDefault: true })).join("")
      : '<div class="replay-empty">No structured sections for this tab.</div>';
  } else if (isAction) {
    title = "Action";
    const filteredAction = actionSections.filter((s) => String(s?.id || "") !== "tool_calls");
    const actionCards = filteredAction.map((s) => replaySectionCard(s, payload.turn_id)).join("");
    const pairs = Array.isArray(payload.tool_call_response_pairs) ? payload.tool_call_response_pairs : [];
    const pairCards = pairs.length
      ? pairs.map((pair) => replayToolPairCard(pair, payload.turn_id)).join("")
      : '<div class="replay-empty">No tool calls captured for this turn.</div>';
    contentHtml = `${actionCards}<div class="replay-tool-pairs">${pairCards}</div>`;
  } else if (isSummary) {
    title = "Summary";
    contentHtml = `
      <div class="replay-summary-grid">
        <button class="replay-summary-metric replay-summary-link" data-metric="tool_calls">
          <div class="k">Tool Calls</div><div class="v">${formatNumber(replaySummary.tool_calls)}</div>
        </button>
        <div class="replay-summary-metric"><div class="k">Context Tokens</div><div class="v">${formatNumber(replaySummary.context_tokens)}</div></div>
        <button class="replay-summary-metric replay-summary-link" data-metric="files_rw">
          <div class="k">Files Read/Written</div><div class="v">${formatNumber(replaySummary.files_read)} / ${formatNumber(replaySummary.files_written)}</div>
        </button>
        <button class="replay-summary-metric replay-summary-link" data-metric="subprocesses">
          <div class="k">Subprocesses Spawned</div><div class="v">${formatNumber(replaySummary.subprocesses_spawned)}</div>
        </button>
        <div class="replay-summary-metric"><div class="k">Network Calls</div><div class="v">${formatNumber(replaySummary.network_calls)}</div></div>
        <div class="replay-summary-metric"><div class="k">Context/Action Sections</div><div class="v">${formatNumber(replaySummary.context_sections)} / ${formatNumber(replaySummary.action_sections)}</div></div>
      </div>`;
  } else if (isRawEvents) {
    title = "Raw Events";
    
    let rawEventsAnomalyPanelHtml = "";
    const rawReport = (payload || {}).raw_events_anomaly;
    if (rawReport && rawEventsHasAnomaly) {
      const violations = Array.isArray(rawReport.violations) ? rawReport.violations : [];
      const items = violations.slice(0, 20).map((violation) => {
        const rule = String(violation?.rule || "unknown");
        const severity = String(violation?.severity || "LOW");
        const resource = String(
          violation?.resource
            || violation?.path
            || ((violation?.dest_ip || violation?.dest_port)
              ? `${String(violation?.dest_ip || "")}:${String(violation?.dest_port || 0)}`
              : (violation?.child_binary || ""))
        );
        const operation = String(violation?.operation || violation?.reason || "");
        return `
          <div class="anomaly-row">
            <div><span class="anomaly-rule">${escapeHtml(rule)}</span> <span class="row-sub">${escapeHtml(severity)}</span></div>
            <div class="anomaly-text">${escapeHtml(resource || "(resource unavailable)")}${operation ? ` · ${escapeHtml(operation)}` : ""}</div>
          </div>`;
      }).join("");

      rawEventsAnomalyPanelHtml = `
        <div class="timeline-row anomaly-panel" style="margin-bottom: 12px; margin-top: 12px; border: 1px solid var(--border-color); border-radius: 6px;">
          <div class="timeline-head">
            <span class="row-title">Turn Anomaly</span>
            ${anomalyIndicatorHtml(rawEventsAnomaly, "tool-anomaly-indicator")}
          </div>
          <div class="row-content">
            <div class="mono-text">${escapeHtml(String(rawEventsAnomaly.summary || "anomaly detected"))}</div>
            <div class="anomaly-list">${items || '<div class="mono-text">No violation details captured.</div>'}</div>
          </div>
        </div>`;
    }

    contentHtml = `
      <div class="replay-raw-pane">
        ${rawEventsAnomalyPanelHtml}
        <div class="replay-raw-controls" id="replayRawControls"></div>
        <div class="replay-raw-host" id="replayRawEventsHost"><div class="replay-empty">Loading raw event trace...</div></div>
      </div>`;
  }

  const right = graphCanvas.querySelector("#replayRightPane");
  if (!right) return;
  right.innerHTML = `
    <div class="replay-pane-head">
      <div class="replay-turn-label">${escapeHtml(payload.label || payload.turn_id || "Turn")}</div>
      <div class="replay-meta">${escapeHtml(title)} view</div>
    </div>
    <div class="replay-subtabs">
      <button class="replay-subtab ${isContext ? "active" : ""}" id="replayContextTab">Context</button>
      <button class="replay-subtab ${isAction ? "active" : ""}" id="replayActionTab">Action</button>
      <button class="replay-subtab ${isSummary ? "active" : ""}" id="replaySummaryTab">Summary</button>
      <button class="replay-subtab ${isRawEvents ? "active" : ""}" id="replayRawEventsTab">Raw Events ${rawEventsTabAnomalyHtml}</button>
    </div>
    <div class="replay-sections">${contentHtml}</div>`;

  const toolPairAnomalyById = new Map();
  const replayPairs = Array.isArray(payload.tool_call_response_pairs) ? payload.tool_call_response_pairs : [];
  for (const pair of replayPairs) {
    const toolCallId = String(pair?.tool_call_id || "").trim();
    if (!toolCallId) continue;
    if (pair && typeof pair.anomaly === "object") {
      toolPairAnomalyById.set(toolCallId, pair.anomaly);
    }
  }

  wireReplayExpanders(right);

  right.querySelectorAll(".replay-source-link").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const pid = Number(btn.getAttribute("data-source-pid") || "0");
      if (!pid || !payload.turn_id) return;
      const toolCallId = String(btn.getAttribute("data-source-tool-call-id") || "").trim();
      const anomaly = toolCallId ? (toolPairAnomalyById.get(toolCallId) || null) : null;
      await openSourceTracePopup(payload.turn_id, pid, "tool output", payload.start_ts, payload.end_ts, false, anomaly);
    });
  });

  $("replayContextTab").addEventListener("click", () => {
    if (currentReplayPaneTab === "context") return;
    currentReplayPaneTab = "context";
    renderReplayDetail(payload);
  });
  $("replayActionTab").addEventListener("click", () => {
    if (currentReplayPaneTab === "action") return;
    currentReplayPaneTab = "action";
    renderReplayDetail(payload);
  });
  $("replaySummaryTab").addEventListener("click", () => {
    if (currentReplayPaneTab === "summary") return;
    currentReplayPaneTab = "summary";
    renderReplayDetail(payload);
  });
  $("replayRawEventsTab").addEventListener("click", () => {
    if (currentReplayPaneTab === "raw_events") return;
    currentReplayPaneTab = "raw_events";
    renderReplayDetail(payload);
  });

  right.querySelectorAll(".replay-summary-link").forEach((btn) => {
    btn.addEventListener("click", () => {
      const metric = btn.getAttribute("data-metric") || "";

      if (metric === "tool_calls") {
        openReplayMetricsPopup("Tool Calls", `Turn ${payload.label || payload.turn_id || ""}`, (body) => {
          const rows = Array.isArray(replaySummary.tool_call_pairs) ? replaySummary.tool_call_pairs : [];
          if (!rows.length) {
            body.innerHTML = '<div class="replay-empty">No tool calls captured in this turn.</div>';
            return;
          }
          body.innerHTML = rows.map((pair) => replayToolPairCard(pair, payload.turn_id)).join("");
          wireReplayExpanders(body);
          body.querySelectorAll(".replay-source-link").forEach((sourceBtn) => {
            sourceBtn.addEventListener("click", async () => {
              const pid = Number(sourceBtn.getAttribute("data-source-pid") || "0");
              if (!pid || !payload.turn_id) return;
              const toolCallId = String(sourceBtn.getAttribute("data-source-tool-call-id") || "").trim();
              const anomaly = toolCallId ? (toolPairAnomalyById.get(toolCallId) || null) : null;
              await openSourceTracePopup(payload.turn_id, pid, "tool output", payload.start_ts, payload.end_ts, false, anomaly);
            });
          });
        });
        return;
      }

      if (metric === "files_rw") {
        openReplayMetricsPopup("Files Read/Written", `Turn ${payload.label || payload.turn_id || ""}`, (body) => {
          const activity = replaySummary.file_activity || {};
          const tree = activity.tree || null;
          const readPaths = Array.isArray(activity.read_paths) ? activity.read_paths : [];
          const writePaths = Array.isArray(activity.write_paths) ? activity.write_paths : [];

          const summary = document.createElement("div");
          summary.className = "mono-text";
          summary.textContent = `read=${formatNumber(readPaths.length)} write=${formatNumber(writePaths.length)}`;
          body.appendChild(summary);

          if (!tree) {
            body.innerHTML += '<div class="replay-empty">No file activity captured for this turn.</div>';
            return;
          }
          const wrap = document.createElement("div");
          wrap.className = "replay-file-tree-wrap";
          wrap.appendChild(createFileTreeNode(tree, null, { disableResourceDrilldown: true }));
          body.appendChild(wrap);
        });
        return;
      }

      if (metric === "subprocesses") {
        openReplayMetricsPopup("Subprocesses", `Turn ${payload.label || payload.turn_id || ""}`, (body) => {
          const rows = Array.isArray(replaySummary.subprocesses) ? replaySummary.subprocesses : [];
          if (!rows.length) {
            body.innerHTML = '<div class="replay-empty">No subprocesses captured in this turn.</div>';
            return;
          }

          for (const row of rows) {
            const commands = Array.isArray(row.commands) ? row.commands : [];
            const block = document.createElement("div");
            block.className = "timeline-row row-process";
            block.innerHTML = `
              <div class="timeline-head">
                <span class="row-title">PID ${escapeHtml(String(row.pid || "-"))}</span>
                <span class="row-sub">ppid ${escapeHtml(String(row.parent_pid || "-"))}</span>
                <button class="inline-btn replay-subprocess-tree-link" data-pid="${escapeHtml(String(row.pid || "0"))}">View process tree</button>
              </div>
              <div class="row-content">
                <div class="mini-label">Exec commands</div>
                <pre class="mono-block">${escapeHtml(commands.join("\n") || "No command strings captured")}</pre>
              </div>`;
            body.appendChild(block);
          }

          body.querySelectorAll(".replay-subprocess-tree-link").forEach((treeBtn) => {
            treeBtn.addEventListener("click", async () => {
              const pid = Number(treeBtn.getAttribute("data-pid") || "0");
              if (!pid || !payload.turn_id) return;
              await openSourceTracePopup(payload.turn_id, pid, "subprocess", payload.start_ts, payload.end_ts);
            });
          });
        });
      }
    });
  });

  if (isRawEvents) {
    renderReplayRawEventsPane(payload);
  }
}

async function renderReplayRawEventsPane(payload) {
  const controls = graphCanvas.querySelector("#replayRawControls");
  const host = graphCanvas.querySelector("#replayRawEventsHost");
  if (!controls || !host) return;

  if (replayRawTraceViewerState.turnId !== payload.turn_id) {
    replayRawTraceViewerState = { turnId: payload.turn_id, pid: null, stack: [] };
  }
  const state = replayRawTraceViewerState;

  controls.innerHTML = "";
  if (state.stack.length > 0) {
    const backBtn = document.createElement("button");
    backBtn.className = "inline-btn";
    backBtn.textContent = "Back";
    backBtn.addEventListener("click", async () => {
      state.pid = state.stack.pop();
      await renderReplayRawEventsPane(payload);
    });
    controls.appendChild(backBtn);
  }

  const detailBtn = document.createElement("button");
  detailBtn.className = "inline-btn";
  detailBtn.textContent = detailedTraceViewEnabled ? "Detailed: On" : "Detailed: Off";
  detailBtn.addEventListener("click", async () => {
    detailedTraceViewEnabled = !detailedTraceViewEnabled;
    await renderReplayRawEventsPane(payload);
  });
  controls.appendChild(detailBtn);

  const editFiltersBtn = document.createElement("button");
  editFiltersBtn.className = "inline-btn";
  editFiltersBtn.textContent = "Edit Hidden Events";
  editFiltersBtn.addEventListener("click", async () => {
    const changed = editCompactTraceHiddenEventTypes();
    if (!changed) return;
    await renderReplayRawEventsPane(payload);
  });
  controls.appendChild(editFiltersBtn);

  const scopeLabel = document.createElement("span");
  scopeLabel.className = "row-sub";
  scopeLabel.textContent = state.pid == null
    ? "All processes in turn window"
    : `PID ${String(state.pid)} in turn window`;
  controls.appendChild(scopeLabel);

  const filterLabel = document.createElement("span");
  filterLabel.className = "row-sub";
  filterLabel.textContent = detailedTraceViewEnabled
    ? "Showing all event types"
    : `Hidden in compact: ${compactHiddenEventsLabel()}`;
  controls.appendChild(filterLabel);

  await display_trace(state.pid, payload.start_ts, payload.end_ts, {
    targetEl: host,
    hiddenEventTypes: activeHiddenTraceEventTypes(),
    onSelectPid: async (childPid) => {
      if (!childPid || Number(childPid) <= 0) return;
      state.stack.push(state.pid);
      state.pid = childPid;
      await renderReplayRawEventsPane(payload);
    },
  });
}

function stateDiffTreeNode(node, onSelectFile, depth = 0) {
  if (!node) return "";
  const kind = String(node.kind || "");
  if (kind === "file") {
    const path = String(node.path || "");
    const active = replayStateDiffFilePath === path ? " active" : "";
    const added = Number(node.lines_added || 0);
    const removed = Number(node.lines_removed || 0);
    const total = Number(node.total_changed || 0);
    const warn = node.binary || node.truncated ? " state-diff-warn" : "";
    return `<button class="state-diff-file${active}${warn}" data-path="${escapeHtml(path)}" style="padding-left:${12 + depth * 16}px;">
      <span class="state-diff-file-name">${escapeHtml(node.name || path)}</span>
      <span class="state-diff-file-stats">+${formatNumber(added)} -${formatNumber(removed)} (${formatNumber(total)})</span>
    </button>`;
  }

  const children = Array.isArray(node.children) ? node.children : [];
  const counts = node.counts || {};
  const label = node.name === "/" ? "workspace" : String(node.name || "folder");
  const body = children.map((child) => stateDiffTreeNode(child, onSelectFile, depth + 1)).join("");
  return `<details class="state-diff-folder" open>
    <summary style="padding-left:${4 + depth * 16}px;">
      <span>${escapeHtml(label)}</span>
      <span class="state-diff-folder-stats">${formatNumber(Number(counts.files || 0))} files · +${formatNumber(Number(counts.added || 0))} -${formatNumber(Number(counts.removed || 0))}</span>
    </summary>
    <div class="state-diff-folder-body">${body}</div>
  </details>`;
}

function wireStateDiffTreeEvents(container) {
  if (!container) return;
  container.querySelectorAll(".state-diff-file").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const path = btn.getAttribute("data-path") || "";
      if (!path) return;
      replayStateDiffFilePath = path;
      await loadReplayStateDiffFile(path);
    });
  });
}

function renderReplayStateDiffFilePane(payload) {
  const right = graphCanvas.querySelector("#replayRightPane");
  if (!right) return;

  if (!payload) {
    right.innerHTML = '<div class="replay-empty">Select a file to inspect the state diff.</div>';
    return;
  }

  const stats = payload.stats || {};
  right.innerHTML = `
    <div class="replay-pane-head">
      <div class="replay-turn-label">${escapeHtml(payload.path || "file")}</div>
      <div class="replay-meta">Git-style unified diff</div>
    </div>
    <div class="state-diff-metrics">
      <span class="op-pill op-read">+${formatNumber(Number(stats.lines_added || 0))}</span>
      <span class="op-pill op-write">-${formatNumber(Number(stats.lines_removed || 0))}</span>
      <span class="op-pill op-rename">Δ ${formatNumber(Number(stats.total_changed || 0))}</span>
    </div>
    <pre class="state-diff-pre">${escapeHtml(payload.diff || "No textual diff available")}</pre>`;
}

function renderReplayStateDiffLayout(payload) {
  replayStateDiffData = payload;
  const turns = Array.isArray(payload.turns) ? payload.turns : [];
  const selected = payload.selected || {};
  replayStateDiffFromTurnId = selected.from_turn_id || replayStateDiffFromTurnId;
  replayStateDiffToTurnId = selected.to_turn_id || replayStateDiffToTurnId;

  const turnOptions = turns
    .map((turn) => `<option value="${escapeHtml(String(turn.turn_id || ""))}">${escapeHtml(String(turn.label || turn.turn_id || ""))}</option>`)
    .join("");

  const treeHtml = stateDiffTreeNode(payload.tree || { name: "/", kind: "folder", children: [] }, () => {});
  const summary = payload.summary || {};

  graphCanvas.innerHTML = `
    <div class="replay-layout state-diff-layout">
      <aside class="replay-left">
        <div class="replay-left-head">State Diff Explorer</div>
        <div class="state-diff-controls">
          <label>Previous turn</label>
          <select id="stateDiffFromSelect">${turnOptions}</select>
          <label>Current turn</label>
          <select id="stateDiffToSelect">${turnOptions}</select>
          <button class="btn" id="stateDiffApplyBtn">Apply range</button>
          <div class="state-diff-summary">${formatNumber(Number(summary.files_changed || 0))} files · +${formatNumber(Number(summary.lines_added || 0))} -${formatNumber(Number(summary.lines_removed || 0))}</div>
        </div>
        <div class="state-diff-tree" id="stateDiffTree">${treeHtml}</div>
      </aside>
      <section class="replay-right" id="replayRightPane">
        <div class="replay-empty">Select a file to inspect the state diff.</div>
      </section>
    </div>`;

  const fromSel = $("stateDiffFromSelect");
  const toSel = $("stateDiffToSelect");
  if (fromSel && replayStateDiffFromTurnId) fromSel.value = replayStateDiffFromTurnId;
  if (toSel && replayStateDiffToTurnId) toSel.value = replayStateDiffToTurnId;

  const applyBtn = $("stateDiffApplyBtn");
  if (applyBtn) {
    applyBtn.addEventListener("click", async () => {
      replayStateDiffFromTurnId = fromSel ? fromSel.value : replayStateDiffFromTurnId;
      replayStateDiffToTurnId = toSel ? toSel.value : replayStateDiffToTurnId;
      replayStateDiffFilePath = "";
      await loadReplayStateDiff();
    });
  }

  wireStateDiffTreeEvents($("stateDiffTree"));
}

async function loadReplayStateDiff() {
  if (!selectedTraceId) return;
  replayViewMode = "state_diff";

  const params = new URLSearchParams();
  if (replayStateDiffFromTurnId) params.set("from_turn_id", replayStateDiffFromTurnId);
  if (replayStateDiffToTurnId) params.set("to_turn_id", replayStateDiffToTurnId);
  const payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/replay-state-diff?${params.toString()}`);
  replayStateDiffFromTurnId = (payload.selected || {}).from_turn_id || replayStateDiffFromTurnId;
  replayStateDiffToTurnId = (payload.selected || {}).to_turn_id || replayStateDiffToTurnId;
  renderReplayStateDiffLayout(payload);

  const files = Array.isArray(payload.files) ? payload.files : [];
  if (!replayStateDiffFilePath || !files.some((f) => String(f.path || "") === replayStateDiffFilePath)) {
    replayStateDiffFilePath = files.length ? String(files[0].path || "") : "";
  }
  if (replayStateDiffFilePath) {
    await loadReplayStateDiffFile(replayStateDiffFilePath);
  }
}

async function loadReplayStateDiffFile(path) {
  if (!selectedTraceId || !path) return;
  replayStateDiffFilePath = path;
  const params = new URLSearchParams({ path });
  if (replayStateDiffFromTurnId) params.set("from_turn_id", replayStateDiffFromTurnId);
  if (replayStateDiffToTurnId) params.set("to_turn_id", replayStateDiffToTurnId);

  const payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/replay-state-diff/file?${params.toString()}`);
  renderReplayStateDiffLayout(replayStateDiffData || {
    turns: [],
    selected: { from_turn_id: replayStateDiffFromTurnId, to_turn_id: replayStateDiffToTurnId },
    tree: { name: "/", kind: "folder", children: [] },
    summary: {},
  });
  renderReplayStateDiffFilePane(payload);
}

function renderReplayShell(overview) {
  if (replayViewMode === "state_diff") {
    if (replayStateDiffData) {
      renderReplayStateDiffLayout(replayStateDiffData);
      return;
    }
  }

  const existingList = graphCanvas.querySelector(".replay-turn-list");
  const scrollPos = existingList ? existingList.scrollTop : 0;

  const turns = (overview || {}).turns || [];
  const turnButtons = turns.map((turn) => {
    const active = turn.turn_id === currentReplayTurnId;
    const anomalyHtml = anomalyIndicatorHtml(turn.anomaly || null, "replay-turn-anomaly-indicator");
    return `
      <button class="replay-turn-item ${active ? "active" : ""}" data-turn-id="${escapeHtml(turn.turn_id)}">
        <div class="replay-turn-top">
          <span class="replay-turn-name">${escapeHtml(turn.label || turn.turn_id)}</span>
          <span class="replay-turn-meta-wrap"><span class="replay-turn-tools">${formatNumber(turn.tool_call_count)} tools</span>${anomalyHtml}</span>
        </div>
        <div class="replay-turn-meta">ctx ${formatNumber(turn.context_section_count)} · act ${formatNumber(turn.action_section_count)}</div>
      </button>`;
  }).join("");

  graphCanvas.innerHTML = `
    <div class="replay-layout">
      <aside class="replay-left">
        <div class="replay-left-head replay-left-head-row">
          <span>Turns</span>
          <button class="btn" id="viewStateDiffBtn">View state diff</button>
        </div>
        <div class="replay-turn-list">${turnButtons || '<div class="replay-empty">No turns available</div>'}</div>
      </aside>
      <section class="replay-right" id="replayRightPane">
        <div class="replay-empty">Select a turn to inspect context and action details.</div>
      </section>
    </div>`;

  const newList = graphCanvas.querySelector(".replay-turn-list");
  if (newList && scrollPos > 0) {
    newList.scrollTop = scrollPos;
  }

  graphCanvas.querySelectorAll(".replay-turn-item").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const turnId = btn.getAttribute("data-turn-id");
      if (!turnId) return;
      replayViewMode = "turn";
      currentReplayTurnId = turnId;
      await loadReplayTurnDetail(turnId);
    });
  });

  const stateDiffBtn = $("viewStateDiffBtn");
  if (stateDiffBtn) {
    stateDiffBtn.addEventListener("click", async () => {
      await loadReplayStateDiff();
    });
  }
}

async function loadReplayTurnDetail(turnId) {
  if (!selectedTraceId) return;
  replayViewMode = "turn";
  replayRawTraceViewerState = { turnId, pid: null, stack: [] };
  await primeReplaySourceMaps();
  const [payload, turnDetail] = await Promise.all([
    api(`/api/traces/${encodeURIComponent(selectedTraceId)}/replay-turns/${encodeURIComponent(turnId)}`),
    api(`/api/traces/${encodeURIComponent(selectedTraceId)}/turns/${encodeURIComponent(turnId)}`).catch(() => null),
  ]);
  currentReplayToolSourceIndex = turnDetail ? buildReplayToolSourceIndex(turnDetail) : [];
  if (turnDetail) {
    absorbReplayToolSourcesFromTurnDetail(turnDetail);
  }
  renderReplayShell(replayOverview || { turns: [] });
  renderReplayDetail(payload);
}

async function loadReplayOverview() {
  if (!selectedTraceId) return;
  const payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/replay-turns`);
  replayOverview = payload;
  replaySourceMapTraceId = null;
  replayViewMode = "turn";
  replayStateDiffData = null;
  replayStateDiffFilePath = "";

  const turns = payload.turns || [];
  if (turns.length > 0) {
    replayStateDiffFromTurnId = String(turns[0].turn_id || "");
    replayStateDiffToTurnId = String(turns[turns.length - 1].turn_id || replayStateDiffFromTurnId);
  } else {
    replayStateDiffFromTurnId = null;
    replayStateDiffToTurnId = null;
  }
  const strip = $("summaryStrip");
  strip.style.gridTemplateColumns = "repeat(4, 1fr)";
  strip.innerHTML = `
    <div class="summary-card"><div class="k">Turns</div><div class="v">${formatNumber(turns.length)}</div></div>
    <div class="summary-card"><div class="k">Tool Calls</div><div class="v">${formatNumber(turns.reduce((a, t) => a + Number(t.tool_call_count || 0), 0))}</div></div>
    <div class="summary-card"><div class="k">Context Sections</div><div class="v">${formatNumber(turns.reduce((a, t) => a + Number(t.context_section_count || 0), 0))}</div></div>
    <div class="summary-card"><div class="k">Action Sections</div><div class="v">${formatNumber(turns.reduce((a, t) => a + Number(t.action_section_count || 0), 0))}</div></div>`;

  currentReplayPaneTab = "context";
  if (!currentReplayTurnId || !turns.some((t) => t.turn_id === currentReplayTurnId)) {
    currentReplayTurnId = turns.length > 0 ? turns[0].turn_id : null;
  }

  renderReplayShell(payload);
  if (currentReplayTurnId) {
    await loadReplayTurnDetail(currentReplayTurnId);
  }
}

function renderProcessSubtrace(payload) {
  graphCanvas.innerHTML = "";
  const s = payload.summary || {};

  const summary = document.createElement("div");
  summary.className = "turn-exec-summary";
  summary.innerHTML = `
    <div class="mini-card"><div class="k">Command</div><div class="v mono-small">${escapeHtml(s.command || "-")}</div></div>
    <div class="mini-card"><div class="k">PID</div><div class="v">${formatNumber(s.pid)}</div></div>
    <div class="mini-card"><div class="k">Parent PID</div><div class="v">${formatNumber(s.parent_pid)}</div></div>
    <div class="mini-card"><div class="k">Duration</div><div class="v">${escapeHtml(formatMs(s.duration_ms))}</div></div>
    <div class="mini-card"><div class="k">Exit</div><div class="v">${s.exit_code == null ? "-" : escapeHtml(String(s.exit_code))}</div></div>
    <div class="mini-card"><div class="k">Files Read</div><div class="v">${formatNumber(s.files_read)}</div></div>
    <div class="mini-card"><div class="k">Files Written</div><div class="v">${formatNumber(s.files_written)}</div></div>
    <div class="mini-card"><div class="k">Child Processes</div><div class="v">${formatNumber(s.child_processes_spawned)}</div></div>
    <div class="mini-card"><div class="k">Network Calls</div><div class="v">${formatNumber(s.network_calls)}</div></div>`;

  const timeline = document.createElement("div");
  timeline.className = "timeline-wrap";
  for (const entry of payload.timeline || []) {
    timeline.appendChild(renderSystemGroup(entry, payload.turn_id));
  }

  graphCanvas.appendChild(summary);
  graphCanvas.appendChild(timeline);
}

function renderRawResource(payload, title) {
  setCollapsed(selectionSectionBody, selectionCaret, false);

  const rows = payload.events || [];
  detailsEl.innerHTML = `
    <div class="detail-title">${escapeHtml(title)}</div>
    <div class="mini-label">Preview</div>
    <pre class="mono-block">${escapeHtml(payload.preview && payload.preview.content ? payload.preview.content : (payload.preview && payload.preview.message ? payload.preview.message : "No preview"))}</pre>
    <div class="mini-label">Raw BPF events</div>
    <div class="raw-table-wrap">
      <table class="raw-table">
        <thead><tr><th>syscall</th><th>t+ms</th><th>pid</th><th>summary</th></tr></thead>
        <tbody>
          ${rows.map((row, idx) => `<tr data-idx="${idx}"><td>${escapeHtml(row.syscall)}</td><td>${escapeHtml(Math.round(Number(row.ts_rel_ms || 0)).toString())}</td><td>${escapeHtml(String(row.pid || ""))}</td><td>${escapeHtml(row.summary || "")}</td></tr>`).join("")}
        </tbody>
      </table>
    </div>
    <div class="mini-label">Event details</div>
    <pre class="mono-block" id="rawEventDetail">Select a row to inspect full syscall arguments.</pre>`;

  const detail = detailsEl.querySelector("#rawEventDetail");
  detailsEl.querySelectorAll("tr[data-idx]").forEach((tr) => {
    tr.addEventListener("click", () => {
      const idx = Number(tr.getAttribute("data-idx") || "0");
      detail.textContent = JSON.stringify(rows[idx].args || {}, null, 2);
    });
  });
}

async function loadRawResource(turnId, resourceType, resourceKey, title) {
  if (!selectedTraceId) return;
  const params = new URLSearchParams({
    turn_id: turnId,
    resource_type: resourceType,
    resource_key: resourceKey,
  });
  const payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/raw-resource-events?${params.toString()}`);
  renderRawResource(payload, title);
}

async function loadTurnDetail(turnId) {
  if (!selectedTraceId) return;
  const payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/turns/${encodeURIComponent(turnId)}`);
  renderTurnDetail(payload);
}

async function loadProcessSubtrace(turnId, pid) {
  if (!selectedTraceId) return;
  const payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/process-subtrace/${encodeURIComponent(turnId)}/${encodeURIComponent(pid)}`);
  renderProcessSubtrace(payload);
}

async function loadTurnsOverview() {
  if (!selectedTraceId) return;

  const payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/turns`);
  turnsOverview = payload;
  updateExecutiveSummary(payload.executive_summary || {});

  graphCanvas.innerHTML = "";
  const tabs = renderTurnTabs(payload.turns || []);
  graphCanvas.appendChild(tabs);

  const firstTurn = ((payload.turns || [])[0] || {}).turn_id;
  currentTurnId = firstTurn || null;
  viewStack = [];
  renderBreadcrumbs();

  if (!firstTurn) {
    graphCanvas.innerHTML = '<div class="empty-state"><h3>No turn data</h3><p>No turns were detected in this trace yet.</p></div>';
    return;
  }
}

async function restoreFromStack() {
  const top = viewStack[viewStack.length - 1];
  if (!top) {
    await loadTurnsOverview();
    return;
  }
  if (top.kind === "turn") {
    currentTurnId = top.turnId;
    const detail = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/turns/${encodeURIComponent(top.turnId)}`);
    renderTurnDetail(detail);
    const tabs = renderTurnTabs((turnsOverview || {}).turns || []);
    graphCanvas.prepend(tabs);
    return;
  }
  if (top.kind === "process") {
    await loadProcessSubtrace(top.turnId, top.pid);
  }
}

function setActiveTab(tabName) {
  activeTab = tabName;
  profilerTabBtn.classList.toggle("active", tabName === "profiler");
  replayTabBtn.classList.toggle("active", tabName === "replay");
  graphWrapper.classList.toggle("replay-mode", Boolean(selectedTraceId));
}

function getStoredCustomSchemas() {
  try {
    const raw = localStorage.getItem("mantle.customLlmSchemas") || "[]";
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (_) {
    return [];
  }
}

function saveStoredCustomSchemas(schemas) {
  localStorage.setItem("mantle.customLlmSchemas", JSON.stringify(schemas || []));
}

async function loadSettingsView() {
  const backend = await api("/api/settings/llm-schemas");
  const backendSchemas = backend.schemas || [];
  const customSchemas = getStoredCustomSchemas();

  const strip = $("summaryStrip");
  strip.style.gridTemplateColumns = "repeat(3, 1fr)";
  strip.innerHTML = `
    <div class="summary-card"><div class="k">Builtin Schemas</div><div class="v">${formatNumber((backendSchemas || []).filter((s) => String(s.id || "").startsWith("builtin_")).length)}</div></div>
    <div class="summary-card"><div class="k">Custom Schemas</div><div class="v">${formatNumber(customSchemas.length)}</div></div>
    <div class="summary-card"><div class="k">Active Schemas</div><div class="v">${formatNumber(backendSchemas.length)}</div></div>`;

  graphCanvas.innerHTML = `
    <div class="settings-wrap">
      <div class="timeline-row">
        <div class="timeline-head"><span class="row-title">LLM API Schema Settings</span><span class="row-sub">endpoint + request/response schema</span></div>
        <div class="row-content">
          <div class="mini-label">Built-in and active schemas</div>
          <pre class="mono-block" id="settingsActiveSchemas">${escapeHtml(JSON.stringify(backendSchemas, null, 2))}</pre>
        </div>
      </div>
      <div class="timeline-row">
        <div class="timeline-head"><span class="row-title">Add Custom Schema</span></div>
        <div class="row-content settings-form">
          <label class="mini-label">Schema ID</label>
          <input class="schema-input" id="schemaIdInput" placeholder="custom_vendor_chat" />
          <label class="mini-label">Name</label>
          <input class="schema-input" id="schemaNameInput" placeholder="Vendor Chat API" />
          <label class="mini-label">API Endpoint Regex</label>
          <input class="schema-input" id="schemaEndpointInput" placeholder="/v1/chat$" />
          <label class="mini-label">Request JSON schema (object)</label>
          <textarea class="schema-textarea" id="schemaRequestInput">{\n  "messages_path": "messages",\n  "instructions_path": "instructions"\n}</textarea>
          <label class="mini-label">Response JSON schema (object)</label>
          <textarea class="schema-textarea" id="schemaResponseInput">{\n  "assistant_paths": ["choices[].message.content"]\n}</textarea>
          <div class="settings-actions">
            <button class="btn" id="addSchemaBtn">Add Schema</button>
            <button class="btn" id="applySchemasBtn">Apply All Schemas</button>
          </div>
        </div>
      </div>
      <div class="timeline-row">
        <div class="timeline-head"><span class="row-title">Custom Schemas (localStorage)</span></div>
        <div class="row-content">
          <pre class="mono-block" id="settingsCustomSchemas">${escapeHtml(JSON.stringify(customSchemas, null, 2))}</pre>
        </div>
      </div>
    </div>`;

  const customEl = $("settingsCustomSchemas");
  const addBtn = $("addSchemaBtn");
  const applyBtn = $("applySchemasBtn");

  addBtn.addEventListener("click", () => {
    const id = String($("schemaIdInput").value || "").trim();
    const name = String($("schemaNameInput").value || "").trim() || id;
    const endpoint = String($("schemaEndpointInput").value || "").trim();
    if (!id || !endpoint) {
      return;
    }
    let reqObj = {};
    let respObj = {};
    try {
      reqObj = JSON.parse(String($("schemaRequestInput").value || "{}"));
      respObj = JSON.parse(String($("schemaResponseInput").value || "{}"));
    } catch (_) {
      return;
    }

    const current = getStoredCustomSchemas().filter((s) => String(s.id || "") !== id);
    current.push({ id, name, endpoint_pattern: endpoint, request: reqObj, response: respObj });
    saveStoredCustomSchemas(current);
    customEl.textContent = JSON.stringify(current, null, 2);
  });

  applyBtn.addEventListener("click", async () => {
    const merged = [...(backendSchemas || []).filter((s) => String(s.id || "").startsWith("builtin_")), ...getStoredCustomSchemas()];
    await fetch("/api/settings/llm-schemas", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ schemas: merged }),
    });
    await loadSettingsView();
  });
}

async function selectTrace(traceId) {
  selectedTraceId = traceId;
  currentTurnId = null;
  currentReplayTurnId = null;
  viewStack = [];
  graphCanvas.innerHTML = "";
  renderTraceList(cachedTraces);
  renderBreadcrumbs();
  graphWrapper.classList.toggle("replay-mode", true);
  if (activeTab === "profiler") {
    await loadTokenProfile(traceId);
  } else {
    await loadReplayOverview();
  }
}

async function refreshTraces(force = false, options = {}) {
  const preserveView = options.preserveView !== false;
  const prevSelectedTraceId = selectedTraceId;
  const payload = await api("/api/traces");
  const version = Number(payload.version || 0);
  if (!force && version === latestVersion) {
    return;
  }

  latestVersion = version;
  cachedTraces = payload.traces || [];

  if (selectedTraceId && !cachedTraces.some((t) => t.trace_id === selectedTraceId)) {
    selectedTraceId = null;
  }

  const selectedTraceChanged = prevSelectedTraceId !== selectedTraceId;
  const needsMainPaneBootstrap = graphCanvas.childElementCount === 0;

  renderTraceList(cachedTraces);

  if (!selectedTraceId) {
    graphWrapper.classList.toggle("replay-mode", false);
    renderBreadcrumbs();
    graphCanvas.innerHTML = `<div class="empty-state"><h3>Token Profiler</h3><p>Select a trace to view its token consumption profile.</p></div>`;
    return;
  }

  if (preserveView && !selectedTraceChanged && !needsMainPaneBootstrap) {
    return;
  }

  graphWrapper.classList.toggle("replay-mode", true);
  if (activeTab === "profiler") {
    await loadTokenProfile(selectedTraceId);
  } else {
    await loadReplayOverview();
  }
}

function installStyles() {
  const style = document.createElement("style");
  style.textContent = `
    .turn-tabs { display:flex; flex-direction:column; gap:10px; padding: 6px 0 14px; }
    .turn-tab { width:100%; border:1px solid var(--border); border-radius:8px; background:var(--surface); text-align:left; padding:10px; cursor:pointer; }
    .turn-tab.active { box-shadow: inset 0 0 0 2px var(--blue-500); background: var(--blue-50); }
    .turn-tab-top { display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; }
    .turn-tab-meta { display:inline-flex; align-items:center; gap:6px; margin-left:auto; }
    .turn-id { font-weight:700; font-size:12px; }
    .turn-tools { font-size:11px; color:var(--text-muted); }
    .turn-tags { display:flex; gap:6px; flex-wrap:wrap; min-height:22px; }
    .tag-pill { font-size:10px; font-weight:700; text-transform:uppercase; border-radius:999px; padding:2px 8px; }
    .pill-amber { background:#fef3c7; color:#92400e; }
    .pill-red { background:#fee2e2; color:#991b1b; }
    .pill-gray { background:#e2e8f0; color:#334155; }
    .pill-blue { background:#dbeafe; color:#1d4ed8; }
    .pill-teal { background:#ccfbf1; color:#0f766e; }
    .turn-summary { margin-top:7px; font-size:11px; color:var(--text-secondary); }

    .trace-process-group { border-bottom:1px solid var(--border-light); padding-bottom:4px; }
    .trace-process-header { display:flex; justify-content:space-between; align-items:center; padding:8px 12px 6px; background:var(--slate-50); border-top:1px solid var(--border-light); }
    .trace-process-name { font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.04em; color:var(--text-secondary); }
    .trace-process-count { font-size:10px; color:var(--text-muted); }
    .trace-process-empty { padding:8px 12px; font-size:11px; color:var(--text-muted); }
    .trace-move-select { border:1px solid var(--border); border-radius:6px; font-size:11px; padding:2px 5px; margin-left:4px; }
    .trace-row-actions { display:flex; flex-direction:column; align-items:flex-end; gap:8px; }
    .trace-row-actions .trace-delete-btn { margin:0; }

    .anomaly-indicator { width:16px; height:16px; border-radius:999px; display:inline-flex; align-items:center; justify-content:center; font-size:10px; font-weight:800; line-height:1; flex:0 0 16px; }
    .anomaly-indicator::before { content:"!"; }
    .anomaly-indicator.anomaly { background:var(--red-100); color:var(--red-600); border:1px solid var(--red-500); }
    .anomaly-indicator.verified { background:var(--emerald-100); color:var(--emerald-600); border:1px solid var(--emerald-500); }
    .anomaly-indicator.verified::before { content:"\\2713"; font-size:11px; }
    .tool-anomaly-indicator { margin-left:4px; }

    .turn-exec-summary { display:grid; grid-template-columns: repeat(5, 1fr); gap:10px; margin: 8px 0 12px; }
    .mini-card { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:10px; }
    .mini-card .k { font-size:10px; color:var(--text-muted); text-transform:uppercase; font-weight:700; }
    .mini-card .v { font-size:18px; font-weight:700; margin-top:2px; word-break:break-word; }
    .mini-card .v.mono-small { font-family:Consolas, Monaco, monospace; font-size:12px; }

    .prompt-response { background:var(--surface); border:1px solid var(--border); border-radius:8px; margin-bottom:12px; }
    .prompt-response > summary { cursor:pointer; padding:10px 12px; font-weight:700; }
    .pr-grid { display:grid; grid-template-columns: 1fr 1fr; gap:10px; padding:0 12px 12px; }
    .section-panel-list { display:grid; gap:8px; }
    .section-panel { border:1px solid var(--border); border-radius:8px; background:var(--surface); }
    .section-panel > summary { cursor:pointer; padding:8px 10px; font-size:12px; font-weight:700; }
    .section-body { padding:0 10px 10px; display:grid; gap:8px; }
    .section-count { color:var(--text-muted); font-weight:600; }

    .timeline-wrap { display:flex; flex-direction:column; gap:10px; }
    .timeline-row { border:1px solid var(--border); border-radius:8px; background:var(--surface); padding:10px 12px; }
    .timeline-head { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    .row-title { font-weight:700; font-size:13px; }
    .row-sub { font-size:11px; color:var(--text-muted); text-transform:uppercase; }
    .row-content { margin-top:8px; }

    .tool-entry { border-left:4px solid #7e22ce; }
    .source-link { margin-left:auto; border:1px solid var(--blue-100); background:var(--blue-50); color:var(--blue-600); border-radius:999px; padding:2px 8px; font-size:10px; font-weight:700; cursor:pointer; }
    .source-link:hover { background:var(--blue-100); }
    .source-missing { margin-left:auto; font-size:10px; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.03em; }
    .row-file { border-left:4px solid #d97706; }
    .row-network { border-left:4px solid #2563eb; }
    .row-process { border-left:4px solid #6b7280; }

    .inline-btn { border:1px solid var(--border); background:var(--slate-50); border-radius:6px; padding:3px 7px; font-size:11px; cursor:pointer; margin-left:auto; }
    .inline-btn:hover { background: var(--slate-100); }
    .debug-btn { margin-left:0; }
    .event-debug-btn { margin-left:auto; }
    .group-toggle { margin-left:0; }

    .mono-block, .mono-text, .raw-json pre { font-family:Consolas, Monaco, monospace; font-size:11px; white-space:pre-wrap; word-break:break-word; background:var(--slate-50); border:1px solid var(--border); border-radius:6px; padding:8px; }
    .mini-label { font-size:10px; text-transform:uppercase; font-weight:700; color:var(--text-muted); margin-bottom:4px; }

    .tree-dir { margin-left: 6px; }
    .tree-dir > summary { cursor:pointer; font-size:12px; font-weight:600; display:flex; align-items:center; justify-content:space-between; gap:8px; }
    .tree-pills { display:flex; gap:6px; }
    .tree-file { margin-left: 18px; display:flex; justify-content:space-between; font-size:12px; border:1px solid var(--border-light); border-radius:6px; padding:4px 8px; cursor:pointer; }
    .tree-file:hover { background: var(--slate-50); }
    .tree-meta { display:flex; align-items:center; gap:8px; }
    .tree-read { border-left:3px solid #d97706; }
    .tree-write { border-left:3px solid #dc2626; }
    .tree-read_write { border-left:3px solid #b45309; }
    .tree-state { font-size:10px; text-transform:uppercase; color:var(--text-muted); }
    .group-pills { display:flex; gap:6px; }
    .op-pill { font-size:10px; font-weight:700; border-radius:999px; padding:2px 7px; }
    .op-read { background:#fef3c7; color:#92400e; }
    .op-write { background:#fee2e2; color:#991b1b; }
    .op-rename { background:#dbeafe; color:#1e40af; }

    .proc-list, .net-list { display:flex; flex-direction:column; gap:6px; margin-top:8px; }
    .proc-node, .net-node { border:1px solid var(--border); background:var(--surface); border-radius:6px; text-align:left; padding:6px 8px; cursor:pointer; font-size:12px; font-family:Consolas, Monaco, monospace; list-style:none; }
    .proc-node:hover, .net-node:hover { background: var(--slate-50); }
    .proc-inline { border:1px solid var(--border); border-radius:6px; background:var(--surface); }
    .proc-inline > summary::-webkit-details-marker { display:none; }
    .proc-inline-body { padding:8px; border-top:1px solid var(--border-light); display:grid; gap:8px; }
    .proc-inline-timeline { display:grid; gap:8px; }
    .capture-flag { color:#2563eb; font-weight:700; }

    .raw-table-wrap { max-height: 280px; overflow:auto; border:1px solid var(--border); border-radius:6px; margin-bottom:8px; }
    .raw-table { width:100%; border-collapse:collapse; font-size:12px; }
    .raw-table th, .raw-table td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--border-light); }
    .raw-table tr:hover { background:var(--slate-50); cursor:pointer; }

    .settings-form { display:grid; gap:8px; }
    .schema-input { border:1px solid var(--border); border-radius:6px; padding:7px 9px; font-size:12px; }
    .schema-textarea { border:1px solid var(--border); border-radius:6px; padding:7px 9px; min-height:96px; font-family:Consolas, Monaco, monospace; font-size:12px; }
    .settings-actions { display:flex; gap:8px; margin-top:6px; }

    .replay-layout { display:grid; grid-template-columns: 280px 1fr; gap:12px; height:100%; min-height:0; }
    .replay-left { border:1px solid var(--border); border-radius:10px; background:var(--surface); overflow:hidden; display:flex; flex-direction:column; min-height:0; }
    .replay-left-head { padding:10px 12px; font-size:12px; font-weight:700; color:var(--text-secondary); border-bottom:1px solid var(--border); text-transform:uppercase; letter-spacing:0.04em; }
    .replay-left-head-row { display:flex; align-items:center; justify-content:space-between; gap:8px; }
    .replay-turn-list { overflow:auto; display:flex; flex-direction:column; flex:1; min-height:0; }
    .replay-turn-item { border:0; border-bottom:1px solid var(--border-light); background:var(--surface); text-align:left; padding:10px; cursor:pointer; }
    .replay-turn-item:hover { background:var(--slate-50); }
    .replay-turn-item.active { background:var(--blue-50); box-shadow: inset 3px 0 0 var(--blue-500); }
    .replay-turn-top { display:flex; justify-content:space-between; gap:6px; }
    .replay-turn-meta-wrap { display:inline-flex; align-items:center; gap:6px; margin-left:auto; }
    .replay-turn-name { font-size:12px; font-weight:700; color:var(--text-primary); }
    .replay-turn-tools { font-size:10px; color:var(--text-muted); text-transform:uppercase; }
    .replay-turn-meta { margin-top:4px; font-size:11px; color:var(--text-secondary); }

    .replay-right { border:1px solid var(--border); border-radius:10px; background:var(--surface); display:flex; flex-direction:column; min-height:0; min-width:0; }
    .replay-pane-head { display:flex; justify-content:space-between; align-items:center; padding:10px 12px; border-bottom:1px solid var(--border); }
    .replay-turn-label { font-weight:700; font-size:13px; color:var(--text-primary); }
    .replay-meta { font-size:11px; color:var(--text-muted); text-transform:uppercase; }
    .replay-subtabs { display:flex; gap:8px; padding:10px 12px; border-bottom:1px solid var(--border); }
    .replay-subtab { border:1px solid var(--border); border-radius:999px; padding:5px 10px; background:var(--slate-50); color:var(--text-secondary); font-size:12px; font-weight:700; cursor:pointer; }
    .replay-subtab.active { background:var(--blue-50); color:var(--blue-600); border-color:var(--blue-100); }

    .replay-sections { padding:10px 12px 14px; overflow-y:auto; overflow-x:hidden; display:flex; flex-direction:column; gap:10px; flex:1; }
    .replay-raw-pane { display:grid; gap:10px; }
    .replay-raw-controls { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
    .replay-raw-host { display:grid; gap:10px; }
    .timeline-root-collapsed > summary { cursor:pointer; font-size:12px; font-weight:700; color:var(--text-secondary); padding:6px 0; }
    .replay-card { border:1px solid var(--border); border-radius:8px; overflow:visible; }
    .replay-card > summary { list-style: none; cursor: pointer; display:flex; align-items:center; justify-content:space-between; gap:8px; }
    .replay-card > summary::-webkit-details-marker { display: none; }
    .replay-band-title { min-width: 0; }
    .replay-band-toggle { font-size: 10px; font-weight: 600; opacity: 0.8; white-space: nowrap; }
    .replay-band-toggle::before { content: "Expand"; }
    .replay-card[open] .replay-band-toggle::before { content: "Collapse"; }
    .replay-band { padding:7px 10px; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.04em; }
    .replay-card-body { padding:8px; display:grid; gap:8px; overflow:visible; }
    .replay-value-wrap { display:grid; gap:4px; }
    .replay-value-body { display:grid; gap:6px; }
    .replay-value-head { display:flex; justify-content:flex-end; }
    .replay-source-link { border:1px solid var(--blue-100); background:var(--blue-50); color:var(--blue-600); border-radius:999px; padding:2px 8px; font-size:10px; font-weight:700; cursor:pointer; }
    .replay-source-link:hover { background:var(--blue-100); }
    .replay-source-missing { font-size:10px; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.03em; }
    .replay-pre { margin:0; white-space:pre-wrap; word-break:break-word; font-family:Consolas, Monaco, monospace; font-size:11px; background:var(--slate-50); border:1px solid var(--border); border-radius:6px; padding:8px; overflow:visible; }
    .replay-empty { color:var(--text-muted); font-size:12px; padding:16px; text-align:center; }
    .replay-tool-pairs { display:grid; gap:10px; }
    .replay-tool-call-pair .replay-band { background:#dcfce7; color:#065f46; }
    .replay-pair-block { display:grid; gap:4px; }

    .replay-summary-grid { display:grid; grid-template-columns: repeat(3, 1fr); gap:10px; }
    .replay-summary-metric { border:1px solid var(--border); border-radius:8px; background:var(--slate-50); padding:10px; text-align:left; }
    .replay-summary-metric .k { font-size:10px; text-transform:uppercase; color:var(--text-muted); font-weight:700; letter-spacing:0.04em; }
    .replay-summary-metric .v { font-size:16px; font-weight:700; color:var(--text-primary); margin-top:3px; word-break:break-word; }
    .replay-summary-link { cursor:pointer; }
    .replay-summary-link:hover { border-color:var(--blue-100); background:var(--blue-50); }

    .replay-file-tree-wrap { border:1px solid var(--border); border-radius:8px; padding:8px; margin-top:8px; max-height:56vh; overflow:auto; }

    .state-diff-layout .replay-left { min-width: 300px; }
    .state-diff-controls { display:grid; gap:6px; padding:10px; border-bottom:1px solid var(--border); }
    .state-diff-controls label { font-size:11px; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.03em; }
    .state-diff-controls select { border:1px solid var(--border); border-radius:6px; padding:6px 8px; font-size:12px; background:var(--surface); }
    .state-diff-summary { font-size:11px; color:var(--text-secondary); }
    .state-diff-tree { overflow:auto; padding:8px; display:grid; gap:4px; }
    .state-diff-folder { border:1px solid var(--border-light); border-radius:6px; background:var(--surface); }
    .state-diff-folder > summary { list-style:none; cursor:pointer; display:flex; align-items:center; justify-content:space-between; gap:8px; padding:6px 8px; font-size:12px; font-weight:600; }
    .state-diff-folder > summary::-webkit-details-marker { display:none; }
    .state-diff-folder-stats { color:var(--text-muted); font-size:10px; font-weight:500; }
    .state-diff-folder-body { display:grid; gap:3px; padding-bottom:4px; }
    .state-diff-file { border:0; background:transparent; text-align:left; width:100%; cursor:pointer; display:flex; align-items:center; justify-content:space-between; gap:6px; padding:4px 8px; font-size:12px; color:var(--text-primary); }
    .state-diff-file:hover { background:var(--slate-50); }
    .state-diff-file.active { background:var(--blue-50); box-shadow: inset 3px 0 0 var(--blue-500); }
    .state-diff-file-name { font-family:Consolas, Monaco, monospace; }
    .state-diff-file-stats { font-size:10px; color:var(--text-muted); white-space:nowrap; }
    .state-diff-warn .state-diff-file-stats { color:var(--amber-600); }
    .state-diff-metrics { display:flex; gap:6px; padding:10px 12px; border-bottom:1px solid var(--border); }
    .state-diff-pre { margin:0; border:0; border-radius:0; padding:12px; flex:1; overflow:auto; white-space:pre; word-break:normal; font-family:Consolas, Monaco, monospace; font-size:12px; background:#0b1320; color:#dbe7ff; }

    .replay-system .replay-band { background:#dbeafe; color:#1e3a8a; }
    .replay-developer .replay-band { background:#ede9fe; color:#5b21b6; }
    .replay-user .replay-band { background:#d1fae5; color:#065f46; }
    .replay-assistant .replay-band { background:#fee2e2; color:#991b1b; }
    .replay-tool_output .replay-band { background:#fef3c7; color:#92400e; }
    .replay-tool_call .replay-band { background:#cffafe; color:#155e75; }
    .replay-tools .replay-band { background:#e2e8f0; color:#334155; }
    .replay-generic .replay-band { background:#f1f5f9; color:#334155; }

    .graph-wrapper.replay-mode { overflow: hidden; }
    .graph-wrapper.replay-mode .graph-canvas { padding: 10px 12px 12px; height:100%; min-height:0; }

    .process-trace-overlay { position:fixed; inset:0; background:rgba(15,23,42,0.42); display:none; align-items:center; justify-content:center; padding:18px; z-index:1200; }
    .process-trace-overlay.open { display:flex; }
    .process-trace-modal { width:min(1120px, 96vw); max-height:90vh; background:var(--surface); border:1px solid var(--border); border-radius:12px; box-shadow:0 24px 48px rgba(15,23,42,0.22); display:flex; flex-direction:column; overflow:hidden; }
    .process-trace-head { display:flex; align-items:center; justify-content:space-between; gap:10px; padding:10px 12px; border-bottom:1px solid var(--border); }
    .process-trace-title { font-size:14px; font-weight:700; color:var(--text-primary); }
    .process-trace-subtitle { font-size:11px; color:var(--text-muted); margin-top:2px; }
    .process-trace-body { padding:12px; overflow:auto; }
    .process-trace-content { display:grid; gap:10px; }
    .anomaly-panel { border-left:4px solid var(--red-500); background:var(--red-50); }
    .anomaly-list { display:grid; gap:6px; margin-top:8px; }
    .anomaly-row { border:1px solid var(--red-100); border-radius:6px; background:var(--surface); padding:6px 8px; }
    .anomaly-rule { font-size:10px; font-weight:700; color:var(--red-600); text-transform:uppercase; letter-spacing:0.03em; }
    .anomaly-text { margin-top:2px; font-size:11px; color:var(--text-secondary); word-break:break-word; }

    .replay-metrics-overlay { position:fixed; inset:0; background:rgba(15,23,42,0.38); display:none; align-items:center; justify-content:center; padding:18px; z-index:1100; }
    .replay-metrics-overlay.open { display:flex; }
    .replay-metrics-modal { width:min(980px, 96vw); max-height:88vh; background:var(--surface); border:1px solid var(--border); border-radius:12px; box-shadow:0 20px 42px rgba(15,23,42,0.2); display:flex; flex-direction:column; overflow:hidden; }

    /* === Discovery Tabs (event viewer redesign) === */
    .discovery-wrap { display:flex; flex-direction:column; gap:0; border:1px solid var(--border); border-radius:10px; overflow:hidden; background:var(--surface); }
    .discovery-host { margin-top:10px; }
    .discovery-tab-bar { display:flex; gap:0; border-bottom:1px solid var(--border); background:var(--slate-50); }
    .discovery-tab { flex:1; border:0; border-bottom:3px solid transparent; background:transparent; padding:10px 14px; font-size:12px; font-weight:700; color:var(--text-secondary); cursor:pointer; transition:all .15s; text-align:center; }
    .discovery-tab:hover { background:var(--slate-100); color:var(--text-primary); }
    .discovery-tab.active { background:var(--surface); color:var(--blue-600); border-bottom-color:var(--blue-500); }
    .discovery-content { padding:10px; max-height:40vh; overflow:auto; min-height:100px; }
    .discovery-file-tree { }
    .discovery-file-tree .tree-dir { margin-left:4px; }
    .discovery-file-tree .tree-file { transition:all .12s; }
    .discovery-file-tree .tree-file.discovery-selected { background:var(--blue-50); box-shadow:inset 3px 0 0 var(--blue-500); }

    /* Anomaly highlights on tree nodes */
    .tree-anomaly { border-color:var(--red-200) !important; background:var(--red-50) !important; }
    .tree-anomaly .tree-name { color:var(--red-600); font-weight:700; }
    .tree-anomaly-icon { margin-left:4px; }

    /* Network list */
    .discovery-net-list { display:flex; flex-direction:column; gap:6px; }
    .discovery-net-row { border:1px solid var(--border); border-radius:8px; background:var(--surface); text-align:left; padding:8px 10px; cursor:pointer; transition:all .12s; width:100%; }
    .discovery-net-row:hover { background:var(--slate-50); border-color:var(--slate-300); }
    .discovery-net-row.discovery-selected { background:var(--blue-50); box-shadow:inset 3px 0 0 var(--blue-500); }
    .discovery-net-anomaly { border-color:var(--red-200); background:var(--red-50); }
    .discovery-net-anomaly:hover { background:var(--red-100); }
    .discovery-net-dest { font-size:12px; font-weight:600; font-family:Consolas, Monaco, monospace; color:var(--text-primary); display:flex; align-items:center; gap:6px; }
    .discovery-net-stats { margin-top:3px; }

    /* Commands list */
    .discovery-cmd-list { display:flex; flex-direction:column; gap:6px; }
    .discovery-cmd-row { border:1px solid var(--border); border-radius:8px; background:var(--surface); text-align:left; padding:8px 10px; cursor:pointer; transition:all .12s; width:100%; }
    .discovery-cmd-row:hover { background:var(--slate-50); border-color:var(--slate-300); }
    .discovery-cmd-row.discovery-selected { background:var(--blue-50); box-shadow:inset 3px 0 0 var(--blue-500); }
    .discovery-cmd-text { font-size:12px; font-weight:600; font-family:Consolas, Monaco, monospace; color:var(--text-primary); word-break:break-all; }
    .discovery-cmd-meta { margin-top:3px; display:flex; gap:8px; }

    /* Detail panel (contextual drill-down) */
    .discovery-detail { padding:10px; border-top:1px solid var(--border); background:var(--slate-50); min-height:60px; max-height:36vh; overflow:auto; }
    .discovery-detail-heading { display:flex; align-items:baseline; gap:8px; flex-wrap:wrap; margin-bottom:8px; padding-bottom:6px; border-bottom:1px solid var(--border); }
    .discovery-detail-heading .detail-title { font-size:13px; font-weight:700; font-family:Consolas, Monaco, monospace; color:var(--text-primary); word-break:break-all; }
    .discovery-detail-panel { display:flex; flex-direction:column; gap:6px; }
    .discovery-detail-row { border:1px solid var(--border-light); border-radius:6px; background:var(--surface); padding:6px 8px; }
    .discovery-detail-meta { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
    .discovery-detail-pid { font-size:11px; font-weight:700; color:var(--text-secondary); font-family:Consolas, Monaco, monospace; }
    .discovery-detail-op { }
    .discovery-detail-ts { font-size:10px; color:var(--text-muted); font-variant-numeric:tabular-nums; }
    .discovery-detail-cmd { font-size:11px; }

    /* Open Full Trace button */
    .discovery-open-trace-btn { margin-left:auto; border:1px solid var(--blue-100); background:var(--blue-50); color:var(--blue-600); border-radius:999px; padding:2px 10px; font-size:10px; font-weight:700; cursor:pointer; transition:all .15s; white-space:nowrap; }
    .discovery-open-trace-btn:hover { background:var(--blue-100); border-color:var(--blue-200); }

    @media (max-width: 1200px) {
      .turn-exec-summary { grid-template-columns: repeat(3, 1fr); }
      .pr-grid { grid-template-columns: 1fr; }
      .replay-layout { grid-template-columns: 220px 1fr; }
      .replay-summary-grid { grid-template-columns: repeat(2, 1fr); }
    }
    @media (max-width: 820px) {
      .turn-exec-summary { grid-template-columns: repeat(2, 1fr); }
      .replay-layout { grid-template-columns: 1fr; }
      .replay-left { max-height: 240px; }
      .replay-summary-grid { grid-template-columns: 1fr; }
    }
  `;
  document.head.appendChild(style);
}

async function init() {
  installStyles();
  loadProcessState();

  setCollapsed(fileSectionBody, fileCaret, true);
  setCollapsed(toolsSectionBody, toolsCaret, true);
  setCollapsed(selectionSectionBody, selectionCaret, false);

  fileToggle.addEventListener("click", () => {
    const collapsed = fileSectionBody.style.display !== "none";
    setCollapsed(fileSectionBody, fileCaret, collapsed);
  });
  toolsToggle.addEventListener("click", () => {
    const collapsed = toolsSectionBody.style.display !== "none";
    setCollapsed(toolsSectionBody, toolsCaret, collapsed);
  });
  selectionToggle.addEventListener("click", () => {
    const collapsed = selectionSectionBody.style.display !== "none";
    setCollapsed(selectionSectionBody, selectionCaret, collapsed);
  });

  // Legacy zoom controls are not used in turn view.
  zoomInBtn.style.display = "none";
  zoomOutBtn.style.display = "none";
  fitBtn.style.display = "none";
  $("zoomDisplay").style.display = "none";

  if (addProcessBtn) {
    addProcessBtn.addEventListener("click", createProcess);
  }

  profilerTabBtn.addEventListener("click", async () => {
    if (activeTab === "profiler") return;
    setActiveTab("profiler");
    viewStack = [];
    renderBreadcrumbs();
    if (selectedTraceId) {
      await loadTokenProfile(selectedTraceId);
    } else {
      graphCanvas.innerHTML = `<div class="empty-state"><h3>Token Profiler</h3><p>Select a trace to view its token consumption profile.</p></div>`;
    }
  });

  replayTabBtn.addEventListener("click", async () => {
    if (activeTab === "replay") return;
    setActiveTab("replay");
    viewStack = [];
    renderBreadcrumbs();
    if (selectedTraceId) {
      await loadReplayOverview();
    } else {
      graphCanvas.innerHTML = `<div class="empty-state"><h3>Replay</h3><p>Select a trace to view its turn-by-turn replay.</p></div>`;
    }
  });

  setActiveTab("profiler");
  await refreshTraces(true, { preserveView: false });

  setInterval(async () => {
    try {
      await refreshTraces(false, { preserveView: true });
    } catch (_) {
      // keep polling
    }
  }, 3000);

  try {
    const protocol = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${protocol}://${location.host}/ws`);
    ws.onmessage = async (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === "version" && Number(msg.version) !== latestVersion) {
        await refreshTraces(false, { preserveView: true });
      }
    };
    ws.onerror = () => ws.close();
  } catch (_) {
    // websocket optional
  }
}

init();
