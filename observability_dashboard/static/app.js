/* ===================================================================
   Agent Trace Observatory – Frontend
   HTML/SVG graph rendering with dagre layout, vertical scrolling,
   smooth zoom, file-activity panel, breadcrumb navigation.
   =================================================================== */

// ─── State ────────────────────────────────────────────────────────
let selectedTraceId = null;
let currentMode = "high"; // "high" | "tool"
let currentToolCallId = null;
let cachedTraces = [];
let latestVersion = -1;
let zoomLevel = 1;
let selectedNodeId = null;
let cachedTraceFiles = []; // trace-level files cache
let currentStraceMode = false; // true when showing strace-only (no trajectory)

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
const zoomInBtn = $("zoomInBtn");
const zoomOutBtn = $("zoomOutBtn");
const fitBtn = $("fitBtn");
const zoomDisplay = $("zoomDisplay");

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
      <div class="trace-name">${escapeHtml(t.trace_id)}</div>
      <div class="trace-meta">
        <span class="trace-status ${statusCls}">${t.status}</span>
        &nbsp;agent: ${t.agent_event_count} &nbsp;sys: ${t.sys_event_count}
      </div>`;
    div.onclick = () => selectTrace(t.trace_id);
    traceListEl.appendChild(div);
  }
}

async function selectTrace(traceId) {
  selectedTraceId = traceId;
  currentMode = "high";
  currentToolCallId = null;
  selectedNodeId = null;
  zoomLevel = 1;
  applyZoom();
  renderTraceList(cachedTraces);
  await loadHighLevelGraph();
  await loadTraceSummary();
}

// ─── Summary cards ────────────────────────────────────────────────
function updateSummaryCards(summary) {
  if (currentStraceMode) {
    // Strace-only mode: show system-level stats
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
}

async function goBackToHighLevel() {
  currentMode = "high";
  currentToolCallId = null;
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

// ─── File Tree Building ────────────────────────────────────────────
function buildFileTree(files) {
  const root = { name: "", children: {}, files: [] };

  for (const f of files) {
    const path = f.path.replace(/^\/+/, "");
    const parts = path.split("/");
    let node = root;

    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (!node.children[part]) {
        node.children[part] = { name: part, children: {}, files: [] };
      }
      node = node.children[part];
    }

    node.files.push({ ...f, fileName: parts[parts.length - 1] });
  }

  compressSingleChildChains(root);
  return root;
}

function compressSingleChildChains(node) {
  for (const key of Object.keys(node.children)) {
    compressSingleChildChains(node.children[key]);
  }
  const childKeys = Object.keys(node.children);
  if (childKeys.length === 1 && node.files.length === 0) {
    const key = childKeys[0];
    const child = node.children[key];
    node.name = node.name ? node.name + "/" + child.name : child.name;
    node.children = child.children;
    node.files = child.files;
  }
}

function countFilesInTree(node) {
  let count = node.files.length;
  for (const key of Object.keys(node.children)) {
    count += countFilesInTree(node.children[key]);
  }
  return count;
}

function renderFileTreeNode(node, container, depth) {
  const childKeys = Object.keys(node.children).sort();

  // Render child folders first
  for (const key of childKeys) {
    const child = node.children[key];
    const totalFiles = countFilesInTree(child);

    const wrapper = document.createElement("div");
    wrapper.className = "folder-wrapper";

    const row = document.createElement("div");
    row.className = "file-row folder-row";
    row.style.paddingLeft = 12 + depth * 16 + "px";
    row.innerHTML = `
      <div class="file-path folder-path">
        <span class="folder-toggle">▶</span>
        <span class="folder-icon">📁</span>
        <span>${escapeHtml(child.name)}/</span>
        <span class="file-count">${totalFiles} file${totalFiles !== 1 ? "s" : ""}</span>
      </div>`;

    const childContainer = document.createElement("div");
    childContainer.className = "folder-children";
    childContainer.style.display = "none";

    let expanded = false;
    let childrenRendered = false;

    row.addEventListener("click", (e) => {
      e.stopPropagation();
      expanded = !expanded;
      if (!childrenRendered) {
        renderFileTreeNode(child, childContainer, depth + 1);
        childrenRendered = true;
      }
      childContainer.style.display = expanded ? "block" : "none";
      row.querySelector(".folder-toggle").textContent = expanded ? "▼" : "▶";
    });

    wrapper.appendChild(row);
    wrapper.appendChild(childContainer);
    container.appendChild(wrapper);
  }

  // Render direct files (with grouping if > 3)
  const fileList = node.files;
  if (fileList.length > 0 && fileList.length <= 3) {
    for (const f of fileList) {
      const row = document.createElement("div");
      row.className = "file-row";
      row.style.paddingLeft = 12 + depth * 16 + "px";
      const opsHtml = (f.ops || [])
        .map((op) => `<span class="op-badge op-${op}">${op}</span>`)
        .join("");
      row.innerHTML = `
        <div class="file-path">${escapeHtml(f.fileName)}</div>
        <div class="file-ops">
          ${opsHtml}
          <span class="file-count">×${f.count || 0}</span>
        </div>`;
      container.appendChild(row);
    }
  } else if (fileList.length > 3) {
    // Show first file
    const first = fileList[0];
    const firstRow = document.createElement("div");
    firstRow.className = "file-row";
    firstRow.style.paddingLeft = 12 + depth * 16 + "px";
    const firstOpsHtml = (first.ops || [])
      .map((op) => `<span class="op-badge op-${op}">${op}</span>`)
      .join("");
    firstRow.innerHTML = `
      <div class="file-path">${escapeHtml(first.fileName)}</div>
      <div class="file-ops">
        ${firstOpsHtml}
        <span class="file-count">×${first.count || 0}</span>
      </div>`;
    container.appendChild(firstRow);

    // Collapsed "+ N other files" group
    const remaining = fileList.length - 1;
    const groupWrapper = document.createElement("div");
    groupWrapper.className = "folder-wrapper";

    const groupRow = document.createElement("div");
    groupRow.className = "file-row folder-row grouped-files-row";
    groupRow.style.paddingLeft = 12 + depth * 16 + "px";
    groupRow.innerHTML = `
      <div class="file-path grouped-path">
        <span class="folder-toggle">▶</span>
        ${escapeHtml(first.fileName)} + ${remaining} other file${remaining !== 1 ? "s" : ""}
      </div>`;

    const restContainer = document.createElement("div");
    restContainer.className = "folder-children";
    restContainer.style.display = "none";

    let groupExpanded = false;
    let groupRendered = false;

    groupRow.addEventListener("click", (e) => {
      e.stopPropagation();
      groupExpanded = !groupExpanded;
      if (!groupRendered) {
        for (let i = 1; i < fileList.length; i++) {
          const f = fileList[i];
          const row = document.createElement("div");
          row.className = "file-row";
          row.style.paddingLeft = 12 + (depth + 1) * 16 + "px";
          const opsHtml = (f.ops || [])
            .map((op) => `<span class="op-badge op-${op}">${op}</span>`)
            .join("");
          row.innerHTML = `
            <div class="file-path">${escapeHtml(f.fileName)}</div>
            <div class="file-ops">
              ${opsHtml}
              <span class="file-count">×${f.count || 0}</span>
            </div>`;
          restContainer.appendChild(row);
        }
        groupRendered = true;
      }
      restContainer.style.display = groupExpanded ? "block" : "none";
      groupRow.querySelector(".folder-toggle").textContent = groupExpanded ? "▼" : "▶";
    });

    groupWrapper.appendChild(groupRow);
    groupWrapper.appendChild(restContainer);
    container.appendChild(groupWrapper);
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
        const bytesStr = n.bytes > 1024 ? `${(n.bytes / 1024).toFixed(1)}KB` : (n.bytes > 0 ? `${n.bytes}B` : "");
        row.innerHTML = `
          <div class="file-path" style="color:var(--emerald-600);">${escapeHtml(n.dest)}</div>
          <div class="file-ops">
            ${opsHtml}
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
      const tree = buildFileTree(filtered);

      // Show common prefix if present
      if (tree.name) {
        const prefixRow = document.createElement("div");
        prefixRow.className = "file-row tree-root-prefix";
        prefixRow.innerHTML = `<div class="file-path" style="color:var(--text-muted);font-size:11px;">📂 ${escapeHtml(tree.name)}/</div>`;
        filesListEl.appendChild(prefixRow);
      }

      renderFileTreeNode(tree, filesListEl, tree.name ? 1 : 0);
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
  const metaStr = JSON.stringify(meta, null, 2);
  detailsEl.innerHTML = `
    <div class="detail-title">${escapeHtml(nodeData.label || nodeData.id)}</div>
    <pre>${escapeHtml(metaStr)}</pre>`;
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
    const kindLabels = { prompt: "User Prompt", tool_step: "Tool Call", assistant_response: "Agent Response" };
    const kindLabel = kindLabels[kind] || kind;
    const duration = formatDuration(meta.duration_ms);

    let titleText = "";
    let bodyText = "";

    if (kind === "prompt") {
      titleText = "User Prompt";
      bodyText = truncate(meta.content);
    } else if (kind === "tool_step") {
      titleText = meta.tool_name || "Tool";
      const args = meta.arguments || {};
      if (args.command) {
        bodyText = args.command;
      } else {
        bodyText = truncate(JSON.stringify(args));
      }
    } else if (kind === "assistant_response") {
      titleText = "Agent Response";
      bodyText = truncate(meta.content);
    }

    let footerHtml = "";
    if (kind === "tool_step") {
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
      <div class="tnode-body"><code>${escapeHtml(bodyText)}</code></div>
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
      if ((kind === "tool_step" || kind === "tool_call") && meta.tool_call_id) {
        currentMode = "tool";
        currentToolCallId = meta.tool_call_id;
        zoomLevel = 1;
        applyZoom();
        await loadToolGraph(meta.tool_call_id);

        try {
          const summary = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/tool-summary/${encodeURIComponent(meta.tool_call_id)}`);
          const files = summary.files || [];
          const net = summary.network || [];
          window._lastToolFiles = files;
          window._lastToolNetwork = net;
          if (files.length > 0 || net.length > 0) {
            renderFiles(files, `Files for: ${meta.tool_name || meta.tool_call_id}`, files.length, net);
          } else {
            renderFiles(cachedTraceFiles, "No tool-specific files — showing trace-level activity", cachedTraceFiles.length, window._cachedTraceNetwork);
          }
        } catch (_) {
          renderFiles(cachedTraceFiles, "Trace-level file activity", cachedTraceFiles.length, window._cachedTraceNetwork);
        }
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

// ─── Strace-Only Timeline Renderer ────────────────────────────────
function renderStraceTimeline(payload) {
  graphCanvas.innerHTML = "";
  emptyState.style.display = "none";

  const nodes = payload.nodes || [];
  if (nodes.length === 0) {
    graphCanvas.innerHTML = '<div class="empty-state"><h3>No system events</h3><p>The strace log contained no recognizable commands.</p></div>';
    return;
  }

  // Banner
  const banner = document.createElement("div");
  banner.className = "strace-mode-banner";
  banner.textContent = "⚡ Strace-only mode — no agent trajectory available. Showing system-level command timeline.";

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

// ─── Loaders ──────────────────────────────────────────────────────
async function loadHighLevelGraph() {
  if (!selectedTraceId) return;
  renderBreadcrumbs();
  const payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/high-level-graph`);

  if (payload.mode === "strace_only") {
    currentStraceMode = true;
    updateSummaryCards(payload.summary || {});
    renderStraceTimeline(payload);
  } else {
    currentStraceMode = false;
    updateSummaryCards(payload.summary || {});
    renderHighLevelGraph(payload);
  }
}

async function loadToolGraph(toolCallId) {
  if (!selectedTraceId) return;
  renderBreadcrumbs();
  const payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/tool-graph/${encodeURIComponent(toolCallId)}`);
  renderDAGGraph(payload);
}

async function loadTraceSummary() {
  if (!selectedTraceId) return;
  try {
    const summary = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/summary`);
    cachedTraceFiles = summary.files || [];
    window._cachedTraceNetwork = summary.network || [];
    const total = summary.totals?.unique_files ?? cachedTraceFiles.length;
    renderFiles(cachedTraceFiles, "Trace-level file activity", total, window._cachedTraceNetwork);
  } catch {
    cachedTraceFiles = [];
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
  if (!selectedTraceId && traces.length > 0) {
    selectedTraceId = traces[0].trace_id;
  }

  renderTraceList(traces);
  if (!selectedTraceId) return;

  if (!keepView || currentMode === "high") {
    await loadHighLevelGraph();
  } else if (currentToolCallId) {
    await loadToolGraph(currentToolCallId);
  }
  await loadTraceSummary();
}

// ─── Init ─────────────────────────────────────────────────────────
async function init() {
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
