let selectedTraceId = null;
let currentMode = "high";
let currentToolCallId = null;
let cy = null;
let cachedTraces = [];
let latestVersion = -1;

const traceListEl = document.getElementById("traceList");
const traceTitleEl = document.getElementById("traceTitle");
const viewModeEl = document.getElementById("viewMode");
const detailsEl = document.getElementById("details");
const backBtn = document.getElementById("backBtn");
const zoomInBtn = document.getElementById("zoomInBtn");
const zoomOutBtn = document.getElementById("zoomOutBtn");
const fitBtn = document.getElementById("fitBtn");
const filesListEl = document.getElementById("filesList");
const traceSummaryMetaEl = document.getElementById("traceSummaryMeta");

const sumPromptsEl = document.getElementById("sumPrompts");
const sumToolsEl = document.getElementById("sumTools");
const sumResponsesEl = document.getElementById("sumResponses");
const sumStatusEl = document.getElementById("sumStatus");

backBtn.addEventListener("click", async () => {
  currentMode = "high";
  currentToolCallId = null;
  backBtn.style.display = "none";
  await loadHighLevelGraph();
  await loadTraceSummary();
});

zoomInBtn.addEventListener("click", () => {
  if (!cy) return;
  cy.zoom({ level: cy.zoom() * 1.2, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
});

zoomOutBtn.addEventListener("click", () => {
  if (!cy) return;
  cy.zoom({ level: cy.zoom() / 1.2, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
});

fitBtn.addEventListener("click", () => {
  if (!cy) return;
  cy.fit(undefined, 24);
});

async function api(path) {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`API error ${res.status}`);
  return res.json();
}

function renderTraceList(traces) {
  cachedTraces = traces;
  traceListEl.innerHTML = "";
  for (const trace of traces) {
    const div = document.createElement("div");
    div.className = "trace-item" + (trace.trace_id === selectedTraceId ? " active" : "");
    div.innerHTML = `
      <div><strong>${trace.trace_id}</strong></div>
      <div class="muted">${trace.status} • agent=${trace.agent_event_count}, sys=${trace.sys_event_count}</div>
    `;
    div.onclick = async () => {
      selectedTraceId = trace.trace_id;
      currentMode = "high";
      currentToolCallId = null;
      backBtn.style.display = "none";
      renderTraceList(cachedTraces);
      await loadHighLevelGraph();
      await loadTraceSummary();
    };
    traceListEl.appendChild(div);
  }
}

function renderFiles(files, meta) {
  traceSummaryMetaEl.textContent = meta || "";
  filesListEl.innerHTML = "";
  if (!files || files.length === 0) {
    filesListEl.innerHTML = `<div class="file-row muted">No user-visible file activity in this scope.</div>`;
    return;
  }

  for (const f of files.slice(0, 120)) {
    const row = document.createElement("div");
    row.className = "file-row";
    row.innerHTML = `
      <div style="font-size:12px; font-weight:600; word-break:break-word;">${f.path}</div>
      <div class="ops">${(f.ops || []).join(", ")} • x${f.count || 0}</div>
    `;
    filesListEl.appendChild(row);
  }
}

function updateSummaryCards(summary) {
  const s = summary || {};
  sumPromptsEl.textContent = String(s.prompts ?? 0);
  sumToolsEl.textContent = String(s.tool_steps ?? 0);
  sumResponsesEl.textContent = String(s.responses ?? 0);
  sumStatusEl.textContent = String(s.trace_status ?? "-");
}

function buildElements(payload) {
  const elements = [];
  for (const n of payload.nodes || []) {
    elements.push({ data: { id: n.id, label: n.label, kind: n.kind, metadata: n.metadata || {} } });
  }
  for (const e of payload.edges || []) {
    elements.push({ data: { id: `${e.source}->${e.target}:${e.label || ""}`, source: e.source, target: e.target, label: e.label || "" } });
  }
  return elements;
}

function wireWheelPan() {
  const graphEl = document.getElementById("graph");
  graphEl.onwheel = (evt) => {
    if (!cy) return;
    evt.preventDefault();

    if (evt.ctrlKey || evt.metaKey) {
      const zoomFactor = evt.deltaY > 0 ? 0.93 : 1.07;
      const next = cy.zoom() * zoomFactor;
      cy.zoom({
        level: Math.max(0.03, Math.min(6, next)),
        renderedPosition: { x: evt.offsetX, y: evt.offsetY },
      });
      return;
    }

    cy.panBy({ x: -evt.deltaX, y: -evt.deltaY });
  };
}

function renderGraph(payload) {
  const elements = buildElements(payload);
  if (cy) cy.destroy();

  cy = cytoscape({
    container: document.getElementById("graph"),
    elements,
    style: [
      {
        selector: "node",
        style: {
          "background-color": "#4f46e5",
          label: "data(label)",
          color: "#111827",
          "text-wrap": "wrap",
          "text-max-width": "320px",
          "font-size": "13px",
          "text-valign": "center",
          "text-halign": "center",
          shape: "roundrectangle",
          width: 300,
          height: 90,
          padding: "12px",
        },
      },
      { selector: "node[kind='prompt']", style: { "background-color": "#bfdbfe" } },
      { selector: "node[kind='tool_step']", style: { "background-color": "#fde68a" } },
      { selector: "node[kind='assistant_response']", style: { "background-color": "#bbf7d0" } },
      { selector: "node[kind='tool_call']", style: { "background-color": "#fde68a" } },
      { selector: "node[kind='action']", style: { "background-color": "#fca5a5", width: 320 } },
      { selector: "node[kind='resource']", style: { "background-color": "#d1fae5", width: 380, height: 92 } },
      { selector: "node[kind='placeholder']", style: { "background-color": "#e5e7eb", width: 360 } },
      {
        selector: "edge",
        style: {
          width: 2,
          "line-color": "#94a3b8",
          "target-arrow-color": "#94a3b8",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          label: "data(label)",
          "font-size": "11px",
          color: "#475569",
          "text-background-color": "#fff",
          "text-background-opacity": 1,
          "text-background-padding": "2px",
        },
      },
    ],
    minZoom: 0.03,
    maxZoom: 6,
    layout: {
      name: "breadthfirst",
      directed: true,
      spacingFactor: currentMode === "tool" ? 1.15 : 1.0,
      padding: 20,
      fit: true,
      avoidOverlap: true,
      rankDir: currentMode === "tool" ? "TB" : "LR",
    },
  });

  wireWheelPan();

  cy.on("tap", "node", async (evt) => {
    const data = evt.target.data();
    detailsEl.innerHTML = `<strong>${data.label}</strong><pre>${JSON.stringify(data.metadata || {}, null, 2)}</pre>`;

    const metadata = data.metadata || {};
    if (selectedTraceId && metadata.tool_call_id) {
      try {
        const summary = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/tool-summary/${encodeURIComponent(metadata.tool_call_id)}`);
        renderFiles(summary.files || [], `Tool scope: ${summary.tool_call_id} • files=${summary.totals?.unique_files ?? 0}`);
      } catch (_) {}
    }
  });

  cy.on("dbltap", "node", async (evt) => {
    const data = evt.target.data();
    if ((data.kind === "tool_step" || data.kind === "tool_call") && data.metadata && data.metadata.tool_call_id) {
      currentMode = "tool";
      currentToolCallId = data.metadata.tool_call_id;
      backBtn.style.display = "inline-block";
      await loadToolGraph(data.metadata.tool_call_id);
      try {
        const summary = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/tool-summary/${encodeURIComponent(data.metadata.tool_call_id)}`);
        renderFiles(summary.files || [], `Tool scope: ${summary.tool_call_id} • files=${summary.totals?.unique_files ?? 0}`);
      } catch (_) {}
    }
  });
}

async function loadTraceSummary() {
  if (!selectedTraceId) return;
  try {
    const summary = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/summary`);
    const meta = `Trace ${summary.trace_id} • ${summary.status} • files=${summary.totals?.unique_files ?? 0}`;
    renderFiles(summary.files || [], meta);
  } catch {
    renderFiles([], "No summary available");
  }
}

async function loadHighLevelGraph() {
  if (!selectedTraceId) return;
  const payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/high-level-graph`);
  traceTitleEl.textContent = selectedTraceId;
  viewModeEl.textContent = "High-level";
  updateSummaryCards(payload.summary || {});
  renderGraph(payload);
}

async function loadToolGraph(toolCallId) {
  if (!selectedTraceId) return;
  const payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/tool-graph/${encodeURIComponent(toolCallId)}`);
  traceTitleEl.textContent = selectedTraceId;
  viewModeEl.textContent = `Tool drilldown: ${toolCallId}`;
  renderGraph(payload);
}

async function refreshTraces(keepView = true, force = false) {
  const payload = await api("/api/traces");
  const version = payload.version ?? 0;

  if (keepView && !force && version === latestVersion) {
    return;
  }

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

async function init() {
  await refreshTraces(false);

  setInterval(async () => {
    try {
      await refreshTraces(true);
    } catch (_) {}
  }, 2000);

  try {
    const protocol = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${protocol}://${location.host}/ws`);
    ws.onmessage = async (evt) => {
      const msg = JSON.parse(evt.data);
      if (msg.type === "version") {
        if (typeof msg.version === "number" && msg.version === latestVersion) return;
        await refreshTraces(true, true);
      }
    };
    ws.onerror = () => ws.close();
  } catch (_) {}
}

init();
