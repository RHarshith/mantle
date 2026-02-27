let selectedTraceId = null;
let currentMode = "high";
let currentToolCallId = null;
let cy = null;
let cachedTraces = [];

const traceListEl = document.getElementById("traceList");
const traceTitleEl = document.getElementById("traceTitle");
const viewModeEl = document.getElementById("viewMode");
const detailsEl = document.getElementById("details");
const backBtn = document.getElementById("backBtn");

backBtn.addEventListener("click", async () => {
  currentMode = "high";
  currentToolCallId = null;
  backBtn.style.display = "none";
  await loadHighLevelGraph();
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
    };
    traceListEl.appendChild(div);
  }
}

function renderGraph(payload) {
  const elements = [];

  for (const n of payload.nodes || []) {
    elements.push({
      data: {
        id: n.id,
        label: n.label,
        kind: n.kind,
        metadata: n.metadata || {},
      },
    });
  }

  for (const e of payload.edges || []) {
    elements.push({
      data: {
        id: `${e.source}->${e.target}:${e.label || ""}`,
        source: e.source,
        target: e.target,
        label: e.label || "",
      },
    });
  }

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
          "text-max-width": "170px",
          "font-size": "11px",
          "text-valign": "center",
          "text-halign": "center",
          shape: "roundrectangle",
          width: 190,
          height: 58,
          padding: "8px",
        },
      },
      { selector: "node[kind='prompt']", style: { "background-color": "#bfdbfe" } },
      { selector: "node[kind='tool_call']", style: { "background-color": "#fde68a" } },
      { selector: "node[kind='tool_response']", style: { "background-color": "#c7d2fe" } },
      { selector: "node[kind='assistant_response']", style: { "background-color": "#bbf7d0" } },
      { selector: "node[kind='action']", style: { "background-color": "#fca5a5" } },
      { selector: "node[kind='resource']", style: { "background-color": "#d1fae5", width: 230 } },
      {
        selector: "edge",
        style: {
          width: 2,
          "line-color": "#94a3b8",
          "target-arrow-color": "#94a3b8",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          label: "data(label)",
          "font-size": "10px",
          color: "#475569",
          "text-background-color": "#fff",
          "text-background-opacity": 1,
          "text-background-padding": "2px",
        },
      },
    ],
    layout: { name: "breadthfirst", directed: true, spacingFactor: 1.25, padding: 24 },
  });

  cy.on("tap", "node", (evt) => {
    const data = evt.target.data();
    detailsEl.innerHTML = `<strong>${data.label}</strong><pre>${JSON.stringify(data.metadata || {}, null, 2)}</pre>`;
  });

  cy.on("dbltap", "node", async (evt) => {
    const data = evt.target.data();
    if (data.kind === "tool_call" && data.metadata && data.metadata.tool_call_id) {
      currentMode = "tool";
      currentToolCallId = data.metadata.tool_call_id;
      backBtn.style.display = "inline-block";
      await loadToolGraph(data.metadata.tool_call_id);
    }
  });
}

async function loadHighLevelGraph() {
  if (!selectedTraceId) return;
  const payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/high-level-graph`);
  traceTitleEl.textContent = selectedTraceId;
  viewModeEl.textContent = "High-level";
  renderGraph(payload);
}

async function loadToolGraph(toolCallId) {
  if (!selectedTraceId) return;
  const payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/tool-graph/${encodeURIComponent(toolCallId)}`);
  traceTitleEl.textContent = selectedTraceId;
  viewModeEl.textContent = `Tool drilldown: ${toolCallId}`;
  renderGraph(payload);
}

async function refreshTraces(keepView = true) {
  const payload = await api("/api/traces");
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
}

async function init() {
  await refreshTraces(false);

  // Baseline realtime behavior via polling (works even if websocket backend is unavailable).
  setInterval(async () => {
    try {
      await refreshTraces(true);
    } catch (_) {}
  }, 1500);

  // Optional websocket fast-path; silently degrade to polling-only if unavailable.
  try {
    const protocol = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${protocol}://${location.host}/ws`);

    ws.onmessage = async (evt) => {
      const msg = JSON.parse(evt.data);
      if (msg.type === "version") {
        await refreshTraces(true);
      }
    };

    ws.onerror = () => {
      ws.close();
    };
  } catch (_) {}
}

init();
