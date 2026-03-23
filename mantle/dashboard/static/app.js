/* Agent Trace Observatory - Turn-first dashboard */

let selectedTraceId = null;
let cachedTraces = [];
let latestVersion = -1;
let activeTab = "trace";

let turnsOverview = null;
let currentTurnId = null;
let viewStack = [];

const $ = (id) => document.getElementById(id);
const traceListEl = $("traceList");
const breadcrumbsEl = $("breadcrumbs");
const graphCanvas = $("graphCanvas");
const detailsEl = $("details");
const traceTabBtn = $("traceTabBtn");
const taintTabBtn = $("taintTabBtn");
const blastTabBtn = $("blastTabBtn");
const settingsTabBtn = $("settingsTabBtn");
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

function toneClass(tag) {
  if (tag === "read and plan") return "pill-amber";
  if (tag === "edit") return "pill-red";
  if (tag === "execute") return "pill-gray";
  if (tag === "network") return "pill-blue";
  if (tag === "response") return "pill-teal";
  return "pill-gray";
}

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

function renderTraceList(traces) {
  traceListEl.innerHTML = "";
  for (const t of traces) {
    const row = document.createElement("div");
    row.className = `trace-item${t.trace_id === selectedTraceId ? " active" : ""}`;
    const statusClass = t.status === "completed" ? "completed" : "active";
    row.innerHTML = `
      <div class="trace-row">
        <div class="trace-main">
          <div class="trace-name">${escapeHtml(t.trace_id)}</div>
          <div class="trace-meta"><span class="trace-status ${statusClass}">${escapeHtml(t.status)}</span> agent: ${formatNumber(t.agent_event_count)} sys: ${formatNumber(t.sys_event_count)}</div>
        </div>
      </div>`;
    row.addEventListener("click", () => selectTrace(t.trace_id));
    traceListEl.appendChild(row);
  }
}

function renderBreadcrumbs() {
  breadcrumbsEl.innerHTML = "";
  if (!selectedTraceId) {
    breadcrumbsEl.innerHTML = '<span class="crumb current">No trace selected</span>';
    return;
  }

  const root = document.createElement("span");
  root.className = "crumb";
  root.textContent = selectedTraceId;
  root.addEventListener("click", async () => {
    viewStack = [];
    await loadTurnsOverview();
  });
  breadcrumbsEl.appendChild(root);

  const full = [...viewStack];
  if (full.length === 0) {
    const cur = document.createElement("span");
    cur.className = "crumb current";
    cur.textContent = "Turns";
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
    const tags = (turn.tags || []).map((tag) => `<span class="tag-pill ${toneClass(tag)}">${escapeHtml(tag)}</span>`).join("");
    btn.innerHTML = `
      <div class="turn-tab-top">
        <span class="turn-id">${escapeHtml(turn.label)}</span>
        <span class="turn-tools">${formatNumber(turn.tool_call_count)} tools</span>
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

  card.innerHTML = `
    <div class="timeline-head">
      <span class="row-title">Tool: ${escapeHtml(entry.tool_name || "unknown")}</span>
      <span class="row-sub">${escapeHtml(entry.tool_call_id || "")}</span>
    </div>
    <div class="row-content">
      <div><div class="mini-label">Input arguments</div>${jsonBlock(entry.arguments)}</div>
      <div>
        <div class="mini-label">Return value</div>
        <pre class="mono-block result-block">${escapeHtml(t.short)}</pre>
        ${t.truncated ? '<button class="inline-btn">Expand</button>' : ""}
      </div>
    </div>`;

  const btn = card.querySelector(".inline-btn");
  if (btn) {
    const pre = card.querySelector(".result-block");
    btn.addEventListener("click", () => {
      const expanded = btn.textContent === "Collapse";
      pre.textContent = expanded ? t.short : t.long;
      btn.textContent = expanded ? "Expand" : "Collapse";
    });
  }

  return card;
}

function createFileTreeNode(node, turnId) {
  if (!node) return document.createElement("div");

  if (node.kind === "file") {
    const row = document.createElement("div");
    const state = String(node.state || "read");
    const stateText = state === "read_write" ? "read/write" : state;
    row.className = `tree-file tree-${state}`;
    row.innerHTML = `<span class="tree-name">${escapeHtml(node.name)}</span><span class="tree-state">${escapeHtml(stateText)}</span>`;
    row.addEventListener("click", async () => {
      await loadRawResource(turnId, "file", node.path, `${node.path} (${stateText})`);
    });
    return row;
  }

  const details = document.createElement("details");
  details.className = "tree-dir";
  details.open = true;
  const summary = document.createElement("summary");
  summary.textContent = node.name || "/";
  details.appendChild(summary);

  for (const child of node.children || []) {
    details.appendChild(createFileTreeNode(child, turnId));
  }
  return details;
}

function renderSystemGroup(entry, turnId) {
  const row = document.createElement("div");
  row.className = `timeline-row ${systemTone(entry.category)}`;

  const hasExpand = entry.category === "process"
    ? Array.isArray(entry.process_tree) && entry.process_tree.length > 0
    : !entry.standalone;
  row.innerHTML = `
    <div class="timeline-head">
      <span class="row-title">${escapeHtml(entry.title)}</span>
      <span class="row-sub">${escapeHtml(entry.category)}</span>
      ${hasExpand ? '<button class="inline-btn group-toggle">Expand</button>' : ""}
    </div>
    <div class="row-content" style="display:${hasExpand ? "none" : "block"};"></div>`;

  const content = row.querySelector(".row-content");

  if (entry.category === "file") {
    const tree = createFileTreeNode(entry.tree, turnId);
    content.appendChild(tree);
  } else if (entry.category === "process") {
    const hints = document.createElement("div");
    hints.className = "mono-text";
    const cmds = (entry.commands || []).slice(0, 6).join("\n");
    hints.textContent = cmds || "No command strings captured";
    content.appendChild(hints);

    const list = document.createElement("div");
    list.className = "proc-list";
    const childProcesses = entry.process_tree || [];
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
          const payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/process-subtrace/${encodeURIComponent(turnId)}/${encodeURIComponent(p.pid)}`);
          const s = payload.summary || {};
          nested.innerHTML = "";

          const summary = document.createElement("div");
          summary.className = "mono-text";
          summary.textContent = `pid=${String(s.pid || p.pid)} ppid=${String(s.parent_pid || "-")} files_read=${formatNumber(s.files_read)} files_written=${formatNumber(s.files_written)} child_spawns=${formatNumber(s.child_processes_spawned)} network_calls=${formatNumber(s.network_calls)} exit=${s.exit_code == null ? "-" : String(s.exit_code)}`;
          nested.appendChild(summary);

          for (const subEntry of payload.timeline || []) {
            nested.appendChild(renderSystemGroup(subEntry, turnId));
          }
        } catch (_err) {
          nested.innerHTML = '<div class="mono-text">Failed to load process activity for this PID.</div>';
        }
      }
    };

    content.appendChild(list);

    if (!hasExpand) {
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
  } else if (entry.category === "network") {
    const calls = document.createElement("div");
    calls.className = "net-list";
    for (const call of entry.calls || []) {
      const btn = document.createElement("button");
      btn.className = "net-node";
      btn.innerHTML = `${escapeHtml(call.dest)} · tx ${formatNumber(call.bytes_sent)}B · rx ${formatNumber(call.bytes_recv)}B${call.full_capture ? ' · <span class="capture-flag">full capture available</span>' : ""}`;
      btn.addEventListener("click", async () => {
        await loadRawResource(turnId, "network", call.dest, call.dest);
      });
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
  collapsible.innerHTML = `
    <summary>Prompt and model response</summary>
    <div class="pr-grid">
      <div>
        <div class="mini-label">Prompt</div>
        <pre class="mono-block">${escapeHtml(payload.prompt_text || "No prompt text captured")}</pre>
      </div>
      <div>
        <div class="mini-label">Response</div>
        <pre class="mono-block">${escapeHtml(payload.response_text || "No response text captured")}</pre>
      </div>
    </div>`;

  const timeline = document.createElement("div");
  timeline.className = "timeline-wrap";
  const rawTimeline = payload.timeline || [];

  // Collapse kernel activity that occurred before the first tool call.
  let firstToolIdx = -1;
  for (let i = 0; i < rawTimeline.length; i += 1) {
    if (rawTimeline[i].entry_type === "tool_call") {
      firstToolIdx = i;
      break;
    }
  }
  if (firstToolIdx > 0) {
    const pre = rawTimeline.slice(0, firstToolIdx).filter((e) => e.entry_type === "system_group");
    if (pre.length > 0) {
      const counts = payload.pre_tool_counts || {};
      const preRow = document.createElement("div");
      preRow.className = "timeline-row row-process";
      preRow.innerHTML = `
        <div class="timeline-head">
          <span class="row-title">Kernel setup activity before first tool</span>
          <span class="row-sub">pre-tool block</span>
          <button class="inline-btn group-toggle">Expand</button>
        </div>
        <div class="row-content" style="display:none;">
          <div class="mono-text">reads=${formatNumber(counts.file_read || 0)} · writes=${formatNumber(counts.file_write || 0)} · spawns=${formatNumber(counts.process_spawn || 0)} · network_ops=${formatNumber(counts.network || 0)}</div>
          <div class="nested-groups"></div>
        </div>`;
      const nested = preRow.querySelector(".nested-groups");
      for (const entry of pre) {
        nested.appendChild(renderSystemGroup(entry, payload.turn_id));
      }
      makeToggle(preRow.querySelector(".group-toggle"), preRow.querySelector(".row-content"));
      timeline.appendChild(preRow);
    }
  }

  const startIdx = firstToolIdx > 0 ? firstToolIdx : 0;
  for (let i = startIdx; i < rawTimeline.length; i += 1) {
    const entry = rawTimeline[i];
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
  traceTabBtn.classList.toggle("active", tabName === "trace");
  taintTabBtn.classList.toggle("active", tabName === "taint");
  blastTabBtn.classList.toggle("active", tabName === "blast");
  settingsTabBtn.classList.toggle("active", tabName === "settings");
}

async function loadTaintAnalysis() {
  if (!selectedTraceId) return;
  const report = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/taint-analysis`);
  const counts = report.finding_counts || {};
  const strip = $("summaryStrip");
  strip.style.gridTemplateColumns = "repeat(4, 1fr)";
  strip.innerHTML = `
    <div class="summary-card"><div class="k">Critical</div><div class="v">${formatNumber(counts.critical)}</div></div>
    <div class="summary-card"><div class="k">Warning</div><div class="v">${formatNumber(counts.warning)}</div></div>
    <div class="summary-card"><div class="k">Info</div><div class="v">${formatNumber(counts.info)}</div></div>
    <div class="summary-card"><div class="k">Policy</div><div class="v" style="font-size:14px">${escapeHtml(report.trust_policy || "-")}</div></div>`;

  graphCanvas.innerHTML = `<div class="raw-json">${jsonBlock(report)}</div>`;
}

async function loadBlastAnalysis() {
  if (!selectedTraceId) return;
  const traces = cachedTraces.map((t) => t.trace_id).filter((id) => id !== selectedTraceId);
  if (traces.length === 0) {
    graphCanvas.innerHTML = '<div class="empty-state"><h3>No baselines</h3><p>Need at least one additional trace.</p></div>';
    return;
  }
  const params = new URLSearchParams({
    candidate_id: selectedTraceId,
    baseline_ids: traces.join(","),
  });
  const report = await api(`/api/blast-radius/compare?${params.toString()}`);
  const s = report.summary || {};
  const strip = $("summaryStrip");
  strip.style.gridTemplateColumns = "repeat(4, 1fr)";
  strip.innerHTML = `
    <div class="summary-card"><div class="k">Checkpoints</div><div class="v">${formatNumber(s.checkpoints)}</div></div>
    <div class="summary-card"><div class="k">Deviations</div><div class="v">${formatNumber(s.deviations)}</div></div>
    <div class="summary-card"><div class="k">Score</div><div class="v">${formatNumber(s.deviation_score)}</div></div>
    <div class="summary-card"><div class="k">Consistency</div><div class="v" style="font-size:14px">${s.eventual_consistency ? "yes" : "no"}</div></div>`;

  graphCanvas.innerHTML = `<div class="raw-json">${jsonBlock(report)}</div>`;
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
  viewStack = [];
  renderTraceList(cachedTraces);
  renderBreadcrumbs();

  if (activeTab === "trace") {
    await loadTurnsOverview();
  } else if (activeTab === "taint") {
    await loadTaintAnalysis();
  } else if (activeTab === "settings") {
    await loadSettingsView();
  } else {
    await loadBlastAnalysis();
  }
}

async function refreshTraces(force = false) {
  const payload = await api("/api/traces");
  const version = Number(payload.version || 0);
  if (!force && version === latestVersion) {
    return;
  }

  latestVersion = version;
  cachedTraces = payload.traces || [];

  if (!selectedTraceId && cachedTraces.length > 0) {
    selectedTraceId = cachedTraces[0].trace_id;
  }
  if (selectedTraceId && !cachedTraces.some((t) => t.trace_id === selectedTraceId)) {
    selectedTraceId = cachedTraces.length > 0 ? cachedTraces[0].trace_id : null;
  }

  renderTraceList(cachedTraces);

  if (!selectedTraceId) {
    graphCanvas.innerHTML = '<div class="empty-state"><h3>No trace selected</h3><p>Select a trace to view timeline.</p></div>';
    return;
  }

  if (activeTab === "trace") {
    await loadTurnsOverview();
  } else if (activeTab === "taint") {
    await loadTaintAnalysis();
  } else if (activeTab === "settings") {
    await loadSettingsView();
  } else {
    await loadBlastAnalysis();
  }
}

function installStyles() {
  const style = document.createElement("style");
  style.textContent = `
    .turn-tabs { display:flex; gap:10px; overflow:auto; padding: 6px 0 14px; }
    .turn-tab { min-width: 220px; border:1px solid var(--border); border-radius:8px; background:var(--surface); text-align:left; padding:10px; cursor:pointer; }
    .turn-tab.active { box-shadow: inset 0 0 0 2px var(--blue-500); background: var(--blue-50); }
    .turn-tab-top { display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; }
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

    .turn-exec-summary { display:grid; grid-template-columns: repeat(5, 1fr); gap:10px; margin: 8px 0 12px; }
    .mini-card { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:10px; }
    .mini-card .k { font-size:10px; color:var(--text-muted); text-transform:uppercase; font-weight:700; }
    .mini-card .v { font-size:18px; font-weight:700; margin-top:2px; word-break:break-word; }
    .mini-card .v.mono-small { font-family:Consolas, Monaco, monospace; font-size:12px; }

    .prompt-response { background:var(--surface); border:1px solid var(--border); border-radius:8px; margin-bottom:12px; }
    .prompt-response > summary { cursor:pointer; padding:10px 12px; font-weight:700; }
    .pr-grid { display:grid; grid-template-columns: 1fr 1fr; gap:10px; padding:0 12px 12px; }

    .timeline-wrap { display:flex; flex-direction:column; gap:10px; }
    .timeline-row { border:1px solid var(--border); border-radius:8px; background:var(--surface); padding:10px 12px; }
    .timeline-head { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    .row-title { font-weight:700; font-size:13px; }
    .row-sub { font-size:11px; color:var(--text-muted); text-transform:uppercase; }
    .row-content { margin-top:8px; }

    .tool-entry { border-left:4px solid #7e22ce; }
    .row-file { border-left:4px solid #d97706; }
    .row-network { border-left:4px solid #2563eb; }
    .row-process { border-left:4px solid #6b7280; }

    .inline-btn { border:1px solid var(--border); background:var(--slate-50); border-radius:6px; padding:3px 7px; font-size:11px; cursor:pointer; margin-left:auto; }
    .inline-btn:hover { background: var(--slate-100); }

    .mono-block, .mono-text, .raw-json pre { font-family:Consolas, Monaco, monospace; font-size:11px; white-space:pre-wrap; word-break:break-word; background:var(--slate-50); border:1px solid var(--border); border-radius:6px; padding:8px; }
    .mini-label { font-size:10px; text-transform:uppercase; font-weight:700; color:var(--text-muted); margin-bottom:4px; }

    .tree-dir { margin-left: 6px; }
    .tree-dir > summary { cursor:pointer; font-size:12px; font-weight:600; }
    .tree-file { margin-left: 18px; display:flex; justify-content:space-between; font-size:12px; border:1px solid var(--border-light); border-radius:6px; padding:4px 8px; cursor:pointer; }
    .tree-file:hover { background: var(--slate-50); }
    .tree-read { border-left:3px solid #d97706; }
    .tree-write { border-left:3px solid #dc2626; }
    .tree-read_write { border-left:3px solid #b45309; }
    .tree-state { font-size:10px; text-transform:uppercase; color:var(--text-muted); }

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

    @media (max-width: 1200px) {
      .turn-exec-summary { grid-template-columns: repeat(3, 1fr); }
      .pr-grid { grid-template-columns: 1fr; }
    }
    @media (max-width: 820px) {
      .turn-exec-summary { grid-template-columns: repeat(2, 1fr); }
    }
  `;
  document.head.appendChild(style);
}

async function init() {
  installStyles();

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

  traceTabBtn.addEventListener("click", async () => {
    if (activeTab === "trace") return;
    setActiveTab("trace");
    viewStack = [];
    renderBreadcrumbs();
    await loadTurnsOverview();
  });

  taintTabBtn.addEventListener("click", async () => {
    if (activeTab === "taint") return;
    setActiveTab("taint");
    viewStack = [{ kind: "taint", label: "Taint Analysis" }];
    renderBreadcrumbs();
    await loadTaintAnalysis();
  });

  blastTabBtn.addEventListener("click", async () => {
    if (activeTab === "blast") return;
    setActiveTab("blast");
    viewStack = [{ kind: "blast", label: "Blast Radius" }];
    renderBreadcrumbs();
    await loadBlastAnalysis();
  });

  settingsTabBtn.addEventListener("click", async () => {
    if (activeTab === "settings") return;
    setActiveTab("settings");
    viewStack = [{ kind: "settings", label: "Settings" }];
    renderBreadcrumbs();
    await loadSettingsView();
  });

  await refreshTraces(true);

  setInterval(async () => {
    try {
      await refreshTraces(false);
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
        await refreshTraces(true);
      }
    };
    ws.onerror = () => ws.close();
  } catch (_) {
    // websocket optional
  }
}

init();
