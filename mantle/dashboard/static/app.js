/* Agent Trace Observatory - Turn-first dashboard */

let selectedTraceId = null;
let cachedTraces = [];
let latestVersion = -1;
let activeTab = "trace";
let replayOverview = null;
let currentReplayTurnId = null;
let currentReplayPaneTab = "context";
let currentReplayToolSourceIndex = [];
let replaySourceByToolCallId = new Map();
let replaySourceByResultText = new Map();
let replaySourceMapTraceId = null;

let turnsOverview = null;
let currentTurnId = null;
let viewStack = [];

const $ = (id) => document.getElementById(id);
const traceListEl = $("traceList");
const breadcrumbsEl = $("breadcrumbs");
const graphWrapper = $("graphWrapper");
const graphCanvas = $("graphCanvas");
const detailsEl = $("details");
const traceTabBtn = $("traceTabBtn");
const replayTabBtn = $("replayTabBtn");
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

  const sourceLink = card.querySelector(".source-link");
  if (sourceLink && turnId) {
    sourceLink.addEventListener("click", async () => {
      await openSourceTracePopup(turnId, sourcePid, entry.tool_name || "unknown");
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
    row.innerHTML = `<span class="tree-name">${escapeHtml(node.name)}</span><span class="tree-state">${escapeHtml(stateText)}</span>`;
    if (!disableDrilldown && turnId) {
      row.addEventListener("click", async () => {
        await loadRawResource(turnId, "file", node.path, `${node.path} (${stateText})`);
      });
    }
    return row;
  }

  const details = document.createElement("details");
  details.className = "tree-dir";
  details.open = true;
  const summary = document.createElement("summary");
  summary.innerHTML = `<span>${escapeHtml(node.name || "/")}</span><span class="tree-pills">${renderCountPills(node.counts)}</span>`;
  details.appendChild(summary);

  for (const child of node.children || []) {
    details.appendChild(createFileTreeNode(child, turnId, options));
  }
  return details;
}

function renderSystemGroup(entry, turnId, options = {}) {
  const row = document.createElement("div");
  row.className = `timeline-row ${systemTone(entry.category)}`;
  const groupPills = entry.category === "file" ? renderCountPills(entry.counts) : "";
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
      ${hasExpand ? '<button class="inline-btn group-toggle">Expand</button>' : ""}
    </div>
    <div class="row-content" style="display:${hasExpand ? "none" : "block"};"></div>`;

  const content = row.querySelector(".row-content");

  if (entry.category === "file") {
    const tree = createFileTreeNode(entry.tree, turnId, options);
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

    content.appendChild(list);

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

function renderProcessTracePopup(payload, turnId, toolName) {
  const overlay = ensureProcessTracePopup();
  const titleEl = overlay.querySelector("#processTraceTitle");
  const subtitleEl = overlay.querySelector("#processTraceSubtitle");
  const bodyEl = overlay.querySelector("#processTraceBody");
  const s = payload.summary || {};

  titleEl.textContent = `Process Trace · pid ${String(s.pid || payload.pid || "-")}`;
  subtitleEl.textContent = `Tool: ${String(toolName || "unknown")} · lifecycle ${payload.full_lifecycle ? "full" : "turn"}`;

  const wrap = document.createElement("div");
  wrap.className = "process-trace-content";

  const meta = document.createElement("div");
  meta.className = "group-pills";
  const rootPills = [];
  if (Number(s.child_processes_spawned || 0) > 0) rootPills.push(`${formatNumber(s.child_processes_spawned)} process${Number(s.child_processes_spawned) === 1 ? "" : "es"} spawned`);
  if (Number(s.files_read || 0) > 0) rootPills.push(`reads ${formatNumber(s.files_read)}`);
  if (Number(s.files_written || 0) > 0) rootPills.push(`writes ${formatNumber(s.files_written)}`);
  if (Number(s.network_calls || 0) > 0) rootPills.push(`network ${formatNumber(s.network_calls)}`);
  meta.innerHTML = rootPills.map((label) => `<span class="op-pill op-rename">${escapeHtml(label)}</span>`).join("");

  const processTree = document.createElement("div");
  processTree.className = "proc-list";
  const execCommands = Array.isArray(s.exec_commands) ? s.exec_commands : [];

  if (execCommands.length) {
    const cmds = document.createElement("div");
    cmds.className = "timeline-row row-process";
    cmds.innerHTML = `
      <div class="timeline-head">
        <span class="row-title">Exec Commands</span>
        <span class="row-sub">pid ${escapeHtml(String(s.pid || payload.pid || "-"))}</span>
      </div>
      <div class="row-content"><pre class="mono-block">${escapeHtml(execCommands.join("\n"))}</pre></div>`;
    processTree.appendChild(cmds);
  }

  const renderProcessNode = (node, parentEl, depth = 0) => {
    const row = document.createElement("div");
    row.className = "timeline-row row-process";
    row.style.marginLeft = `${Math.max(0, depth) * 16}px`;
    row.innerHTML = `
      <div class="timeline-head">
        <span class="row-title">pid ${escapeHtml(String(node.pid))}</span>
        <span class="row-sub mono-small">${escapeHtml(node.command || "(command unknown)")}</span>
        <span class="group-pills"></span>
        <button class="inline-btn group-toggle">Expand</button>
      </div>
      <div class="row-content" style="display:none;"><div class="mono-text">Loading process activity...</div></div>`;

    const toggle = row.querySelector(".group-toggle");
    const content = row.querySelector(".row-content");
    const pillsHost = row.querySelector(".group-pills");
    let loaded = false;

    toggle.addEventListener("click", async () => {
      const expanded = content.style.display !== "none";
      content.style.display = expanded ? "none" : "block";
      toggle.textContent = expanded ? "Expand" : "Collapse";
      if (expanded || loaded) return;
      loaded = true;

      try {
        const childPayload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/process-subtrace/${encodeURIComponent(turnId)}/${encodeURIComponent(node.pid)}?full_lifecycle=1`);
        const cs = childPayload.summary || {};
        const childPills = [];
        if (Number(cs.child_processes_spawned || 0) > 0) childPills.push(`${formatNumber(cs.child_processes_spawned)} process${Number(cs.child_processes_spawned) === 1 ? "" : "es"} spawned`);
        if (Number(cs.files_read || 0) > 0) childPills.push(`reads ${formatNumber(cs.files_read)}`);
        if (Number(cs.files_written || 0) > 0) childPills.push(`writes ${formatNumber(cs.files_written)}`);
        if (Number(cs.network_calls || 0) > 0) childPills.push(`network ${formatNumber(cs.network_calls)}`);
        pillsHost.innerHTML = childPills.map((label) => `<span class="op-pill op-rename">${escapeHtml(label)}</span>`).join("");

        const children = extractChildren(childPayload.timeline || []);
        content.innerHTML = "";
        renderTimelineSequence(childPayload.timeline || [], content, depth + 1);
        if (!content.children.length) {
          content.innerHTML = '<div class="mono-text">No child activity.</div>';
          return;
        }
      } catch (_err) {
        content.innerHTML = '<div class="mono-text">Failed to load process activity for this PID.</div>';
      }
    });

    parentEl.appendChild(row);
  };

  const renderCommandRow = (command, parentEl, depth = 0) => {
    const row = document.createElement("div");
    row.className = "timeline-row row-process";
    row.style.marginLeft = `${Math.max(0, depth) * 16}px`;
    row.innerHTML = `
      <div class="timeline-head">
        <span class="row-title">command_exec</span>
        <span class="row-sub mono-small">${escapeHtml(command || "(command unknown)")}</span>
      </div>`;
    parentEl.appendChild(row);
  };

  const renderFileRow = (entry, parentEl, depth = 0) => {
    const row = document.createElement("div");
    row.className = "timeline-row row-file";
    row.style.marginLeft = `${Math.max(0, depth) * 16}px`;
    row.innerHTML = `
      <div class="timeline-head">
        <span class="row-title">${escapeHtml(entry.title || "files touched")}</span>
        <span class="group-pills">${renderCountPills(entry.counts)}</span>
      </div>
      <div class="row-content" style="display:block;"></div>`;
    const content = row.querySelector(".row-content");
    content.appendChild(createFileTreeNode(entry.tree, null, { disableResourceDrilldown: true }));
    parentEl.appendChild(row);
  };

  const renderNetworkRow = (entry, parentEl, depth = 0) => {
    const row = document.createElement("div");
    row.className = "timeline-row row-network";
    row.style.marginLeft = `${Math.max(0, depth) * 16}px`;
    const calls = Array.isArray(entry.calls) ? entry.calls : [];
    const parts = [];
    for (const call of calls) {
      const sent = Number(call.bytes_sent || 0);
      const recv = Number(call.bytes_recv || 0);
      parts.push(`${call.dest} (tx ${sent}B rx ${recv}B)`);
    }
    row.innerHTML = `
      <div class="timeline-head">
        <span class="row-title">${escapeHtml(entry.title || "network")}</span>
        <span class="row-sub mono-small">${escapeHtml(parts.join(" | ") || "No network details")}</span>
      </div>`;
    parentEl.appendChild(row);
  };

  const renderTimelineSequence = (timeline, parentEl, depth = 0) => {
    for (const entry of timeline || []) {
      if (!entry) continue;
      const category = String(entry.category || "");

      if (category === "file") {
        renderFileRow(entry, parentEl, depth);
        continue;
      }

      if (category === "process") {
        const commands = Array.isArray(entry.commands) ? entry.commands : [];
        for (const cmd of commands) {
          renderCommandRow(String(cmd || ""), parentEl, depth);
        }

        const children = Array.isArray(entry.process_tree) ? entry.process_tree : [];
        for (const child of children) {
          const pid = Number(child && child.pid);
          if (!pid) continue;
          renderProcessNode({ pid, command: String((child && child.command) || "") }, parentEl, depth);
        }
        continue;
      }

      if (category === "network") {
        renderNetworkRow(entry, parentEl, depth);
      }
    }
  };

  renderTimelineSequence(payload.timeline || [], processTree, 0);

  wrap.appendChild(meta);
  wrap.appendChild(processTree);
  bodyEl.innerHTML = "";
  bodyEl.appendChild(wrap);
  overlay.classList.add("open");
}

async function openSourceTracePopup(turnId, pid, toolName) {
  if (!selectedTraceId || !turnId || !pid) return;
  const overlay = ensureProcessTracePopup();
  const bodyEl = overlay.querySelector("#processTraceBody");
  bodyEl.innerHTML = '<div class="mono-text">Loading process trace...</div>';
  overlay.classList.add("open");

  try {
    const payload = await api(`/api/traces/${encodeURIComponent(selectedTraceId)}/process-subtrace/${encodeURIComponent(turnId)}/${encodeURIComponent(pid)}?full_lifecycle=1`);
    renderProcessTracePopup(payload, turnId, toolName);
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
  const isToolOutput = String(section.style || "") === "tool_output";
  const sneakLines = Number(options.sneakLines || 0);
  const openByDefault = Boolean(options.openByDefault);
  const blocks = values.map((v) => {
    if (!isToolOutput) {
      return replayValueBlock(v, { sneakLines });
    }
    const source = findReplaySourceForValue(v);
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
  const source = pair && typeof pair.source === "object" ? pair.source : { status: "source_not_found" };
  const sourcePid = Number(source.pid || 0);
  const sourceHtml = sourcePid > 0
    ? `<button class="replay-source-link" data-source-pid="${String(sourcePid)}">source: pid${String(sourcePid)}</button>`
    : '<span class="replay-source-missing">source: not found</span>';

  const responseText = typeof pair?.response === "string"
    ? pair.response
    : JSON.stringify(pair?.response ?? null, null, 2);
  const response = truncateLines(responseText, 4);

  return `
    <details class="replay-card replay-tool_pair replay-tool-call-pair" open>
      <summary class="replay-band">
        <span class="replay-band-title">${escapeHtml(pair?.tool_name || "tool")} (${escapeHtml(pair?.tool_call_id || "")})</span>
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
    </div>
    <div class="replay-sections">${contentHtml}</div>`;

  wireReplayExpanders(right);

  right.querySelectorAll(".replay-source-link").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const pid = Number(btn.getAttribute("data-source-pid") || "0");
      if (!pid || !payload.turn_id) return;
      await openSourceTracePopup(payload.turn_id, pid, "tool output");
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
              await openSourceTracePopup(payload.turn_id, pid, "tool output");
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
              await openSourceTracePopup(payload.turn_id, pid, "subprocess");
            });
          });
        });
      }
    });
  });
}

function renderReplayShell(overview) {
  const turns = (overview || {}).turns || [];
  const turnButtons = turns.map((turn) => {
    const active = turn.turn_id === currentReplayTurnId;
    return `
      <button class="replay-turn-item ${active ? "active" : ""}" data-turn-id="${escapeHtml(turn.turn_id)}">
        <div class="replay-turn-top">
          <span class="replay-turn-name">${escapeHtml(turn.label || turn.turn_id)}</span>
          <span class="replay-turn-tools">${formatNumber(turn.tool_call_count)} tools</span>
        </div>
        <div class="replay-turn-meta">ctx ${formatNumber(turn.context_section_count)} · act ${formatNumber(turn.action_section_count)}</div>
      </button>`;
  }).join("");

  graphCanvas.innerHTML = `
    <div class="replay-layout">
      <aside class="replay-left">
        <div class="replay-left-head">Turns</div>
        <div class="replay-turn-list">${turnButtons || '<div class="replay-empty">No turns available</div>'}</div>
      </aside>
      <section class="replay-right" id="replayRightPane">
        <div class="replay-empty">Select a turn to inspect context and action details.</div>
      </section>
    </div>`;

  graphCanvas.querySelectorAll(".replay-turn-item").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const turnId = btn.getAttribute("data-turn-id");
      if (!turnId) return;
      currentReplayTurnId = turnId;
      await loadReplayTurnDetail(turnId);
    });
  });
}

async function loadReplayTurnDetail(turnId) {
  if (!selectedTraceId) return;
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

  const turns = payload.turns || [];
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
  traceTabBtn.classList.toggle("active", tabName === "trace");
  replayTabBtn.classList.toggle("active", tabName === "replay");
  settingsTabBtn.classList.toggle("active", tabName === "settings");
  graphWrapper.classList.toggle("replay-mode", tabName === "replay");
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
  } else if (activeTab === "replay") {
    await loadReplayOverview();
  } else if (activeTab === "settings") {
    await loadSettingsView();
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
  } else if (activeTab === "replay") {
    await loadReplayOverview();
  } else if (activeTab === "settings") {
    await loadSettingsView();
  }
}

function installStyles() {
  const style = document.createElement("style");
  style.textContent = `
    .turn-tabs { display:flex; flex-direction:column; gap:10px; padding: 6px 0 14px; }
    .turn-tab { width:100%; border:1px solid var(--border); border-radius:8px; background:var(--surface); text-align:left; padding:10px; cursor:pointer; }
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

    .mono-block, .mono-text, .raw-json pre { font-family:Consolas, Monaco, monospace; font-size:11px; white-space:pre-wrap; word-break:break-word; background:var(--slate-50); border:1px solid var(--border); border-radius:6px; padding:8px; }
    .mini-label { font-size:10px; text-transform:uppercase; font-weight:700; color:var(--text-muted); margin-bottom:4px; }

    .tree-dir { margin-left: 6px; }
    .tree-dir > summary { cursor:pointer; font-size:12px; font-weight:600; display:flex; align-items:center; justify-content:space-between; gap:8px; }
    .tree-pills { display:flex; gap:6px; }
    .tree-file { margin-left: 18px; display:flex; justify-content:space-between; font-size:12px; border:1px solid var(--border-light); border-radius:6px; padding:4px 8px; cursor:pointer; }
    .tree-file:hover { background: var(--slate-50); }
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
    .replay-turn-list { overflow:auto; display:flex; flex-direction:column; flex:1; min-height:0; }
    .replay-turn-item { border:0; border-bottom:1px solid var(--border-light); background:var(--surface); text-align:left; padding:10px; cursor:pointer; }
    .replay-turn-item:hover { background:var(--slate-50); }
    .replay-turn-item.active { background:var(--blue-50); box-shadow: inset 3px 0 0 var(--blue-500); }
    .replay-turn-top { display:flex; justify-content:space-between; gap:6px; }
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

    .replay-metrics-overlay { position:fixed; inset:0; background:rgba(15,23,42,0.38); display:none; align-items:center; justify-content:center; padding:18px; z-index:1100; }
    .replay-metrics-overlay.open { display:flex; }
    .replay-metrics-modal { width:min(980px, 96vw); max-height:88vh; background:var(--surface); border:1px solid var(--border); border-radius:12px; box-shadow:0 20px 42px rgba(15,23,42,0.2); display:flex; flex-direction:column; overflow:hidden; }

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

  replayTabBtn.addEventListener("click", async () => {
    if (activeTab === "replay") return;
    setActiveTab("replay");
    viewStack = [{ kind: "replay", label: "Replay Trace" }];
    renderBreadcrumbs();
    await loadReplayOverview();
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
