const state = {
  tier: "l1",
  chatHistory: [],
  investigationId: sessionStorage.getItem("tsage_investigation_id") || null,
  investigation: null,
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

function readToken() {
  return sessionStorage.getItem("tsage_read_token") || "";
}

function writeToken() {
  return sessionStorage.getItem("tsage_write_token") || "";
}

function showToast(message, error = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.className = `toast visible${error ? " error" : ""}`;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => {
    toast.className = "toast";
  }, 4200);
}

async function api(path, options = {}, tokenType = "read") {
  const token = tokenType === "write" ? writeToken() : readToken();
  const headers = { ...(options.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (options.body) headers["Content-Type"] = "application/json";

  const response = await fetch(path, { ...options, headers });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = body?.error?.message || body?.detail || `Request failed (${response.status})`;
    throw new Error(message);
  }
  return body.data;
}

function setConnected(connected) {
  const badge = $("#connection-badge");
  badge.textContent = connected ? "Connected" : "Disconnected";
  badge.className = `badge ${connected ? "success" : "neutral"}`;
}

async function refreshServiceData() {
  const dot = $("#wazuh-dot");
  try {
    const [health, summary] = await Promise.all([
      api("/api/v1/health/wazuh"),
      api("/api/v1/alerts/summary?hours=24"),
    ]);
    const healthy = health.status === "healthy";
    dot.className = `status-dot ${healthy ? "healthy" : "unhealthy"}`;
    $("#wazuh-label").textContent = healthy ? "Wazuh healthy" : "Wazuh degraded";
    $("#wazuh-detail").textContent = healthy ? "Indexer and manager online" : "Check service diagnostics";
    renderAlertChart(summary);
    setConnected(true);
  } catch (error) {
    dot.className = "status-dot unhealthy";
    $("#wazuh-label").textContent = "Wazuh unavailable";
    $("#wazuh-detail").textContent = error.message;
    setConnected(Boolean(readToken()));
  }
}

function renderAlertChart(summary = {}) {
  const total = summary.total_alerts || 0;
  $("#alert-total").textContent = total.toLocaleString();
  const levels = summary.by_level || {};
  const buckets = [
    ["critical", Object.entries(levels).filter(([level]) => Number(level) >= 15).reduce((sum, [, count]) => sum + count, 0)],
    ["high", Object.entries(levels).filter(([level]) => Number(level) >= 12 && Number(level) < 15).reduce((sum, [, count]) => sum + count, 0)],
    ["medium", Object.entries(levels).filter(([level]) => Number(level) >= 7 && Number(level) < 12).reduce((sum, [, count]) => sum + count, 0)],
    ["low", Object.entries(levels).filter(([level]) => Number(level) < 7).reduce((sum, [, count]) => sum + count, 0)],
  ];
  const max = Math.max(1, ...buckets.map(([, count]) => count));
  const chart = $("#severity-chart");
  chart.replaceChildren();
  buckets.forEach(([label, count]) => {
    const row = document.createElement("div");
    row.className = `severity-row ${label}`;
    const name = document.createElement("span");
    name.textContent = label;
    const track = document.createElement("div");
    track.className = "severity-track";
    const bar = document.createElement("div");
    bar.className = "severity-bar";
    bar.style.width = `${Math.max(2, (count / max) * 100)}%`;
    const value = document.createElement("strong");
    value.textContent = count;
    track.append(bar);
    row.append(name, track, value);
    chart.append(row);
  });
}

function switchView(name) {
  $$(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.view === name));
  $$(".view").forEach((view) => view.classList.toggle("active", view.id === `${name}-view`));
  $("#page-title").textContent = name === "chat" ? "Agent chat" : "Investigations";
  $("#page-subtitle").textContent = name === "chat"
    ? "Read-only investigation workspace"
    : "LangGraph workflow and approval state";
}

function appendMessage(kind, label, content) {
  const log = $("#chat-log");
  log.querySelector(".empty-state")?.remove();
  const message = document.createElement("article");
  message.className = `message ${kind}`;
  const meta = document.createElement("div");
  meta.className = "message-meta";
  meta.textContent = label;
  const body = document.createElement("div");
  body.className = "message-body";
  body.textContent = content;
  message.append(meta, body);
  log.append(message);
  log.scrollTop = log.scrollHeight;
}

function renderTools(tools) {
  const container = $("#tool-activity");
  container.replaceChildren();
  if (!tools.length) {
    const empty = document.createElement("span");
    empty.className = "muted";
    empty.textContent = "No tools called";
    container.append(empty);
    return;
  }
  tools.forEach((tool) => {
    const chip = document.createElement("span");
    chip.className = "tool-chip";
    chip.textContent = tool;
    container.append(chip);
  });
}

async function submitChat(event) {
  event.preventDefault();
  const input = $("#chat-input");
  const message = input.value.trim();
  if (!message) return;
  appendMessage("user", "You", message);
  input.value = "";
  $("#chat-state").textContent = `${state.tier.toUpperCase()} working...`;

  try {
    const data = await api("/api/v1/soc/chat", {
      method: "POST",
      body: JSON.stringify({
        tier: state.tier,
        message,
        history: state.chatHistory.slice(-20),
      }),
    });
    appendMessage("agent", `SOC ${state.tier.toUpperCase()}`, data.assistant_message);
    state.chatHistory.push(
      { role: "user", content: message },
      { role: "assistant", content: data.assistant_message },
    );
    renderTools(data.tools_used || []);
    $("#chat-state").textContent = "Ready";
  } catch (error) {
    appendMessage("error", "Agent error", error.message);
    $("#chat-state").textContent = "Unavailable";
  }
}

async function createInvestigation(event) {
  event.preventDefault();
  const alertId = $("#alert-id").value.trim();
  const agentId = $("#agent-id").value.trim();
  try {
    const data = await api("/api/v1/investigations", {
      method: "POST",
      body: JSON.stringify({
        alert_id: alertId,
        agent_id: agentId || null,
      }),
    });
    state.investigationId = data.investigation_id;
    sessionStorage.setItem("tsage_investigation_id", state.investigationId);
    renderInvestigation(data);
    showToast("Investigation workflow completed its current run.");
  } catch (error) {
    showToast(error.message, true);
  }
}

async function loadInvestigation() {
  if (!state.investigationId) return;
  try {
    const data = await api(`/api/v1/investigations/${encodeURIComponent(state.investigationId)}`);
    renderInvestigation(data);
  } catch (error) {
    showToast(error.message, true);
  }
}

function resultItem(label, result) {
  const item = document.createElement("article");
  item.className = "result-item";
  const title = document.createElement("strong");
  title.textContent = label;
  const output = document.createElement("pre");
  output.textContent = JSON.stringify(result, null, 2);
  item.append(title, output);
  return item;
}

function renderInvestigation(data) {
  state.investigation = data;
  state.investigationId = data.investigation_id;
  $("#investigation-id").textContent = data.investigation_id;
  $("#refresh-investigation").disabled = false;
  const values = [data.status, data.current_stage, data.severity || "-", data.confidence ?? "-"];
  $$("#investigation-summary strong").forEach((element, index) => {
    element.textContent = values[index];
  });

  const results = $("#agent-results");
  results.replaceChildren();
  [["L1", data.l1_result], ["L2", data.l2_result], ["L3", data.l3_result]].forEach(([label, result]) => {
    if (result) results.append(resultItem(label, result));
  });
  if (!results.children.length) {
    const empty = document.createElement("span");
    empty.className = "muted";
    empty.textContent = "No agent results";
    results.append(empty);
  }

  const audit = $("#audit-trail");
  audit.replaceChildren();
  (data.audit_events || []).slice().reverse().forEach((event) => {
    const item = document.createElement("article");
    item.className = "audit-item";
    const marker = document.createElement("span");
    marker.className = "audit-marker";
    const copy = document.createElement("div");
    copy.className = "audit-copy";
    const title = document.createElement("strong");
    title.textContent = event.event.replaceAll("_", " ");
    const detail = document.createElement("span");
    detail.textContent = `${event.stage} / ${new Date(event.timestamp).toLocaleString()}`;
    copy.append(title, detail);
    item.append(marker, copy);
    audit.append(item);
  });

  renderApproval(data);
  const reportPanel = $("#report-panel");
  reportPanel.classList.toggle("hidden", !data.final_report);
  if (data.final_report) $("#final-report").textContent = JSON.stringify(data.final_report, null, 2);
}

function renderApproval(data) {
  const panel = $("#approval-panel");
  const request = data.approval_request;
  const pending = data.pending_nodes?.includes("human_approval");
  panel.classList.toggle("hidden", !request || !pending);
  if (!request || !pending) return;

  $("#approval-expiry").textContent = `Expires ${new Date(request.expires_at).toLocaleTimeString()}`;
  const actions = $("#approval-actions");
  actions.replaceChildren();
  request.proposed_actions.forEach((action) => {
    const item = document.createElement("article");
    item.className = "action-item";
    const title = document.createElement("strong");
    title.textContent = `${action.action_type} / ${action.target}`;
    const reason = document.createElement("span");
    reason.textContent = action.reason;
    item.append(title, reason);
    actions.append(item);
  });
  $("#modified-actions").value = JSON.stringify(request.proposed_actions, null, 2);
}

async function submitDecision(decision) {
  const request = state.investigation?.approval_request;
  if (!request) return;
  const approvedBy = $("#approver").value.trim();
  if (!approvedBy) {
    showToast("Enter the approver identity.", true);
    return;
  }

  const payload = {
    decision,
    approved_by: approvedBy,
    approval_id: request.approval_id,
  };
  if (decision === "modify") {
    try {
      payload.modified_actions = JSON.parse($("#modified-actions").value);
    } catch {
      showToast("Modified actions must be valid JSON.", true);
      return;
    }
  }

  try {
    const data = await api(
      `/api/v1/investigations/${encodeURIComponent(state.investigationId)}/approval`,
      { method: "POST", body: JSON.stringify(payload) },
      "write",
    );
    renderInvestigation(data);
    showToast(`Decision recorded: ${decision}`);
  } catch (error) {
    showToast(error.message, true);
  }
}

function saveConnection() {
  sessionStorage.setItem("tsage_read_token", $("#read-token").value.trim());
  sessionStorage.setItem("tsage_write_token", $("#write-token").value.trim());
  setConnected(Boolean(readToken()));
  refreshServiceData();
}

function initialize() {
  $("#read-token").value = readToken();
  $("#write-token").value = writeToken();
  setConnected(Boolean(readToken()));

  $$(".nav-item").forEach((button) => button.addEventListener("click", () => switchView(button.dataset.view)));
  $$(".tier-button").forEach((button) => button.addEventListener("click", () => {
    state.tier = button.dataset.tier;
    $$(".tier-button").forEach((item) => item.classList.toggle("active", item === button));
    $(".empty-state span") && ($(".empty-state span").textContent = `Selected agent: SOC ${state.tier.toUpperCase()}`);
  }));
  $("#save-connection").addEventListener("click", saveConnection);
  $("#refresh-data").addEventListener("click", refreshServiceData);
  $("#chat-form").addEventListener("submit", submitChat);
  $("#investigation-form").addEventListener("submit", createInvestigation);
  $("#refresh-investigation").addEventListener("click", loadInvestigation);
  $$(".approval-buttons button").forEach((button) => {
    button.addEventListener("click", () => submitDecision(button.dataset.decision));
  });

  if (readToken()) refreshServiceData();
  if (state.investigationId && readToken()) loadInvestigation();
}

initialize();
