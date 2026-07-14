/* Triager Console
 * Talks to the FastAPI backend mounted at the same origin. */

const state = {
  token: localStorage.getItem("triager_token") || null,
  role: localStorage.getItem("triager_role") || null,
  username: localStorage.getItem("triager_username") || null,
  currentCase: null,
  currentMachine: null,
  machines: [],
  categories: [],
  currentCategory: null,
  currentTable: null,
  currentPage: 1,
  pageSize: 100,
  sortColumn: null,
  sortDir: "asc",
  currentSearch: "",
  jobPollTimer: null,
  jobsRefreshInFlight: false,
  openLogJobId: null,
};

function isReadOnly() {
  return state.role === "read_only";
}

function loadAiConfig() {
  try { return JSON.parse(localStorage.getItem("triager_ai_config") || "{}"); }
  catch (_) { return {}; }
}
function saveAiConfig(cfg) {
  localStorage.setItem("triager_ai_config", JSON.stringify(cfg));
}
function describeAiConfig(cfg) {
  if (!cfg.model) return "no model configured yet";
  if ((cfg.provider || "custom") === "claude") return `Claude &middot; ${cfg.model}`;
  return `${cfg.endpoint || "no endpoint configured yet"} &middot; ${cfg.model}`;
}
function aiConfigIsValid(cfg) {
  if (!cfg.model) return false;
  if ((cfg.provider || "custom") === "claude") return !!cfg.apiKey;
  return !!cfg.endpoint;
}
function aiRequestBase(cfg) {
  const provider = cfg.provider || "custom";
  return {
    provider,
    endpoint: provider === "claude" ? null : cfg.endpoint,
    model: cfg.model,
    api_key: cfg.apiKey || null,
    max_tokens: cfg.maxTokens ? Number(cfg.maxTokens) : null,
  };
}

// Renders AI answers as interpreted Markdown. Sanitized with DOMPurify
// before injection, the model's answer can quote/reflect strings pulled
// straight from evidence data (filenames, registry values, etc.), which
// may contain attacker-crafted HTML/script; treat it as untrusted input
// even though the investigator triggered the request themselves.
function renderMarkdown(md) {
  const raw = window.marked ? marked.parse(md || "") : escapeHtml(md || "").replace(/\n/g, "<br>");
  return window.DOMPurify ? DOMPurify.sanitize(raw) : raw;
}

// The modern Clipboard API (navigator.clipboard) only exists in a "secure
// context", HTTPS, or http://localhost. A self-hosted tool like this one
// is often reached over plain HTTP via a LAN IP (http://192.168.x.x:8000),
// where navigator.clipboard is simply undefined and every copy silently
// fails. document.execCommand('copy') is deprecated but still works in
// insecure contexts in every major browser, so it's the fallback here
// rather than the last resort.
function execCommandCopyText(text) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.top = "0";
  ta.style.left = "-9999px";
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  let ok = false;
  try { ok = document.execCommand("copy"); } catch (_) { ok = false; }
  document.body.removeChild(ta);
  return ok;
}

function execCommandCopyHtml(html) {
  const container = document.createElement("div");
  container.contentEditable = "true";
  container.style.position = "fixed";
  container.style.top = "0";
  container.style.left = "-9999px";
  container.innerHTML = html;
  document.body.appendChild(container);

  const range = document.createRange();
  range.selectNodeContents(container);
  const sel = window.getSelection();
  sel.removeAllRanges();
  sel.addRange(range);

  let ok = false;
  try { ok = document.execCommand("copy"); } catch (_) { ok = false; }
  sel.removeAllRanges();
  document.body.removeChild(container);
  return ok;
}

async function copyPlainText(text) {
  try {
    if (window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (_) { /* fall through to the legacy path below */ }
  return execCommandCopyText(text);
}

// Copies rich HTML (so pasting into Word/Docs/Slack keeps formatting),
// falling back to plain text if the browser doesn't support writing
// multi-format clipboard items (e.g. older Firefox, or a non-secure origin).
async function copyRichHtml(html, plainFallback) {
  try {
    if (window.isSecureContext && navigator.clipboard && window.ClipboardItem) {
      const item = new ClipboardItem({
        "text/html": new Blob([html], { type: "text/html" }),
        "text/plain": new Blob([plainFallback], { type: "text/plain" }),
      });
      await navigator.clipboard.write([item]);
      return true;
    }
  } catch (_) { /* fall through to the legacy path below */ }
  if (execCommandCopyHtml(html)) return true;
  return execCommandCopyText(plainFallback);
}

function goToAiSettings() {
  document.querySelectorAll("#top-nav .tab").forEach((b) => b.classList.remove("active"));
  document.querySelector('#top-nav [data-view="ai-settings"]').classList.add("active");
  document.getElementById("sidebar").style.display = "none";
  renderAiSettingsView();
}

// API
async function api(path, { method = "GET", body, headers = {}, raw = false } = {}) {
  const opts = { method, headers: { ...headers } };
  if (body instanceof FormData) {
    opts.body = body;
  } else if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  if (state.token) opts.headers["Authorization"] = `Bearer ${state.token}`;

  const resp = await fetch(path, opts);
  if (resp.status === 401) {
    logout();
    throw new Error("Session expired, please sign in again");
  }
  if (!resp.ok) {
    let detail = resp.statusText;
    try { detail = (await resp.json()).detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  if (raw) return resp;
  const ct = resp.headers.get("content-type") || "";
  return ct.includes("application/json") ? resp.json() : resp.text();
}

// Authenticated file download, a plain <a href> can't carry the Bearer
// token, so the browser makes an anonymous request and the API (correctly)
// rejects it with 401. Fetch with the auth header instead, then hand the
// browser a blob URL to download.
async function downloadAuthenticated(url, filename) {
  const resp = await api(url, { raw: true });
  const blob = await resp.blob();
  const objectUrl = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = objectUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(objectUrl), 4000);
}

// auth
function showLogin() {
  document.getElementById("login-screen").style.display = "flex";
  document.getElementById("app").classList.remove("active");
}
function showApp() {
  document.getElementById("login-screen").style.display = "none";
  document.getElementById("app").classList.add("active");
  document.getElementById("who-am-i").textContent = `${state.username} :: ${state.role}`;
  document.getElementById("nav-users").style.display = state.role === "admin" ? "inline-block" : "none";
  document.getElementById("nav-global-audit").style.display = state.role === "admin" ? "inline-block" : "none";
  const aiNavBtn = document.querySelector('#top-nav [data-view="ai-settings"]');
  if (aiNavBtn) aiNavBtn.style.display = isReadOnly() ? "none" : "inline-block";
  renderCasesView();
}

async function login() {
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;
  const errEl = document.getElementById("login-error");
  errEl.textContent = "";
  try {
    const form = new URLSearchParams();
    form.set("username", username);
    form.set("password", password);
    const resp = await fetch("/auth/login", { method: "POST", body: form });
    if (!resp.ok) throw new Error("Invalid credentials");
    const data = await resp.json();
    state.token = data.access_token;
    state.role = data.role;
    state.username = data.username;
    localStorage.setItem("triager_token", state.token);
    localStorage.setItem("triager_role", state.role);
    localStorage.setItem("triager_username", state.username);
    showApp();
  } catch (ex) {
    errEl.textContent = ex.message;
  }
}

function logout() {
  state.token = null;
  localStorage.removeItem("triager_token");
  localStorage.removeItem("triager_role");
  localStorage.removeItem("triager_username");
  clearInterval(state.jobPollTimer);
  showLogin();
}

document.getElementById("login-btn").addEventListener("click", login);
document.getElementById("login-password").addEventListener("keydown", (e) => { if (e.key === "Enter") login(); });
document.getElementById("logout-btn").addEventListener("click", logout);
document.querySelectorAll("#top-nav .tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#top-nav .tab").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("sidebar").style.display = "none";
    if (btn.dataset.view === "cases") renderCasesView();
    if (btn.dataset.view === "users") renderUsersView();
    if (btn.dataset.view === "ai-settings") renderAiSettingsView();
    if (btn.dataset.view === "global-audit") renderGlobalAuditView();
  });
});

// helpers
function el(html) {
  const t = document.createElement("template");
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}
function fmtBytes(n) {
  if (!n && n !== 0) return "";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(1)} ${u[i]}`;
}
function escapeHtml(v) {
  if (v === null || v === undefined) return "";
  return String(v).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])).slice(0, 500);
}
function escapeAttr(v) {
  if (v === null || v === undefined) return "";
  return String(v).replace(/"/g, "&quot;").slice(0, 2000);
}

// Reusable search box with column-name autocomplete. fields is either a
// flat array of column names (single-table mode) or an array of
// {label, columns} (cross-table mode, correlation/timeline).
function queryHintText(crossTable) {
  const field = crossTable ? "artifact.column" : "column";
  return `Simple: type a term. Advanced: ${field} contains value, also not_contains / startswith / endswith / = / != / regex, combine with and / or.`;
}

const QUERY_OPERATORS = ["contains", "not_contains", "startswith", "endswith", "=", "!=", "regex"];

function mountQueryBox(container, { fields, crossTable, placeholder, initialValue, onSearch }) {
  container.innerHTML = `
    <div class="query-box">
      <input type="text" class="qb-input" placeholder="${placeholder}" value="${escapeAttr(initialValue || "")}" autocomplete="off" />
      <div class="qb-suggestions"></div>
    </div>
  `;
  const input = container.querySelector(".qb-input");
  const suggBox = container.querySelector(".qb-suggestions");
  let activeIndex = -1;
  let currentMatches = [];

  function currentToken() {
    const val = input.value;
    const pos = input.selectionStart;
    const before = val.slice(0, pos);
    const m = before.match(/([A-Za-z0-9_.=!]*)$/);
    return m ? m[1] : "";
  }

  // Word position within the current and/or-delimited segment: 0 = typing
  // the field, 1 = typing the operator, 2+ = typing the value (no suggestions).
  function wordPositionInSegment() {
    const val = input.value;
    const pos = input.selectionStart;
    const before = val.slice(0, pos);
    const segments = before.split(/\s+(?:and|or)\s+/i);
    const segment = segments[segments.length - 1];
    const endsWithSpace = /\s$/.test(segment);
    const words = segment.split(/\s+/).filter(Boolean);
    return endsWithSpace ? words.length : Math.max(0, words.length - 1);
  }

  function buildSuggestions(prefix, wordPos) {
    const p = prefix.toLowerCase();
    if (wordPos === 1) {
      return QUERY_OPERATORS
        .filter((op) => op.toLowerCase().startsWith(p))
        .map((op) => ({ display: op, insert: op }));
    }
    const results = [];
    if (crossTable) {
      for (const f of fields) {
        const slug = f.label.toLowerCase().replace(/[^a-z0-9]/g, "");
        for (const col of f.columns) {
          const full = `${slug}.${col}`;
          if (full.startsWith(p) || col.toLowerCase().startsWith(p)) {
            results.push({ display: `${f.label}.${col}`, insert: full });
            if (results.length >= 30) return results;
          }
        }
      }
    } else {
      for (const col of fields) {
        if (col.toLowerCase().startsWith(p)) {
          results.push({ display: col, insert: col });
          if (results.length >= 30) return results;
        }
      }
    }
    return results;
  }

  function renderSuggestions() {
    if (currentMatches.length === 0) { suggBox.innerHTML = ""; return; }
    suggBox.innerHTML = currentMatches.map((m, i) =>
      `<div class="qb-suggestion${i === activeIndex ? " qb-suggestion-active" : ""}" data-insert="${escapeAttr(m.insert)}">${escapeHtml(m.display)}</div>`
    ).join("");
    suggBox.querySelectorAll(".qb-suggestion").forEach((item, i) => {
      item.addEventListener("mousedown", (e) => {
        e.preventDefault();
        applySuggestion(currentMatches[i]);
      });
    });
  }

  function applySuggestion(match) {
    const pos = input.selectionStart;
    const val = input.value;
    const before = val.slice(0, pos).replace(/[A-Za-z0-9_.=!]*$/, "");
    const after = val.slice(pos);
    input.value = `${before}${match.insert} ${after}`;
    const newPos = `${before}${match.insert} `.length;
    input.focus();
    input.setSelectionRange(newPos, newPos);
    showSuggestions();
  }

  function showSuggestions() {
    const wordPos = wordPositionInSegment();
    if (wordPos > 1) { activeIndex = -1; currentMatches = []; renderSuggestions(); return; }
    const token = currentToken();
    activeIndex = -1;
    currentMatches = (token || wordPos === 1) ? buildSuggestions(token, wordPos) : [];
    renderSuggestions();
  }

  input.addEventListener("input", showSuggestions);
  input.addEventListener("keydown", (e) => {
    if (currentMatches.length > 0 && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
      e.preventDefault();
      const delta = e.key === "ArrowDown" ? 1 : -1;
      activeIndex = (activeIndex + delta + currentMatches.length) % currentMatches.length;
      renderSuggestions();
      return;
    }
    if (e.key === "Enter") {
      if (activeIndex >= 0 && currentMatches[activeIndex]) {
        e.preventDefault();
        applySuggestion(currentMatches[activeIndex]);
        return;
      }
      suggBox.innerHTML = "";
      currentMatches = [];
      onSearch(input.value.trim());
      return;
    }
    if (e.key === "Escape") { currentMatches = []; suggBox.innerHTML = ""; }
  });
  input.addEventListener("blur", () => setTimeout(() => { currentMatches = []; suggBox.innerHTML = ""; }, 150));

  return {
    getValue: () => input.value.trim(),
    focusInput: () => input.focus(),
  };
}

// Cases list
async function renderCasesView() {
  const main = document.getElementById("main");
  main.innerHTML = "<h2>Cases</h2><div class='subtitle'>Loading...</div>";
  const cases = await api("/cases");

  const canCreate = state.role === "admin" || state.role === "lead";
  main.innerHTML = `
    <h2>Cases</h2>
    <div class="subtitle">${cases.length} case(s) visible to you</div>
    ${canCreate ? `<div class="toolbar"><button class="primary" id="new-case-btn">+ New case</button></div>` : ""}
    <div class="grid" id="cases-grid"></div>
  `;
  const grid = document.getElementById("cases-grid");
  if (cases.length === 0) {
    grid.appendChild(el(`<div class="empty-state">No cases yet. ${canCreate ? "Create one to get started." : "Ask a case lead to add you."}</div>`));
  }
  cases.forEach((c) => {
    const card = el(`
      <div class="card">
        <div class="title">${c.name}</div>
        <div class="meta">${c.reference || "no reference"} &middot; ${c.id.slice(0, 8)}</div>
        <div class="meta" style="margin-top:6px"><span class="status-pill ${c.status}">${c.status}</span></div>
        ${canCreate ? `<div style="margin-top:10px"><button class="danger delete-case-btn" data-id="${c.id}" data-name="${escapeAttr(c.name)}">Delete</button></div>` : ""}
      </div>
    `);
    card.addEventListener("click", (e) => {
      if (e.target.classList.contains("delete-case-btn")) return;
      openCase(c.id);
    });
    const delBtn = card.querySelector(".delete-case-btn");
    if (delBtn) {
      delBtn.addEventListener("click", async (e) => {
        e.stopPropagation();
        if (!confirm(`Permanently delete case "${c.name}"? This deletes every machine and all imported artifact data. This cannot be undone.`)) return;
        await api(`/cases/${c.id}`, { method: "DELETE" });
        renderCasesView();
      });
    }
    grid.appendChild(card);
  });

  if (canCreate) {
    document.getElementById("new-case-btn").addEventListener("click", showNewCaseForm);
  }
}

function showNewCaseForm() {
  const main = document.getElementById("main");
  main.innerHTML = `
    <h2>New case</h2>
    <div class="panel" style="max-width:480px">
      <div class="form-row"><label>Case name</label><input id="nc-name" type="text" /></div>
      <div class="form-row"><label>Reference / ticket number</label><input id="nc-ref" type="text" /></div>
      <div class="form-row"><label>Description</label><textarea id="nc-desc"></textarea></div>
      <button class="primary" id="nc-create">Create case</button>
      <button id="nc-cancel">Cancel</button>
    </div>
  `;
  document.getElementById("nc-cancel").addEventListener("click", renderCasesView);
  document.getElementById("nc-create").addEventListener("click", async () => {
    const name = document.getElementById("nc-name").value.trim();
    if (!name) return;
    const c = await api("/cases", { method: "POST", body: {
      name, reference: document.getElementById("nc-ref").value.trim(),
      description: document.getElementById("nc-desc").value.trim(),
    }});
    openCase(c.id);
  });
}

// Case detail (machines list)
async function openCase(caseId) {
  const caseObj = await api(`/cases/${caseId}`);
  state.currentCase = caseObj;
  state.currentMachine = null;
  state.categories = [];
  state.currentCategory = null;
  state.currentTable = null;

  const machines = await api(`/cases/${caseId}/machines`);
  state.machines = machines;
  renderCaseSidebar();
  renderMachinesView();
}

function sidebarHeader() {
  const c = state.currentCase;
  return `
    <div class="case-name">
      <div class="name">${c.name}</div>
      <div class="ref">${c.reference || c.id.slice(0, 8)}</div>
    </div>
    <div class="special" data-action="back">&larr; All cases</div>
  `;
}

function renderCaseSidebar() {
  const sidebar = document.getElementById("sidebar");
  sidebar.style.display = "block";
  sidebar.innerHTML = sidebarHeader();
  sidebar.querySelector('[data-action="back"]').addEventListener("click", () => {
    sidebar.style.display = "none";
    renderCasesView();
  });

  sidebar.appendChild(el(`<div class="section-label">Machines</div>`));
  state.machines.forEach((m) => {
    const item = el(`
      <div class="cat" data-machine="${m.id}">
        <span>${m.label}${m.hostname ? ` <span class="hint">(${m.hostname})</span>` : ""}</span>
        <span class="status-pill ${m.status}">${m.status}</span>
      </div>
    `);
    item.addEventListener("click", () => openMachine(m.id));
    sidebar.appendChild(item);
  });
  if (!isReadOnly()) {
    const addBtn = el(`<div class="special" data-action="add-machine">&#43; Add machine</div>`);
    addBtn.addEventListener("click", showNewMachineForm);
    sidebar.appendChild(addBtn);
  }

  if (state.currentMachine && (state.currentMachine.status === "ready" || state.currentMachine.status === "ingesting")
      && state.categories.some((c) => c.tables.length > 0)) {
    sidebar.appendChild(el(`<div class="section-label">Artifacts -- ${state.currentMachine.label}${state.currentMachine.status === "ingesting" ? " (partial)" : ""}</div>`));
    state.categories.forEach((cat) => {
      if (cat.tables.length === 0) return;
      const totalRows = cat.tables.reduce((sum, t) => sum + (t.row_count || 0), 0);
      const catEl = el(`
        <div class="cat" data-cat="${cat.key}" title="${cat.tables.length} table(s), ${totalRows.toLocaleString()} row(s)">
          <span>${cat.label}</span><span class="count">${cat.tables.length}</span>
        </div>
      `);
      catEl.addEventListener("click", () => selectCategory(cat.key));
      sidebar.appendChild(catEl);
    });
  }

  const specials = el(`
    <div>
      <div class="section-label">Case tools</div>
      <div class="special" data-action="timeline">&#128197; Timeline</div>
      <div class="special" data-action="correlation">&#128269; Correlation</div>
      <div class="special" data-action="ioc-scan">&#127919; IOC scan</div>
      <div class="special" data-action="findings">&#128204; Findings</div>
      <div class="special" data-action="ai" ${isReadOnly() ? 'style="display:none"' : ""}>&#9729; AI analysis</div>
      <div class="special" data-action="members">&#128101; Case members</div>
      <div class="special" data-action="audit">&#128220; Audit log</div>
      <div class="special" data-action="report">&#128196; Generate report</div>
    </div>
  `);
  specials.querySelector('[data-action="timeline"]').addEventListener("click", renderTimelineView);
  specials.querySelector('[data-action="correlation"]').addEventListener("click", renderCorrelationView);
  specials.querySelector('[data-action="ioc-scan"]').addEventListener("click", renderIocScanView);
  specials.querySelector('[data-action="findings"]').addEventListener("click", renderFindingsView);
  specials.querySelector('[data-action="ai"]').addEventListener("click", renderAIView);
  specials.querySelector('[data-action="members"]').addEventListener("click", renderMembersView);
  specials.querySelector('[data-action="audit"]').addEventListener("click", renderCaseAuditView);
  specials.querySelector('[data-action="report"]').addEventListener("click", renderReportView);
  sidebar.appendChild(specials);

  highlightActive();
}

function highlightActive() {
  document.querySelectorAll(".sidebar .cat[data-machine]").forEach((n) => n.classList.toggle("active", state.currentMachine && n.dataset.machine === state.currentMachine.id && !state.currentCategory));
  document.querySelectorAll(".sidebar .cat[data-cat]").forEach((n) => n.classList.toggle("active", n.dataset.cat === state.currentCategory && !state.currentTable));
  document.querySelectorAll(".sidebar .special").forEach((n) => n.classList.remove("active"));
}

// Machines list (main panel)
function renderMachinesView() {
  const main = document.getElementById("main");
  const c = state.currentCase;
  const canManageCase = state.role === "admin" || state.role === "lead";
  const isClosed = c.status === "closed";
  main.innerHTML = `
    <h2>Machines <span class="status-pill ${c.status}" style="margin-left:8px; vertical-align:middle">${c.status}</span></h2>
    <div class="subtitle">${state.machines.length} machine(s) in this case.</div>
    <div class="toolbar">
      ${!isClosed && !isReadOnly() ? `<button class="primary" id="new-machine-btn">+ Add machine</button>` : ""}
      ${canManageCase ? `<button id="toggle-case-status-btn">${isClosed ? "Reopen case" : "Close case"}</button>` : ""}
      ${canManageCase ? `<button class="danger" id="delete-case-btn">Delete case</button>` : ""}
    </div>
    ${isClosed ? `<div class="hint" style="margin-bottom:12px">This case is closed -- reopen it to add machines or re-ingest evidence. Existing artifacts are still browsable below.</div>` : ""}
    <div class="grid" id="machines-grid"></div>
  `;
  const grid = document.getElementById("machines-grid");
  if (state.machines.length === 0) {
    grid.appendChild(el(`<div class="empty-state">No machines yet. Add one and upload its evidence/triage ZIP.</div>`));
  }
  state.machines.forEach((m) => {
    const card = el(`
      <div class="card">
        <div class="title">${m.label}</div>
        <div class="meta">${m.hostname || "hostname unknown yet"}${m.operating_system ? " &middot; " + m.operating_system : ""}</div>
        <div class="meta" style="margin-top:6px"><span class="status-pill ${m.status}">${m.status}</span></div>
        <div style="margin-top:10px">${isReadOnly() ? "" : `<button class="danger delete-machine-btn" data-id="${m.id}">Delete</button>`}</div>
      </div>
    `);
    card.addEventListener("click", (e) => {
      if (e.target.classList.contains("delete-machine-btn")) return;
      openMachine(m.id);
    });
    const cardDeleteBtn = card.querySelector(".delete-machine-btn");
    if (cardDeleteBtn) cardDeleteBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      if (!confirm(`Permanently delete machine "${m.label}"? This deletes all of its imported artifact data. This cannot be undone.`)) return;
      await api(`/cases/${state.currentCase.id}/machines/${m.id}`, { method: "DELETE" });
      state.machines = await api(`/cases/${state.currentCase.id}/machines`);
      renderCaseSidebar();
      renderMachinesView();
    });
    grid.appendChild(card);
  });
  const newBtn = document.getElementById("new-machine-btn");
  if (newBtn) newBtn.addEventListener("click", showNewMachineForm);

  const toggleBtn = document.getElementById("toggle-case-status-btn");
  if (toggleBtn) {
    toggleBtn.addEventListener("click", async () => {
      const updated = await api(`/cases/${state.currentCase.id}/status`, {
        method: "PATCH", body: { status: isClosed ? "open" : "closed" },
      });
      state.currentCase = updated;
      renderMachinesView();
    });
  }
  const deleteCaseBtn = document.getElementById("delete-case-btn");
  if (deleteCaseBtn) {
    deleteCaseBtn.addEventListener("click", async () => {
      if (!confirm(`Permanently delete case "${c.name}"? This deletes every machine and all imported artifact data. This cannot be undone.`)) return;
      await api(`/cases/${state.currentCase.id}`, { method: "DELETE" });
      document.getElementById("sidebar").style.display = "none";
      renderCasesView();
    });
  }
}

function showNewMachineForm() {
  const main = document.getElementById("main");
  main.innerHTML = `
    <h2>Add machine</h2>
    <div class="subtitle">One machine = one evidence/triage ZIP for one host.</div>
    <div class="panel" style="max-width:420px">
      <div class="form-row"><label>Label (optional -- defaults to "Machine N")</label><input id="nm-label" type="text" placeholder="e.g. Finance-WKS-07" /></div>
      <button class="primary" id="nm-create">Create machine</button>
      <button id="nm-cancel">Cancel</button>
    </div>
  `;
  document.getElementById("nm-cancel").addEventListener("click", renderMachinesView);
  document.getElementById("nm-create").addEventListener("click", async () => {
    const label = document.getElementById("nm-label").value.trim();
    const m = await api(`/cases/${state.currentCase.id}/machines`, { method: "POST", body: { label: label || null } });
    state.machines.push(m);
    renderCaseSidebar();
    openMachine(m.id);
  });
}

// Machine detail
async function openMachine(machineId) {
  const machine = await api(`/cases/${state.currentCase.id}/machines/${machineId}`);
  state.currentMachine = machine;
  state.currentCategory = null;
  state.currentTable = null;

  const idx = state.machines.findIndex((m) => m.id === machineId);
  if (idx >= 0) state.machines[idx] = machine;

  if (machine.status === "new" || machine.status === "error") {
    state.categories = [];
    renderCaseSidebar();
    renderIngestWizard();
  } else if (machine.status === "ingesting") {
    try {
      state.categories = await api(`/cases/${state.currentCase.id}/machines/${machineId}/artifacts/categories`);
    } catch (_) {
      state.categories = [];
    }
    renderCaseSidebar();
    renderIngestProgress();
  } else {
    state.categories = await api(`/cases/${state.currentCase.id}/machines/${machineId}/artifacts/categories`);
    renderCaseSidebar();
    renderMachineOverview();
  }
}

function machineMetaCard(m) {
  const rows = [
    ["Hostname", m.hostname || "unknown"],
    ["Operating system", m.operating_system || "unknown"],
    ["IP address(es)", (m.ip_addresses || []).join(", ") || "unknown"],
    ["Timezone", m.timezone || "unknown"],
    ["OS install date", m.os_install_date || "unknown"],
    ["Source", m.source_kind === "evidence" ? `Raw evidence (${m.triage_profile})` : "Pre-processed Triager output"],
  ];
  return `
    <div class="panel meta-card">
      <div class="meta-card-title">${m.label}</div>
      <div class="meta-grid">
        ${rows.map(([k, v]) => `<div class="meta-k">${k}</div><div class="meta-v">${escapeHtml(v)}</div>`).join("")}
      </div>
    </div>
  `;
}

function renderMachineOverview() {
  const m = state.currentMachine;
  const main = document.getElementById("main");
  const categoriesWithTables = state.categories.filter((c) => c.tables.length > 0);

  main.innerHTML = `
    <div class="breadcrumb"><a href="#" id="bc-machines">Machines</a> / ${m.label}</div>
    <h2>${m.label}</h2>
    <div class="subtitle">Host metadata and artifact categories for this machine.</div>
    ${m.status === "ingesting" ? `<div class="hint" style="margin-bottom:10px">Ingest is still running -- this shows only what's been imported so far. <a href="#" id="back-to-progress">View ingest progress</a></div>` : ""}
    ${machineMetaCard(m)}
    <div class="toolbar" style="margin-top:10px">
      <button class="primary" id="download-processed-btn">Download processed data (.zip)</button>
      ${isReadOnly() ? "" : `<button class="danger" id="delete-machine-btn">Delete this machine</button>`}
    </div>
    <h3 style="margin-top:20px; font-size:13px; color:var(--text-dim); text-transform:uppercase; letter-spacing:0.08em;">Artifact categories</h3>
    <div class="grid" id="cat-grid"></div>
  `;
  document.getElementById("bc-machines").addEventListener("click", (e) => { e.preventDefault(); state.currentMachine = null; renderCaseSidebar(); renderMachinesView(); });
  const backToProgress = document.getElementById("back-to-progress");
  if (backToProgress) backToProgress.addEventListener("click", (e) => { e.preventDefault(); renderIngestProgress(); });
  document.getElementById("download-processed-btn").addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = "Preparing download...";
    try {
      await downloadAuthenticated(
        `/cases/${state.currentCase.id}/machines/${m.id}/download`,
        `${m.label.replace(/[^a-zA-Z0-9 _-]/g, "_")}_processed.zip`,
      );
    } catch (ex) {
      alert(`Download failed: ${ex.message}`);
    } finally {
      btn.disabled = false;
      btn.textContent = originalText;
    }
  });
  const machineDeleteBtn = document.getElementById("delete-machine-btn");
  if (machineDeleteBtn) machineDeleteBtn.addEventListener("click", async () => {
    if (!confirm(`Permanently delete machine "${m.label}"? This deletes all of its imported artifact data. This cannot be undone.`)) return;
    await api(`/cases/${state.currentCase.id}/machines/${m.id}`, { method: "DELETE" });
    state.machines = await api(`/cases/${state.currentCase.id}/machines`);
    state.currentMachine = null;
    renderCaseSidebar();
    renderMachinesView();
  });
  const grid = document.getElementById("cat-grid");
  if (categoriesWithTables.length === 0) {
    grid.appendChild(el(`<div class="empty-state">Import succeeded but no artifact tables were produced. Check the ingest job log.</div>`));
  }
  categoriesWithTables.forEach((cat) => {
    const totalRows = cat.tables.reduce((sum, t) => sum + (t.row_count || 0), 0);
    const card = el(`
      <div class="card">
        <div class="title">${cat.label}</div>
        <div class="meta">${cat.tables.length} table(s) &middot; ${totalRows.toLocaleString()} row(s)</div>
      </div>
    `);
    card.addEventListener("click", () => selectCategory(cat.key));
    grid.appendChild(card);
  });
}

// Category landing view (the "kind" picker)
function selectCategory(catKey) {
  state.currentCategory = catKey;
  state.currentTable = null;
  highlightActive();
  renderCategoryView();
}

function renderCategoryView() {
  const cat = state.categories.find((c) => c.key === state.currentCategory);
  const main = document.getElementById("main");
  if (!cat || cat.tables.length === 0) {
    main.innerHTML = `<div class="empty-state">No tables were imported for this category.</div>`;
    return;
  }

  main.innerHTML = `
    <div class="breadcrumb"><a href="#" id="bc-machine">${state.currentMachine.label}</a> / ${cat.label}</div>
    <h2>${cat.label}</h2>
    <div class="subtitle">${cat.tables.length} artifact table(s) -- select one to view its data</div>
    <div class="grid" id="table-grid"></div>
  `;
  document.getElementById("bc-machine").addEventListener("click", (e) => { e.preventDefault(); renderMachineOverview(); state.currentCategory = null; highlightActive(); });
  const grid = document.getElementById("table-grid");
  cat.tables.forEach((t) => {
    const card = el(`
      <div class="card">
        <div class="title">${t.label}</div>
        <div class="meta">${t.row_count.toLocaleString()} row(s)</div>
      </div>
    `);
    card.addEventListener("click", () => selectTable(cat.key, t.name));
    grid.appendChild(card);
  });
}

// Data table view
async function selectTable(catKey, table) {
  state.currentCategory = catKey;
  state.currentTable = table;
  state.currentPage = 1;
  state.currentSearch = "";
  state.sortColumn = null;
  highlightActive();
  await loadTablePage();
}

async function loadTablePage() {
  const main = document.getElementById("main");
  const cat = state.categories.find((cc) => cc.key === state.currentCategory);
  const tableMeta = cat && cat.tables.find((t) => t.name === state.currentTable);
  main.innerHTML = `<h2>${tableMeta ? tableMeta.label : state.currentTable}</h2><div class="subtitle">Loading...</div>`;

  const payload = {
    table: state.currentTable,
    page: state.currentPage,
    page_size: state.pageSize,
    sort_column: state.sortColumn,
    sort_dir: state.sortDir,
    query: state.currentSearch || undefined,
  };
  const data = await api(`/cases/${state.currentCase.id}/machines/${state.currentMachine.id}/artifacts/query`, { method: "POST", body: payload });

  main.innerHTML = `
    <div class="breadcrumb"><a href="#" id="bc-machine">${state.currentMachine.label}</a> / <a href="#" id="bc-cat">${cat ? cat.label : "Category"}</a> / ${tableMeta ? tableMeta.label : data.table}</div>
    <h2>${tableMeta ? tableMeta.label : data.table}</h2>
    <div class="subtitle">${data.total_rows.toLocaleString()} row(s) &middot; page ${data.page}</div>
    <div class="toolbar">
      <div id="row-search-box" class="query-box-wrap"></div>
      <button class="primary" id="row-search-btn">Search</button>
      ${state.currentSearch ? `<button id="row-search-clear">Clear</button>` : ""}
      <div class="spacer"></div>
      ${isReadOnly() ? "" : `<button id="ai-quick-btn">&#9729; AI analysis</button>`}
      <button id="export-csv-btn">${state.currentSearch ? "Export filtered CSV" : "Export CSV"}</button>
      ${state.currentSearch ? `<button id="export-csv-all-btn">Export full CSV</button>` : ""}
    </div>
    <div class="hint query-hint">${queryHintText(false)}</div>
    <div class="table-scroll">
      <table class="data-table" id="data-table">
        <thead><tr>${data.columns.map((col) => `<th data-col="${col}"><span class="th-label">${col}</span><span class="col-resizer"></span></th>`).join("")}</tr></thead>
        <tbody>${data.rows.map((row) => `<tr>${data.columns.map((col) => `<td title="${escapeAttr(row[col])}">${escapeHtml(row[col])}</td>`).join("")}</tr>`).join("")}</tbody>
      </table>
    </div>
    <div class="pager">
      <button id="pg-prev" ${data.page <= 1 ? "disabled" : ""}>&larr; Prev</button>
      <span>Page ${data.page} of ${Math.max(1, Math.ceil(data.total_rows / data.page_size))}</span>
      <button id="pg-next" ${data.page * data.page_size >= data.total_rows ? "disabled" : ""}>Next &rarr;</button>
    </div>
    <div id="ai-inline-panel"></div>
  `;

  document.getElementById("bc-machine").addEventListener("click", (e) => { e.preventDefault(); state.currentCategory = null; state.currentTable = null; renderMachineOverview(); highlightActive(); });
  document.getElementById("bc-cat").addEventListener("click", (e) => { e.preventDefault(); state.currentTable = null; renderCategoryView(); highlightActive(); });

  const runSearch = (value) => {
    state.currentSearch = (value !== undefined ? value : qb.getValue());
    state.currentPage = 1;
    loadTablePage();
  };
  const qb = mountQueryBox(document.getElementById("row-search-box"), {
    fields: data.columns,
    crossTable: false,
    placeholder: "Search all columns, or column contains value and column2 = value2...",
    initialValue: state.currentSearch,
    onSearch: runSearch,
  });
  document.getElementById("row-search-btn").addEventListener("click", () => runSearch());
  const clearBtn = document.getElementById("row-search-clear");
  if (clearBtn) clearBtn.addEventListener("click", () => { state.currentSearch = ""; state.currentPage = 1; loadTablePage(); });

  document.getElementById("pg-prev").addEventListener("click", () => { state.currentPage--; loadTablePage(); });
  document.getElementById("pg-next").addEventListener("click", () => { state.currentPage++; loadTablePage(); });
  document.querySelectorAll("#data-table th .th-label").forEach((label) => {
    label.addEventListener("click", () => {
      const col = label.closest("th").dataset.col;
      state.sortDir = state.sortColumn === col && state.sortDir === "asc" ? "desc" : "asc";
      state.sortColumn = col;
      loadTablePage();
    });
  });
  enableColumnResize(document.getElementById("data-table"));
  document.querySelectorAll("#data-table tbody tr").forEach((tr, idx) => {
    tr.style.cursor = "pointer";
    tr.addEventListener("click", () => showRowDetail(tableMeta ? tableMeta.label : data.table, data.rows[idx], {
      machineId: state.currentMachine.id, machineLabel: state.currentMachine.label,
      table: data.table, tableLabel: tableMeta ? tableMeta.label : data.table,
    }));
  });

  document.getElementById("export-csv-btn").addEventListener("click", () => {
    const queryParam = state.currentSearch ? `?query=${encodeURIComponent(state.currentSearch)}` : "";
    downloadAuthenticated(
      `/cases/${state.currentCase.id}/machines/${state.currentMachine.id}/artifacts/tables/${data.table}/export.csv${queryParam}`,
      `${data.table}${state.currentSearch ? "_filtered" : ""}.csv`,
    );
  });
  const exportAllBtn = document.getElementById("export-csv-all-btn");
  if (exportAllBtn) {
    exportAllBtn.addEventListener("click", () => {
      downloadAuthenticated(
        `/cases/${state.currentCase.id}/machines/${state.currentMachine.id}/artifacts/tables/${data.table}/export.csv`,
        `${data.table}.csv`,
      );
    });
  }

  const aiQuickBtn = document.getElementById("ai-quick-btn");
  if (aiQuickBtn) {
    aiQuickBtn.addEventListener("click", () => {
      renderInlineAiPanel(tableMeta ? tableMeta.label : data.table, data.table);
    });
    autoShowAiHistoryIfPresent(tableMeta ? tableMeta.label : data.table, data.table);
  }
}

// If this table already has a saved AI conversation, show it right away
// instead of making the investigator remember to click "AI analysis"
// again to see it.
async function autoShowAiHistoryIfPresent(tableLabel, table) {
  try {
    const conversationKey = `table:${state.currentMachine.id}:${table}`;
    const history = await api(`/cases/${state.currentCase.id}/ai/history?conversation_key=${encodeURIComponent(conversationKey)}`);
    // Bail if the investigator already navigated elsewhere while this was loading.
    if (state.currentTable !== table) return;
    if (history.length > 0) {
      renderInlineAiPanel(tableLabel, table);
    }
  } catch (_) {
    // Don't let a history-check failure block the table from rendering.
  }
}

function renderInlineAiPanel(tableLabel, table) {
  const host = document.getElementById("ai-inline-panel");
  if (!host) return;
  host.innerHTML = `
    <div class="panel ai-inline" style="margin-top:14px">
      <div class="modal-title" style="margin-bottom:10px">AI analysis -- ${tableLabel}${state.currentSearch ? ` (filtered: "${state.currentSearch}")` : ""}</div>
      <div id="ai-inline-host"></div>
    </div>
  `;
  mountAiConversation(document.getElementById("ai-inline-host"), {
    conversationKey: `table:${state.currentMachine.id}:${table}`,
    askExtra: { machine_id: state.currentMachine.id, tables: [table], query: state.currentSearch || null },
    defaultQuestion: "Summarize anything notable or suspicious in the data currently shown, and call out entries that warrant closer review.",
  });
}

// Drag-to-resize columns. Applies table-layout:fixed with explicit <th>
// widths so a resize on one column doesn't reflow every other column.
function enableColumnResize(table) {
  if (!table) return;
  const ths = table.querySelectorAll("th");
  table.style.tableLayout = "fixed";
  ths.forEach((th) => {
    if (!th.style.width) th.style.width = `${th.offsetWidth}px`;
    const handle = th.querySelector(".col-resizer");
    if (!handle) return;
    let startX = 0, startWidth = 0;
    const onMove = (e) => {
      const dx = e.clientX - startX;
      th.style.width = `${Math.max(60, startWidth + dx)}px`;
    };
    const onUp = () => {
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
    };
    handle.addEventListener("mousedown", (e) => {
      e.preventDefault();
      e.stopPropagation();
      startX = e.clientX;
      startWidth = th.offsetWidth;
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
  });
}

// Modal (full-row detail)
function showModal(title, bodyHtml) {
  closeModal();
  const overlay = el(`
    <div class="modal-overlay" id="modal-overlay">
      <div class="modal-box">
        <div class="modal-head">
          <div class="modal-title">${title}</div>
          <button id="modal-close">&times;</button>
        </div>
        <div class="modal-body">${bodyHtml}</div>
      </div>
    </div>
  `);
  overlay.addEventListener("click", (e) => { if (e.target === overlay) closeModal(); });
  overlay.querySelector("#modal-close").addEventListener("click", closeModal);
  document.body.appendChild(overlay);
}
function closeModal() {
  const existing = document.getElementById("modal-overlay");
  if (existing) existing.remove();
}
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeModal();
});

function showRowDetail(tableLabel, row, meta) {
  const fields = Object.entries(row)
    .map(([k, v]) => `
      <div class="detail-row">
        <div class="detail-key">${k}</div>
        <div class="detail-val">${escapeHtml(v) || "<span class=\"hint\">(empty)</span>"}</div>
      </div>
    `).join("");
  const canFlag = !!(state.currentCase && meta) && !isReadOnly();
  showModal(tableLabel, `
    <div class="detail-grid">${fields}</div>
    ${canFlag ? `
      <div class="finding-flag-box">
        <textarea id="finding-note" placeholder="Why does this matter? (note saved with this event as a finding)"></textarea>
        <button class="primary" id="finding-save">Flag as finding</button>
        <div class="hint" id="finding-status"></div>
      </div>
    ` : ""}
  `);
  if (canFlag) {
    document.getElementById("finding-save").addEventListener("click", async () => {
      const note = document.getElementById("finding-note").value.trim();
      const statusEl = document.getElementById("finding-status");
      if (!note) { statusEl.textContent = "Write a note first."; return; }
      try {
        await api(`/cases/${state.currentCase.id}/findings`, {
          method: "POST",
          body: {
            machine_id: meta.machineId || null, machine_label: meta.machineLabel || null,
            table_name: meta.table || null, table_label: meta.tableLabel || null,
            row_snapshot: row, note,
          },
        });
        statusEl.textContent = "Saved as a finding.";
        document.getElementById("finding-save").disabled = true;
      } catch (ex) {
        statusEl.textContent = `Error: ${ex.message}`;
      }
    });
  }
}

// Reusable AI conversation panel
// Mounts a full AI conversation (persisted history + ask box) into host.
// conversationKey scopes the history server-side (e.g. "broad:case",
// "broad:<machine_id>", or "table:<machine_id>:<table>") so each place "AI
// analysis" appears keeps its own independent, continuable thread.
// askExtra supplies the fixed parts of every /ai/ask call for this panel
// (machine_id / tables / search); templates, if given, renders DFIR
// question-template buttons above the input box.
async function mountAiConversation(host, { conversationKey, askExtra, templates, defaultQuestion }) {
  const cfg = loadAiConfig();
  host.innerHTML = `
    <div class="ai-conv-toolbar">
      <div class="hint">Using ${describeAiConfig(cfg)} -- <a href="#" id="aic-settings-link">change in AI Settings</a></div>
      <button id="aic-clear">Clear history</button>
    </div>
    ${templates ? `<div class="template-box" id="aic-templates" style="margin-bottom:10px">${templates.map((t, i) => `<button type="button" class="template-btn" data-idx="${i}">${t.label}</button>`).join("")}</div>` : ""}
    <div class="ai-thread" id="aic-thread"></div>
    <div class="form-row"><textarea id="aic-question" placeholder="Ask a question...">${defaultQuestion || ""}</textarea></div>
    <button class="primary" id="aic-ask">Ask</button>
    <div class="hint" id="aic-status"></div>
  `;

  document.getElementById("aic-settings-link").addEventListener("click", (e) => { e.preventDefault(); goToAiSettings(); });

  if (templates) {
    document.querySelectorAll("#aic-templates .template-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.getElementById("aic-question").value = templates[Number(btn.dataset.idx)].question;
        document.querySelectorAll("#aic-templates .template-btn").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
      });
    });
  }

  function appendTurn(thread, m) {
    if (m.role === "user") {
      thread.appendChild(el(`
        <div class="ai-turn ai-turn-user">
          <div class="ai-turn-label">You</div>
          <div class="ai-turn-text">${escapeHtml(m.content)}</div>
        </div>
      `));
      return;
    }
    const turn = el(`
      <div class="ai-turn ai-turn-assistant">
        <div class="ai-turn-label">AI</div>
        <div class="ai-answer-rendered">${renderMarkdown(m.content)}</div>
        <div class="ai-turn-actions">
          <button class="copy-md-btn">Copy Markdown</button>
          <button class="copy-rendered-btn">Copy Rendered</button>
        </div>
      </div>
    `);
    const flashLabel = (btn, label, ok) => {
      const original = label;
      btn.textContent = ok ? "Copied!" : "Copy failed";
      setTimeout(() => { btn.textContent = original; }, 1500);
    };
    turn.querySelector(".copy-md-btn").addEventListener("click", async (e) => {
      const ok = await copyPlainText(m.content);
      flashLabel(e.target, "Copy Markdown", ok);
    });
    turn.querySelector(".copy-rendered-btn").addEventListener("click", async (e) => {
      const renderedEl = turn.querySelector(".ai-answer-rendered");
      const ok = await copyRichHtml(renderedEl.innerHTML, renderedEl.innerText);
      flashLabel(e.target, "Copy Rendered", ok);
    });
    thread.appendChild(turn);
  }

  async function loadHistory() {
    const thread = document.getElementById("aic-thread");
    thread.innerHTML = "<div class='hint'>Loading conversation...</div>";
    const history = await api(`/cases/${state.currentCase.id}/ai/history?conversation_key=${encodeURIComponent(conversationKey)}`);
    thread.innerHTML = "";
    if (history.length === 0) {
      thread.appendChild(el(`<div class="hint">No messages yet in this conversation.</div>`));
    }
    history.forEach((m) => appendTurn(thread, m));
    thread.scrollTop = thread.scrollHeight;
  }

  document.getElementById("aic-clear").addEventListener("click", async () => {
    if (!confirm("Clear this conversation's history? This cannot be undone.")) return;
    await api(`/cases/${state.currentCase.id}/ai/history?conversation_key=${encodeURIComponent(conversationKey)}`, { method: "DELETE" });
    const thread = document.getElementById("aic-thread");
    thread.innerHTML = `<div class="hint">No messages yet in this conversation.</div>`;
  });

  document.getElementById("aic-ask").addEventListener("click", async () => {
    const cfgNow = loadAiConfig();
    const statusEl = document.getElementById("aic-status");
    if (!aiConfigIsValid(cfgNow)) {
      statusEl.textContent = "Finish setting up your provider (model, and endpoint or API key) in AI Settings first.";
      return;
    }
    const questionEl = document.getElementById("aic-question");
    const question = questionEl.value.trim();
    if (!question) return;
    statusEl.textContent = "Thinking...";
    try {
      const resp = await api(`/cases/${state.currentCase.id}/ai/ask`, {
        method: "POST",
        body: { ...aiRequestBase(cfgNow), conversation_key: conversationKey, question, ...askExtra },
      });
      statusEl.textContent = resp.truncated ? "Context was truncated to fit the model." : "";
      const thread = document.getElementById("aic-thread");
      if (thread.children.length === 1 && thread.children[0].classList.contains("hint")) thread.innerHTML = "";
      appendTurn(thread, { role: "user", content: question });
      appendTurn(thread, { role: "assistant", content: resp.answer });
      thread.scrollTop = thread.scrollHeight;
      questionEl.value = "";
    } catch (ex) {
      statusEl.textContent = `Error: ${ex.message}`;
    }
  });

  await loadHistory();
}

// Correlation view (cross-machine)
// Shared hit-card renderer for correlation search and IOC scan results.
function renderHitCard(hit) {
  const fields = Object.entries(hit.row).slice(0, 6)
    .map(([k, v]) => `<div class="hit-field"><b>${k}:</b> ${escapeHtml(v)}</div>`).join("");
  const hitEl = el(`
    <div class="hit" title="Click to view full event">
      <div class="hit-table">${hit.machine_label} &middot; ${hit.table_label} &middot; matched on "${hit.matched_column}"</div>
      ${fields}
    </div>
  `);
  hitEl.addEventListener("click", () => showRowDetail(`${hit.machine_label} / ${hit.table_label}`, hit.row, {
    machineId: hit.machine_id, machineLabel: hit.machine_label, table: hit.table, tableLabel: hit.table_label,
  }));
  return hitEl;
}

async function renderCorrelationView() {
  highlightSpecial("correlation");
  const main = document.getElementById("main");
  main.innerHTML = `
    <h2>Correlation</h2>
    <div class="subtitle">Search a term across every imported artifact table, or use a structured query to corroborate evidence across artifacts. Click a result to see the full event.</div>
    <div class="toolbar">
      <div id="corr-search-box" class="query-box-wrap"></div>
      <label style="font-size:12px;color:var(--text-dim);white-space:nowrap"><input type="checkbox" id="corr-cs" style="width:auto"/> case sensitive</label>
      <button class="primary" id="corr-run">Search</button>
    </div>
    <div class="hint query-hint">${queryHintText(true)}</div>
    <div class="form-row">
      <label>Restrict to machines (none checked = search all)</label>
      <div class="chip-box" id="corr-machines">
        ${state.machines.filter((m) => m.status === "ready").map((m) => `<label class="chip"><input type="checkbox" value="${m.id}" style="width:auto"/> ${m.label}</label>`).join("") || `<span class="hint">No ready machines in this case yet.</span>`}
      </div>
    </div>
    <div id="corr-results"></div>
  `;
  const fields = await api(`/cases/${state.currentCase.id}/correlation/fields`);
  const run = async (value) => {
    const q = value !== undefined ? value : qb.getValue();
    if (!q) return;
    const machineIds = Array.from(document.querySelectorAll("#corr-machines input:checked")).map((n) => n.value);
    const resultsEl = document.getElementById("corr-results");
    resultsEl.innerHTML = "<div class='subtitle'>Searching...</div>";
    const result = await api(`/cases/${state.currentCase.id}/correlation/search`, {
      method: "POST",
      body: {
        query: q, case_sensitive: document.getElementById("corr-cs").checked, max_hits_per_table: 200,
        machine_ids: machineIds.length ? machineIds : null,
      },
    });
    const modeLabel = result.structured ? "structured query" : "term";
    resultsEl.innerHTML = `<div class="subtitle">${result.total_hits} hit(s) (${modeLabel}) across ${new Set(result.hits.map(h => h.table)).size} table(s) and ${new Set(result.hits.map(h => h.machine_id)).size} machine(s)</div>`;
    result.hits.slice(0, 500).forEach((hit) => resultsEl.appendChild(renderHitCard(hit)));
  };
  const qb = mountQueryBox(document.getElementById("corr-search-box"), {
    fields, crossTable: true,
    placeholder: "e.g. mimikatz.exe, or amcache.name contains 123.exe and prefetch.executablename contains 123.exe",
    onSearch: run,
  });
  document.getElementById("corr-run").addEventListener("click", () => run());
}

// IOC scan
async function renderIocScanView() {
  highlightSpecial("ioc-scan");
  const main = document.getElementById("main");
  main.innerHTML = `
    <h2>IOC scan</h2>
    <div class="subtitle">Paste a list of indicators (hashes, filenames, domains, IPs, one per line -- "#" for comments) to scan across every artifact table in this case, same idea as Triager CLI's --find-iocs.</div>
    <div class="form-row"><textarea id="ioc-text" style="min-height:140px; font-family:var(--mono); font-size:12px" placeholder="mimikatz.exe&#10;198.51.100.23&#10;# comment lines start with #"></textarea></div>
    <div class="toolbar">
      <label style="font-size:12px;color:var(--text-dim);white-space:nowrap"><input type="checkbox" id="ioc-cs" style="width:auto"/> case sensitive</label>
      <button class="primary" id="ioc-run">Scan</button>
    </div>
    <div class="form-row">
      <label>Restrict to machines (none checked = scan all)</label>
      <div class="chip-box" id="ioc-machines">
        ${state.machines.filter((m) => m.status === "ready").map((m) => `<label class="chip"><input type="checkbox" value="${m.id}" style="width:auto"/> ${m.label}</label>`).join("") || `<span class="hint">No ready machines in this case yet.</span>`}
      </div>
    </div>
    <div id="ioc-results"></div>
  `;
  document.getElementById("ioc-run").addEventListener("click", async () => {
    const iocsText = document.getElementById("ioc-text").value;
    if (!iocsText.trim()) return;
    const machineIds = Array.from(document.querySelectorAll("#ioc-machines input:checked")).map((n) => n.value);
    const resultsEl = document.getElementById("ioc-results");
    resultsEl.innerHTML = "<div class='subtitle'>Scanning...</div>";
    try {
      const result = await api(`/cases/${state.currentCase.id}/ioc-scan`, {
        method: "POST",
        body: {
          iocs_text: iocsText, case_sensitive: document.getElementById("ioc-cs").checked,
          machine_ids: machineIds.length ? machineIds : null, max_hits_per_ioc: 200,
        },
      });
      resultsEl.innerHTML = `<div class="subtitle">${result.matched_iocs} of ${result.scanned_iocs} indicator(s) matched something</div>`;
      if (result.groups.length === 0) {
        resultsEl.appendChild(el(`<div class="empty-state">No matches.</div>`));
        return;
      }
      result.groups.forEach((group) => {
        const groupEl = el(`
          <div class="ioc-group">
            <div class="ioc-group-head" data-open="false">
              <span class="ioc-group-toggle">&#9656;</span>
              <span class="ioc-group-term">${escapeHtml(group.ioc)}</span>
              <span class="ioc-group-count">${group.total_hits} hit(s)</span>
            </div>
            <div class="ioc-group-body" style="display:none"></div>
          </div>
        `);
        const body = groupEl.querySelector(".ioc-group-body");
        group.hits.forEach((hit) => body.appendChild(renderHitCard(hit)));
        const head = groupEl.querySelector(".ioc-group-head");
        head.addEventListener("click", () => {
          const isOpen = head.dataset.open === "true";
          head.dataset.open = isOpen ? "false" : "true";
          body.style.display = isOpen ? "none" : "block";
          head.querySelector(".ioc-group-toggle").innerHTML = isOpen ? "&#9656;" : "&#9662;";
        });
        resultsEl.appendChild(groupEl);
      });
    } catch (ex) {
      resultsEl.innerHTML = `<div class="hint">Error: ${ex.message}</div>`;
    }
  });
}

// Timeline
async function renderTimelineView() {
  highlightSpecial("timeline");
  const main = document.getElementById("main");
  main.innerHTML = `<h2>Timeline</h2><div class="subtitle">Loading...</div>`;

  const sources = await api(`/cases/${state.currentCase.id}/timeline/sources`);
  const readyMachines = state.machines.filter((m) => m.status === "ready");

  main.innerHTML = `
    <h2>Timeline</h2>
    <div class="subtitle">Every detected timestamp column across every artifact table (and machine) merged into one chronological stream. Click an entry to see the full event.</div>
    <div class="toolbar">
      <div id="tl-search-box" class="query-box-wrap"></div>
      <button class="primary" id="tl-run">Apply</button>
    </div>
    <div class="hint query-hint">${queryHintText(true)}</div>
    <div class="toolbar">
      <label style="font-size:12px;color:var(--text-dim)">From <input type="datetime-local" id="tl-start" /></label>
      <label style="font-size:12px;color:var(--text-dim)">To <input type="datetime-local" id="tl-end" /></label>
    </div>
    <div class="form-row">
      <label>Machines (none checked = all)</label>
      <div class="chip-box" id="tl-machines">
        ${readyMachines.map((m) => `<label class="chip"><input type="checkbox" value="${m.id}" style="width:auto"/> ${m.label}</label>`).join("") || `<span class="hint">No ready machines in this case yet.</span>`}
      </div>
    </div>
    <div class="form-row">
      <label>Categories (none checked = all)</label>
      <div class="chip-box" id="tl-categories">
        ${sources.map((s) => `<label class="chip"><input type="checkbox" value="${s.key}" style="width:auto"/> ${s.label}</label>`).join("") || `<span class="hint">No timestamped artifacts detected yet.</span>`}
      </div>
    </div>
    <div id="tl-results"></div>
  `;

  let currentPage = 1;
  const pageSize = 150;
  const tlFields = await api(`/cases/${state.currentCase.id}/timeline/fields`);
  const qb = mountQueryBox(document.getElementById("tl-search-box"), {
    fields: tlFields, crossTable: true,
    placeholder: "Filter by any column, or artifact.column contains value and artifact2.column2 = value2...",
    onSearch: () => run(1),
  });

  const run = async (page = 1) => {
    currentPage = page;
    const machineIds = Array.from(document.querySelectorAll("#tl-machines input:checked")).map((n) => n.value);
    const categories = Array.from(document.querySelectorAll("#tl-categories input:checked")).map((n) => n.value);
    const startVal = document.getElementById("tl-start").value;
    const endVal = document.getElementById("tl-end").value;
    const resultsEl = document.getElementById("tl-results");
    resultsEl.innerHTML = "<div class='subtitle'>Loading...</div>";

    const result = await api(`/cases/${state.currentCase.id}/timeline/query`, {
      method: "POST",
      body: {
        machine_ids: machineIds.length ? machineIds : null,
        categories: categories.length ? categories : null,
        query: qb.getValue() || null,
        start: startVal ? new Date(startVal).toISOString() : null,
        end: endVal ? new Date(endVal).toISOString() : null,
        page, page_size: pageSize,
      },
    });

    if (result.sources_used === 0) {
      resultsEl.innerHTML = `<div class="empty-state">No timestamped artifacts detected for this case yet. Timeline sources are found automatically as machines are ingested.</div>`;
      return;
    }

    resultsEl.innerHTML = `
      <div class="subtitle">~${result.approx_total.toLocaleString()} matching event(s) across ${result.sources_used} source(s) &middot; page ${result.page}</div>
      <div class="table-scroll">
        <table class="data-table" id="tl-table">
          <thead><tr><th>Timestamp (UTC)</th><th>Machine</th><th>Category</th><th>Artifact</th><th>Column</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
      <div class="pager">
        <button id="tl-prev" ${result.page <= 1 ? "disabled" : ""}>&larr; Prev</button>
        <span>Page ${result.page}</span>
        <button id="tl-next" ${result.entries.length < pageSize ? "disabled" : ""}>Next &rarr;</button>
      </div>
    `;
    const tbody = document.querySelector("#tl-table tbody");
    result.entries.forEach((entry) => {
      const tr = el(`
        <tr style="cursor:pointer">
          <td>${entry.timestamp.replace("T", " ").replace(/\.\d+Z?$/, "").replace("Z", "")}</td>
          <td>${entry.machine_label}</td>
          <td>${entry.category_label}</td>
          <td>${entry.table_label}</td>
          <td>${entry.timestamp_column}</td>
        </tr>
      `);
      tr.addEventListener("click", () => showRowDetail(`${entry.machine_label} / ${entry.table_label}`, entry.row, {
        machineId: entry.machine_id, machineLabel: entry.machine_label, table: entry.table, tableLabel: entry.table_label,
      }));
      tbody.appendChild(tr);
    });
    document.getElementById("tl-prev").addEventListener("click", () => run(currentPage - 1));
    document.getElementById("tl-next").addEventListener("click", () => run(currentPage + 1));
  };

  document.getElementById("tl-run").addEventListener("click", () => run(1));
  run(1);
}

// AI view (broad, case/machine-wide)
const DFIR_PROMPT_TEMPLATES = [
  {
    label: "Executive summary",
    question: "Based on the artifact data provided, write an executive summary of this case for a non-technical stakeholder: what happened, when, on which host(s)/user(s), and how confident are you in each claim.",
  },
  {
    label: "Timeline of activity",
    question: "Build a chronological timeline of the most significant events across the provided artifacts (execution, persistence, file system, logon activity). For each entry give a timestamp, the source machine/artifact/table, and a one-line description. Flag any timestamp gaps or inconsistencies (e.g. anti-forensic timestomping indicators).",
  },
  {
    label: "Persistence mechanisms",
    question: "Identify any persistence mechanisms present in the data (scheduled tasks, run keys, WMI subscriptions, services, startup items). For each, state the machine and artifact it came from, why it's suspicious or benign, and a recommended next step to validate it.",
  },
  {
    label: "Evidence of execution",
    question: "Summarize evidence of program execution (Prefetch, Amcache, Shimcache, BAM/DAM, UserAssist, SRUM). Highlight any executables run from unusual locations (Temp, Downloads, AppData, public folders) or with suspicious names, and cross-reference execution times across these artifacts where possible.",
  },
  {
    label: "Lateral movement / remote access",
    question: "Look for indicators of lateral movement or remote access across machines: RDP cache, event logs related to logons, PsExec/WMI/WinRM traces, or unusual authentication patterns. If multiple machines are present, note any activity that appears to hop between them. Summarize what you find and what's still unconfirmed.",
  },
  {
    label: "User activity summary",
    question: "Summarize user activity relevant to this investigation: browser history, recent documents, typed paths, run history, and PowerShell history. Focus on anything indicating data staging, exfiltration, or intentional evidence destruction.",
  },
  {
    label: "IOC extraction",
    question: "Extract a list of indicators of compromise visible in the data: file paths, file names, hashes, IPs, domains/URLs, and usernames that look attacker-controlled or anomalous. Present as a flat list grouped by IOC type, and note which machine/table each came from.",
  },
  {
    label: "Anti-forensic indicators",
    question: "Look for signs of anti-forensic activity: log clearing, timestomping (MFT/USN vs artifact timestamp mismatches), deleted scheduled tasks, use of tools like sdelete/cipher, or gaps in event log sequence numbers. Report what you find and your confidence level.",
  },
];

async function renderAIView() {
  highlightSpecial("ai");
  const main = document.getElementById("main");
  const readyMachines = state.machines.filter((m) => m.status === "ready");

  main.innerHTML = `
    <h2>AI-assisted analysis</h2>
    <div class="subtitle">Broad, case-wide (or single-machine) analysis, with a persisted conversation per scope. For quick analysis of one artifact table's current view, use the "AI analysis" button on that table instead.</div>
    <div class="panel" style="max-width:760px">
      <div class="form-row">
        <label>Scope</label>
        <select id="ai-scope">
          <option value="">Whole case (all machines)</option>
          ${readyMachines.map((m) => `<option value="${m.id}">${m.label} only</option>`).join("")}
        </select>
      </div>
      <div id="ai-broad-host"></div>
    </div>
  `;

  const mountForScope = (machineId) => {
    const host = document.getElementById("ai-broad-host");
    mountAiConversation(host, {
      conversationKey: machineId ? `broad:${machineId}` : "broad:case",
      askExtra: { machine_id: machineId || null },
      templates: DFIR_PROMPT_TEMPLATES,
    });
  };

  document.getElementById("ai-scope").addEventListener("change", (e) => mountForScope(e.target.value || null));
  mountForScope(null);
}

function highlightSpecial(action) {
  highlightActive();
  const node = document.querySelector(`.sidebar .special[data-action="${action}"]`);
  if (node) node.classList.add("active");
}

// AI Settings (top-level, centralized)
async function renderAiSettingsView() {
  document.getElementById("sidebar").style.display = "none";
  const main = document.getElementById("main");
  const cfg = loadAiConfig();
  const provider = cfg.provider || "custom";
  let defaults = { endpoint: "", model: "" };
  try { defaults = await api("/ai/defaults"); } catch (_) {}

  main.innerHTML = `
    <h2>AI Settings</h2>
    <div class="subtitle">Nothing is sent anywhere until you click "AI analysis".</div>
    <div class="panel" style="max-width:520px">
      <div class="form-row">
        <label>Provider</label>
        <select id="settings-provider">
          <option value="claude" ${provider === "claude" ? "selected" : ""}>Claude (Anthropic API)</option>
          <option value="custom" ${provider === "custom" ? "selected" : ""}>Local / custom endpoint (Ollama, vLLM, LM Studio, OpenAI-compatible)</option>
        </select>
      </div>
      <div class="form-row" id="row-endpoint" style="display:${provider === "claude" ? "none" : "block"}">
        <label>LLM base URL or endpoint</label>
        <input id="settings-endpoint" type="text" value="${cfg.endpoint || defaults.endpoint || ""}" placeholder="http://localhost:11434/v1" />
        <div class="hint">Either a base URL (like an OpenAI client's base_url) or the full .../chat/completions URL.</div>
      </div>
      <div class="form-row">
        <label>Model</label>
        <input id="settings-model" type="text" value="${cfg.model || ""}" placeholder="${provider === "claude" ? "e.g. claude-sonnet-5" : defaults.model || "model name"}" />
      </div>
      <div class="form-row">
        <label id="key-label">${provider === "claude" ? "Anthropic API key" : "API key (optional, leave blank for local endpoints)"}</label>
        <input id="settings-key" type="password" value="${cfg.apiKey || ""}" />
      </div>
      <div class="form-row">
        <label>Max tokens (optional)</label>
        <input id="settings-max-tokens" type="number" min="1" value="${cfg.maxTokens || ""}" placeholder="model default" />
      </div>
      <button class="primary" id="settings-save">Save</button>
      <div class="hint" id="settings-status"></div>
    </div>
    <div class="hint" style="margin-top:10px; max-width:520px">Stored only in this browser (localStorage), never sent to the Triager Web backend except at the moment you ask a question, as part of that one request to Anthropic or your chosen endpoint.</div>
  `;

  document.getElementById("settings-provider").addEventListener("change", (e) => {
    const isClaude = e.target.value === "claude";
    document.getElementById("row-endpoint").style.display = isClaude ? "none" : "block";
    document.getElementById("key-label").textContent = isClaude ? "Anthropic API key" : "API key (optional, leave blank for local endpoints)";
    document.getElementById("settings-model").placeholder = isClaude ? "e.g. claude-sonnet-5" : (defaults.model || "model name");
  });

  document.getElementById("settings-save").addEventListener("click", () => {
    const providerNow = document.getElementById("settings-provider").value;
    saveAiConfig({
      provider: providerNow,
      endpoint: providerNow === "claude" ? "" : document.getElementById("settings-endpoint").value.trim(),
      model: document.getElementById("settings-model").value.trim(),
      apiKey: document.getElementById("settings-key").value.trim(),
      maxTokens: document.getElementById("settings-max-tokens").value.trim(),
    });
    document.getElementById("settings-status").textContent = "Saved.";
  });
}

// Ingest wizard (per machine)
async function renderIngestWizard() {
  const main = document.getElementById("main");
  if (isReadOnly()) {
    main.innerHTML = `
      <div class="breadcrumb"><a href="#" id="bc-machines">Machines</a> / ${state.currentMachine.label}</div>
      <h2>${state.currentMachine.label}</h2>
      <div class="empty-state">This machine has no evidence uploaded yet. Read-only access can't upload or start ingestion.</div>
    `;
    document.getElementById("bc-machines").addEventListener("click", (e) => { e.preventDefault(); state.currentMachine = null; renderCaseSidebar(); renderMachinesView(); });
    return;
  }
  const customConfigs = await api("/configs");
  main.innerHTML = `
    <div class="breadcrumb"><a href="#" id="bc-machines">Machines</a> / ${state.currentMachine.label}</div>
    <h2>Ingest evidence -- ${state.currentMachine.label}</h2>
    <div class="subtitle">Upload either a raw evidence collection (Triager will run against it) or a ZIP of already-processed Triager CSV output, for this one machine.</div>
    ${state.currentMachine.status === "error" ? `<div class="panel" style="border-left-color:var(--danger); max-width:560px; margin-bottom:14px"><b style="color:var(--danger)">Previous attempt failed:</b> ${escapeHtml(state.currentMachine.error_message || "unknown error")}</div>` : ""}
    <div class="panel" style="max-width:560px">
      <div class="form-row">
        <label>What are you uploading?</label>
        <select id="ing-kind">
          <option value="evidence">Raw evidence collection (needs Triager run)</option>
          <option value="processed">Already-processed Triager output (CSV artifacts)</option>
        </select>
      </div>
      <div class="form-row" id="profile-row">
        <label>Triage collection profile</label>
        <select id="ing-profile">
          <option value="velociraptor">Velociraptor</option>
          <option value="aralez">Aralez</option>
          ${customConfigs.map((c) => `<option value="custom:${c.id}">Custom: ${escapeHtml(c.name)}</option>`).join("")}
          <option value="__custom_new__">Custom config -- upload a new .yml file</option>
        </select>
      </div>
      <div class="form-row" id="custom-config-row" style="display:none">
        <label>Config name</label>
        <input id="ing-custom-name" type="text" placeholder="e.g. Aralez v2 layout" />
        <label style="margin-top:8px">Config .yml file</label>
        <input id="ing-custom-file" type="file" accept=".yml,.yaml" />
        <div class="hint">Saved after this upload -- reusable for future ingests without uploading it again. Every path in it must stay relative to the triage root (no ".." or absolute paths).</div>
      </div>
      <div class="form-row">
        <label>ZIP file</label>
        <input id="ing-file" type="file" accept=".zip" />
      </div>
      <div class="hint" id="upload-progress"></div>
      <button class="primary" id="ing-start">Upload &amp; start</button>
    </div>
  `;
  document.getElementById("bc-machines").addEventListener("click", (e) => { e.preventDefault(); state.currentMachine = null; renderCaseSidebar(); renderMachinesView(); });

  document.getElementById("ing-kind").addEventListener("change", (e) => {
    document.getElementById("profile-row").style.display = e.target.value === "evidence" ? "block" : "none";
    if (e.target.value !== "evidence") document.getElementById("custom-config-row").style.display = "none";
    else updateCustomConfigRow();
  });
  document.getElementById("ing-profile").addEventListener("change", updateCustomConfigRow);
  function updateCustomConfigRow() {
    document.getElementById("custom-config-row").style.display =
      document.getElementById("ing-profile").value === "__custom_new__" ? "block" : "none";
  }

  document.getElementById("ing-start").addEventListener("click", startIngest);
}

async function startIngest() {
  const fileInput = document.getElementById("ing-file");
  const file = fileInput.files[0];
  if (!file) { alert("Choose a .zip file first"); return; }
  const kind = document.getElementById("ing-kind").value;
  const profile = document.getElementById("ing-profile").value;
  const progressEl = document.getElementById("upload-progress");
  const machineId = state.currentMachine.id;

  let triageProfile = null;
  let customConfigId = null;

  if (kind === "evidence") {
    if (profile === "__custom_new__") {
      const configFile = document.getElementById("ing-custom-file").files[0];
      const configName = document.getElementById("ing-custom-name").value.trim();
      if (!configFile) { alert("Choose a .yml config file first"); return; }
      if (!configName) { alert("Give the config a name so you can find it again next time"); return; }
      progressEl.textContent = "Uploading config...";
      const cfgForm = new FormData();
      cfgForm.append("name", configName);
      cfgForm.append("file", configFile);
      try {
        const saved = await api("/configs", { method: "POST", body: cfgForm });
        customConfigId = saved.id;
      } catch (ex) {
        progressEl.textContent = `Config upload failed: ${ex.message}`;
        return;
      }
    } else if (profile.startsWith("custom:")) {
      customConfigId = profile.slice("custom:".length);
    } else {
      triageProfile = profile;
    }
  }

  const form = new FormData();
  form.append("file", file);

  const xhr = new XMLHttpRequest();
  xhr.open("POST", `/cases/${state.currentCase.id}/machines/${machineId}/upload`);
  xhr.setRequestHeader("Authorization", `Bearer ${state.token}`);
  xhr.upload.addEventListener("progress", (e) => {
    if (e.lengthComputable) {
      const pct = Math.round((e.loaded / e.total) * 100);
      progressEl.textContent = `Uploading... ${pct}% (${fmtBytes(e.loaded)} / ${fmtBytes(e.total)})`;
    }
  });
  xhr.onload = async () => {
    if (xhr.status !== 200) {
      progressEl.textContent = `Upload failed: ${xhr.responseText}`;
      return;
    }
    const uploadResp = JSON.parse(xhr.responseText);
    progressEl.textContent = "Upload complete. Starting ingest pipeline...";
    try {
      await api(`/cases/${state.currentCase.id}/machines/${machineId}/ingest`, {
        method: "POST",
        body: {
          upload_id: uploadResp.upload_id,
          source_kind: kind,
          triage_profile: triageProfile,
          custom_config_id: customConfigId,
          workers: 0,
        },
      });
      await openMachine(machineId);
    } catch (ex) {
      progressEl.textContent = `Failed to start ingest: ${ex.message}`;
    }
  };
  xhr.onerror = () => { progressEl.textContent = "Upload failed (network error)."; };
  progressEl.textContent = "Uploading...";
  xhr.send(form);
}

// Jobs / progress (per machine)
async function renderIngestProgress() {
  state.openLogJobId = null;
  const main = document.getElementById("main");
  main.innerHTML = `
    <div class="breadcrumb"><a href="#" id="bc-machines">Machines</a> / ${state.currentMachine.label}</div>
    <h2>Ingest jobs -- ${state.currentMachine.label}</h2>
    <div id="partial-artifacts-panel"></div>
    <div id="jobs-list"></div>
  `;
  document.getElementById("bc-machines").addEventListener("click", (e) => { e.preventDefault(); state.currentMachine = null; renderCaseSidebar(); renderMachinesView(); });
  clearInterval(state.jobPollTimer);
  renderPartialArtifactsPanel();
  await refreshJobs();
  state.jobPollTimer = setInterval(refreshJobs, 3000);
}

// Shows a "browse what's already imported" link while ingest is still in
// progress, Triager's own parsers finish (and get incrementally
// imported) well before the whole run exits, so there's often real,
// browsable data available long before "ready".
function renderPartialArtifactsPanel() {
  const panel = document.getElementById("partial-artifacts-panel");
  if (!panel) return;
  const tableCount = state.categories.reduce((sum, c) => sum + c.tables.length, 0);
  if (tableCount === 0) {
    panel.innerHTML = "";
    return;
  }
  panel.innerHTML = `
    <div class="panel" style="margin-bottom:14px; border-left-color: var(--accent)">
      <b>${tableCount} artifact table(s) already imported</b> -- ingest is still running, but you can start
      reviewing what's already done.
      <button class="primary" id="browse-partial-btn" style="margin-left:10px">Browse now</button>
    </div>
  `;
  document.getElementById("browse-partial-btn").addEventListener("click", () => renderMachineOverview());
}

async function refreshJobs() {
  if (!state.currentMachine) { clearInterval(state.jobPollTimer); return; }
  const jobsList = document.getElementById("jobs-list");
  if (!jobsList) { clearInterval(state.jobPollTimer); return; }

  // Guard against overlapping ticks: if a fetch takes close to the poll
  // interval (slow connection, a busy case database mid-import), setInterval
  // doesn't wait for the previous async call to finish, without this,
  // two overlapping invocations could each independently see "all done" and
  // each append their own completion banner, since nothing here ever
  // removes a banner that's already there.
  if (state.jobsRefreshInFlight) return;
  state.jobsRefreshInFlight = true;

  try {
    const machineId = state.currentMachine.id;
    const jobs = await api(`/cases/${state.currentCase.id}/machines/${machineId}/jobs`);

    // Bail if the investigator navigated elsewhere while this was in flight.
    if (!document.getElementById("jobs-list") || !state.currentMachine || state.currentMachine.id !== machineId) {
      return;
    }

    if (state.currentMachine.status === "ingesting") {
      try {
        const previousTableCount = state.categories.reduce((sum, c) => sum + c.tables.length, 0);
        state.categories = await api(`/cases/${state.currentCase.id}/machines/${machineId}/artifacts/categories`);
        const newTableCount = state.categories.reduce((sum, c) => sum + c.tables.length, 0);
        if (newTableCount !== previousTableCount) {
          renderCaseSidebar();
          renderPartialArtifactsPanel();
        }
      } catch (_) {
        // Non-critical, job status/log polling below still proceeds either way.
      }
    }

    jobsList.innerHTML = "";
    // Show oldest-first so the pipeline reads top-to-bottom (extract -> triager -> import).
    jobs.slice().reverse().forEach((job) => {
      const isOpen = state.openLogJobId === job.id;
      const row = el(`
        <div class="job-row">
          <div class="job-type">${job.job_type}</div>
          <span class="status-pill ${job.status}">${job.status}</span>
          <div class="progress-bar"><div class="fill" style="width:${job.progress_pct || 0}%"></div></div>
          <div class="job-msg">${job.message || ""}</div>
          <button data-job="${job.id}" class="view-log">${isOpen ? "hide log" : "log"}</button>
        </div>
      `);
      row.querySelector(".view-log").addEventListener("click", () => showJobLog(job.id));
      jobsList.appendChild(row);
      if (isOpen) {
        // Re-render (not just re-append) with freshly fetched content on
        // every poll tick, so a log left open during a long-running ingest
        // stays visible AND keeps live-updating instead of freezing on
        // whatever it showed the moment it was opened.
        renderJobLogPanel(job.id, jobsList);
      }
    });

    const existingBanner = document.getElementById("ingest-outcome-banner");
    if (existingBanner) existingBanner.remove();

    const allDone = jobs.length > 0 && jobs.every((j) => j.status === "success" || j.status === "failed");
    if (!allDone) return;

    // Stop polling the instant we know we're done, everything after this
    // point is one-time "show the outcome" work, not something that should
    // ever run twice for the same completed ingest.
    clearInterval(state.jobPollTimer);

    const m = await api(`/cases/${state.currentCase.id}/machines/${machineId}`);
    if (!document.getElementById("jobs-list") || !state.currentMachine || state.currentMachine.id !== machineId) {
      return;
    }
    state.currentMachine = m;
    const idx = state.machines.findIndex((mm) => mm.id === machineId);
    if (idx >= 0) state.machines[idx] = m;

    if (m.status === "ready") {
      const banner = el(`<div class="panel" id="ingest-outcome-banner" style="margin-top:12px"><button class="primary" id="go-browse">Ingest complete -- view artifacts &rarr;</button></div>`);
      banner.querySelector("#go-browse").addEventListener("click", () => openMachine(m.id));
      jobsList.parentElement.appendChild(banner);
    } else if (m.status === "error") {
      const banner = el(`<div class="panel" id="ingest-outcome-banner" style="margin-top:12px; border-left-color:var(--danger)"><b style="color:var(--danger)">Ingest failed:</b> ${escapeHtml(m.error_message || "unknown error")} <button id="go-retry" style="margin-left:10px">Try again</button></div>`);
      banner.querySelector("#go-retry").addEventListener("click", () => openMachine(m.id));
      jobsList.parentElement.appendChild(banner);
    }
  } finally {
    state.jobsRefreshInFlight = false;
  }
}

async function showJobLog(jobId) {
  if (state.openLogJobId === jobId) {
    // Toggle closed.
    state.openLogJobId = null;
    const existing = document.getElementById(`log-${jobId}`);
    if (existing) existing.remove();
    // Refresh the row's button label immediately rather than waiting for
    // the next poll tick.
    const btn = document.querySelector(`.view-log[data-job="${jobId}"]`);
    if (btn) btn.textContent = "log";
    return;
  }
  // Only one log panel open at a time, close whatever was open before.
  if (state.openLogJobId) {
    const prevExisting = document.getElementById(`log-${state.openLogJobId}`);
    if (prevExisting) prevExisting.remove();
    const prevBtn = document.querySelector(`.view-log[data-job="${state.openLogJobId}"]`);
    if (prevBtn) prevBtn.textContent = "log";
  }
  state.openLogJobId = jobId;
  const btn = document.querySelector(`.view-log[data-job="${jobId}"]`);
  if (btn) btn.textContent = "hide log";
  const jobsList = document.getElementById("jobs-list");
  if (jobsList) await renderJobLogPanel(jobId, jobsList);
}

// Fetches and (re-)renders one job's log <pre> block, replacing any
// previous instance of it. Used both by the initial "log" button click and
// by refreshJobs()'s poll tick, so a log left open during a long-running
// ingest stays open AND keeps showing live content instead of freezing or
// disappearing on the next refresh.
async function renderJobLogPanel(jobId, jobsList) {
  const log = await api(`/jobs/${jobId}/log`);
  const existing = document.getElementById(`log-${jobId}`);
  if (existing) existing.remove();
  // The investigator may have closed it (or opened a different one) while
  // this fetch was in flight.
  if (state.openLogJobId !== jobId) return;
  const pre = el(`<pre class="log-view" id="log-${jobId}"></pre>`);
  pre.textContent = log;
  jobsList.appendChild(pre);
}

// Case members
// Findings
async function renderFindingsView() {
  highlightSpecial("findings");
  const main = document.getElementById("main");
  main.innerHTML = `<h2>Findings</h2><div class="subtitle">Loading...</div>`;
  const findings = await api(`/cases/${state.currentCase.id}/findings`);

  main.innerHTML = `
    <h2>Findings</h2>
    <div class="subtitle">Your own flagged conclusions, independent of AI -- the actual analytical work product of this case. ${findings.length} finding(s).</div>
    <div id="findings-list"></div>
  `;
  const list = document.getElementById("findings-list");
  if (findings.length === 0) {
    list.appendChild(el(`<div class="empty-state">No findings flagged yet. Open any event's detail view (from a table, correlation, IOC scan, or the timeline) to flag one.</div>`));
    return;
  }

  findings.forEach((f) => {
    const source = f.machine_label && f.table_label ? `${f.machine_label} / ${f.table_label}` : (f.table_label || "");
    const card = el(`
      <div class="hit finding-card">
        <div class="hit-table">${source} &middot; flagged by ${f.created_by_username || "unknown"} &middot; ${f.created_at.replace("T", " ").replace(/\.\d+Z?$/, "").replace("Z", "")}</div>
        <div class="finding-note">${escapeHtml(f.note)}</div>
        <div class="ai-turn-actions">
          ${f.row_snapshot ? `<button class="finding-view-event">View flagged event</button>` : ""}
          ${isReadOnly() ? "" : `<button class="finding-edit">Edit note</button>`}
          ${isReadOnly() ? "" : `<button class="danger finding-delete">Delete</button>`}
        </div>
      </div>
    `);
    if (f.row_snapshot) {
      card.querySelector(".finding-view-event").addEventListener("click", () => showRowDetail(source || "Flagged event", f.row_snapshot));
    }
    const editBtn = card.querySelector(".finding-edit");
    if (editBtn) editBtn.addEventListener("click", () => {
      const newNote = prompt("Edit finding note:", f.note);
      if (newNote === null || newNote.trim() === "") return;
      api(`/cases/${state.currentCase.id}/findings/${f.id}`, { method: "PATCH", body: { note: newNote.trim() } })
        .then(() => renderFindingsView());
    });
    const deleteBtn = card.querySelector(".finding-delete");
    if (deleteBtn) deleteBtn.addEventListener("click", async () => {
      if (!confirm("Delete this finding?")) return;
      await api(`/cases/${state.currentCase.id}/findings/${f.id}`, { method: "DELETE" });
      renderFindingsView();
    });
    list.appendChild(card);
  });
}

// Audit log
function renderAuditTable(events) {
  if (events.length === 0) {
    return `<div class="empty-state">No recorded activity yet.</div>`;
  }
  return `
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>When (UTC)</th><th>Who</th><th>Action</th><th>Target</th><th>Details</th></tr></thead>
        <tbody>${events.map((e) => `
          <tr>
            <td>${e.created_at.replace("T", " ").replace(/\.\d+Z?$/, "").replace("Z", "")}</td>
            <td>${e.username || "system"}</td>
            <td>${e.action}</td>
            <td>${e.target_label || e.target_id || ""}</td>
            <td>${e.details ? escapeHtml(JSON.stringify(e.details)) : ""}</td>
          </tr>
        `).join("")}</tbody>
      </table>
    </div>
  `;
}

async function renderCaseAuditView() {
  highlightSpecial("audit");
  const main = document.getElementById("main");
  main.innerHTML = `<h2>Audit log</h2><div class="subtitle">Loading...</div>`;
  const events = await api(`/cases/${state.currentCase.id}/audit`);
  main.innerHTML = `
    <h2>Audit log</h2>
    <div class="subtitle">Everything recorded against this case: ingests, exports, membership changes, AI questions asked, deletions. Newest first.</div>
    ${renderAuditTable(events)}
  `;
}

async function renderGlobalAuditView() {
  document.getElementById("sidebar").style.display = "none";
  const main = document.getElementById("main");
  main.innerHTML = `<h2>Audit log (all cases)</h2><div class="subtitle">Loading...</div>`;
  const events = await api("/audit");
  main.innerHTML = `
    <h2>Audit log (all cases)</h2>
    <div class="subtitle">System-wide feed: logins, user management, and every case's activity. Newest first.</div>
    ${renderAuditTable(events)}
  `;
}

// Report
async function renderReportView() {
  highlightSpecial("report");
  const main = document.getElementById("main");
  main.innerHTML = `
    <h2>Generate report</h2>
    <div class="subtitle">Builds a Word document combining case metadata, machine host profiles and artifact summaries, every persisted AI conversation, and this case's activity log.</div>
    <div class="panel" style="max-width:480px">
      <button class="primary" id="report-generate">Generate &amp; download .docx</button>
      <div class="hint" id="report-status"></div>
    </div>
  `;
  document.getElementById("report-generate").addEventListener("click", async () => {
    const statusEl = document.getElementById("report-status");
    statusEl.textContent = "Generating report...";
    try {
      await downloadAuthenticated(
        `/cases/${state.currentCase.id}/report.docx`,
        `${state.currentCase.name.replace(/[^a-zA-Z0-9 _-]/g, "_")}_report.docx`,
      );
      statusEl.textContent = "Downloaded.";
    } catch (ex) {
      statusEl.textContent = `Error: ${ex.message}`;
    }
  });
}

async function renderMembersView() {
  highlightSpecial("members");
  const main = document.getElementById("main");
  main.innerHTML = `
    <h2>Case members</h2>
    <div class="subtitle">Grant investigators access to this case.</div>

    <h3 style="margin-top:4px; font-size:13px; color:var(--text-dim); text-transform:uppercase; letter-spacing:0.08em;">Current members</h3>
    <div class="table-scroll" style="max-width:640px; margin-bottom:20px">
      <table class="data-table" id="members-table">
        <thead><tr><th>Username</th><th>Full name</th><th>Role</th><th>Can edit</th><th></th></tr></thead>
        <tbody id="members-tbody"><tr><td colspan="5">Loading...</td></tr></tbody>
      </table>
    </div>

    ${isReadOnly() ? "" : `
    <h3 style="font-size:13px; color:var(--text-dim); text-transform:uppercase; letter-spacing:0.08em;">Add member</h3>
    <div class="panel" style="max-width:480px; position:relative">
      <div class="form-row" style="position:relative">
        <label>Search by username or name</label>
        <input id="mem-search" type="text" autocomplete="off" placeholder="Start typing a username..." />
        <div id="mem-results" class="search-results"></div>
      </div>
      <div class="hint" id="mem-selected">No user selected yet.</div>
      <div class="form-row"><label><input type="checkbox" id="mem-edit" checked style="width:auto"/> Can edit (upload evidence, manage members)</label></div>
      <button class="primary" id="mem-add" disabled>Add member</button>
      <div class="hint" id="mem-status"></div>
    </div>
    `}
  `;

  let selectedUser = null;

  async function loadMembers() {
    const tbody = document.getElementById("members-tbody");
    const members = await api(`/cases/${state.currentCase.id}/members`);
    if (members.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5">No members yet besides the case creator.</td></tr>`;
      return;
    }
    tbody.innerHTML = members.map((m) => `
      <tr>
        <td>${m.username}</td>
        <td>${m.full_name || ""}</td>
        <td>${m.role}</td>
        <td>${m.can_edit ? "yes" : "read only"}</td>
        <td>${isReadOnly() ? "" : `<button class="danger remove-member-btn" data-user-id="${m.user_id}" data-username="${escapeAttr(m.username)}">Remove</button>`}</td>
      </tr>
    `).join("");
    tbody.querySelectorAll(".remove-member-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!confirm(`Remove ${btn.dataset.username} from this case?`)) return;
        await api(`/cases/${state.currentCase.id}/members/${btn.dataset.userId}`, { method: "DELETE" });
        loadMembers();
      });
    });
  }

  let searchTimer = null;
  if (!isReadOnly()) {
    document.getElementById("mem-search").addEventListener("input", (e) => {
      selectedUser = null;
      document.getElementById("mem-add").disabled = true;
      document.getElementById("mem-selected").textContent = "No user selected yet.";
      clearTimeout(searchTimer);
      const q = e.target.value.trim();
      const resultsEl = document.getElementById("mem-results");
      if (!q) { resultsEl.innerHTML = ""; return; }
      searchTimer = setTimeout(async () => {
        try {
          const results = await api(`/users/search?q=${encodeURIComponent(q)}`);
          if (results.length === 0) {
            resultsEl.innerHTML = `<div class="search-result-empty">No matching users.</div>`;
            return;
          }
          resultsEl.innerHTML = results.map((u) => `
            <div class="search-result-item" data-id="${u.id}" data-username="${escapeAttr(u.username)}">
              <b>${u.username}</b>${u.full_name ? ` <span class="hint">${u.full_name}</span>` : ""}
            </div>
          `).join("");
          resultsEl.querySelectorAll(".search-result-item").forEach((item) => {
            item.addEventListener("click", () => {
              selectedUser = { id: item.dataset.id, username: item.dataset.username };
              document.getElementById("mem-search").value = item.dataset.username;
              document.getElementById("mem-selected").textContent = `Selected: ${item.dataset.username}`;
              document.getElementById("mem-add").disabled = false;
              resultsEl.innerHTML = "";
            });
          });
        } catch (_) {
          resultsEl.innerHTML = "";
        }
      }, 250);
    });

    document.getElementById("mem-add").addEventListener("click", async () => {
      const statusEl = document.getElementById("mem-status");
      if (!selectedUser) {
        statusEl.textContent = "Pick a user from the search results first.";
        return;
      }
      try {
        await api(`/cases/${state.currentCase.id}/members`, {
          method: "POST",
          body: { user_id: selectedUser.id, can_edit: document.getElementById("mem-edit").checked },
        });
        statusEl.textContent = `Added ${selectedUser.username}.`;
        document.getElementById("mem-search").value = "";
        document.getElementById("mem-selected").textContent = "No user selected yet.";
        document.getElementById("mem-add").disabled = true;
        selectedUser = null;
        loadMembers();
      } catch (ex) {
        statusEl.textContent = `Error: ${ex.message}`;
      }
    });
  }

  loadMembers();
}

// Users admin (system-level)
async function renderUsersView() {
  const main = document.getElementById("main");
  document.getElementById("sidebar").style.display = "none";
  main.innerHTML = `<h2>Users</h2><div class="subtitle">Loading...</div>`;
  const users = await api("/users");
  main.innerHTML = `
    <h2>Users</h2>
    <div class="toolbar"><button class="primary" id="new-user-btn">+ New user</button></div>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Username</th><th>Full name</th><th>Role</th><th>Active</th><th>User ID (for case membership)</th><th></th></tr></thead>
        <tbody>${users.map((u) => `
          <tr>
            <td>${u.username}</td><td>${u.full_name || ""}</td><td>${u.role}</td>
            <td>${u.is_active ? "yes" : "no"}</td><td>${u.id}</td>
            <td>
              <button class="edit-user-btn" data-id="${u.id}">Edit</button>
              <button class="danger delete-user-btn" data-id="${u.id}" data-username="${escapeAttr(u.username)}">Delete</button>
            </td>
          </tr>`).join("")}
        </tbody>
      </table>
    </div>
  `;
  document.getElementById("new-user-btn").addEventListener("click", showNewUserForm);
  document.querySelectorAll(".edit-user-btn").forEach((btn) => {
    const u = users.find((x) => x.id === btn.dataset.id);
    btn.addEventListener("click", () => showEditUserForm(u));
  });
  document.querySelectorAll(".delete-user-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!confirm(`Permanently delete user "${btn.dataset.username}"? This removes their case memberships. Case data and audit history are unaffected.`)) return;
      try {
        await api(`/users/${btn.dataset.id}`, { method: "DELETE" });
        renderUsersView();
      } catch (ex) {
        alert(`Error: ${ex.message}`);
      }
    });
  });
}

function showEditUserForm(u) {
  const main = document.getElementById("main");
  main.innerHTML = `
    <h2>Edit user -- ${u.username}</h2>
    <div class="panel" style="max-width:420px">
      <div class="form-row"><label>Full name</label><input id="eu-fullname" type="text" value="${escapeAttr(u.full_name || "")}" /></div>
      <div class="form-row"><label>Email</label><input id="eu-email" type="text" value="${escapeAttr(u.email || "")}" /></div>
      <div class="form-row">
        <label>Role</label>
        <select id="eu-role">
          <option value="investigator" ${u.role === "investigator" ? "selected" : ""}>Investigator</option>
          <option value="lead" ${u.role === "lead" ? "selected" : ""}>Case lead</option>
          <option value="read_only" ${u.role === "read_only" ? "selected" : ""}>Read only</option>
          <option value="admin" ${u.role === "admin" ? "selected" : ""}>Admin</option>
        </select>
      </div>
      <div class="form-row"><label><input type="checkbox" id="eu-active" ${u.is_active ? "checked" : ""} style="width:auto"/> Active</label></div>
      <div class="form-row"><label>Reset password (leave blank to keep current)</label><input id="eu-password" type="password" /></div>
      <button class="primary" id="eu-save">Save</button>
      <button id="eu-cancel">Cancel</button>
      <div class="hint" id="eu-status"></div>
    </div>
  `;
  document.getElementById("eu-cancel").addEventListener("click", renderUsersView);
  document.getElementById("eu-save").addEventListener("click", async () => {
    const statusEl = document.getElementById("eu-status");
    const newPassword = document.getElementById("eu-password").value;
    try {
      await api(`/users/${u.id}`, {
        method: "PATCH",
        body: {
          full_name: document.getElementById("eu-fullname").value.trim(),
          email: document.getElementById("eu-email").value.trim(),
          role: document.getElementById("eu-role").value,
          is_active: document.getElementById("eu-active").checked,
          new_password: newPassword || null,
        },
      });
      renderUsersView();
    } catch (ex) {
      statusEl.textContent = `Error: ${ex.message}`;
    }
  });
}

function showNewUserForm() {
  const main = document.getElementById("main");
  main.innerHTML = `
    <h2>New user</h2>
    <div class="panel" style="max-width:420px">
      <div class="form-row"><label>Username</label><input id="nu-username" type="text" /></div>
      <div class="form-row"><label>Password</label><input id="nu-password" type="password" /></div>
      <div class="form-row"><label>Full name</label><input id="nu-fullname" type="text" /></div>
      <div class="form-row">
        <label>Role</label>
        <select id="nu-role">
          <option value="investigator">Investigator</option>
          <option value="lead">Case lead</option>
          <option value="read_only">Read only</option>
          <option value="admin">Admin</option>
        </select>
      </div>
      <button class="primary" id="nu-create">Create</button>
      <button id="nu-cancel">Cancel</button>
    </div>
  `;
  document.getElementById("nu-cancel").addEventListener("click", renderUsersView);
  document.getElementById("nu-create").addEventListener("click", async () => {
    await api("/users", { method: "POST", body: {
      username: document.getElementById("nu-username").value.trim(),
      password: document.getElementById("nu-password").value,
      full_name: document.getElementById("nu-fullname").value.trim(),
      role: document.getElementById("nu-role").value,
    }});
    renderUsersView();
  });
}

// init
if (state.token) { showApp(); } else { showLogin(); }
