"use strict";
// APKForge workbench front end. Every value from the server (APK strings, file names,
// tool output) is untrusted: it is only ever placed with textContent, never innerHTML.

const TOKEN = (() => {
  const m = location.hash.match(/token=([A-Za-z0-9_-]+)/);
  if (m) {
    sessionStorage.setItem("apkforge-token", m[1]);
    history.replaceState(null, "", location.pathname); // keep the token out of the address bar
  }
  return sessionStorage.getItem("apkforge-token") || "";
})();

// -- tiny DOM helpers -----------------------------------------------------------------

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null && v !== false) node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}
const $ = (id) => document.getElementById(id);

function table(headers, rows) {
  return el("table", {},
    el("thead", {}, el("tr", {}, headers.map((h) => el("th", {}, h)))),
    el("tbody", {}, rows));
}
function kv(pairs) {
  return el("dl", { class: "kv" },
    pairs.filter(([, v]) => v !== undefined && v !== null && v !== "")
      .flatMap(([k, v]) => [el("dt", {}, k), el("dd", { class: "mono" }, v)]));
}
function stat(value, label) { return el("div", { class: "stat" }, el("b", {}, value), el("span", {}, label)); }
function rawJson(obj) {
  return el("details", {}, el("summary", {}, "Raw JSON"), el("pre", {}, JSON.stringify(obj, null, 2)));
}
function list(title, items, cls) {
  if (!items || !items.length) return null;
  return el("details", { open: cls === "error" }, el("summary", {}, `${title} (${items.length})`),
    el("ul", {}, items.map((i) => el("li", { class: cls || "" }, i))));
}

const GOOD = new Set(["SUCCESS", "NO_OP", "COMPLETE", "complete", "DONE", "AVAILABLE", "NONE",
  "NO_SIGNIFICANT_STATIC_FINDINGS", "UNCHANGED"]);
const WARN = new Set(["PARTIAL", "partial", "QUEUED", "RUNNING", "CONTAINER_ONLY", "NOT_CHECKED",
  "INCOMPLETE", "medium", "low", "MEDIUM", "LOW"]);
function badge(value) {
  const v = String(value);
  const cls = GOOD.has(v) ? "ok" : WARN.has(v) ? "warn" : "bad";
  return el("span", { class: `badge ${cls}` }, v);
}

// -- API -----------------------------------------------------------------------------

async function api(path, body) {
  const res = await fetch(path, {
    method: body ? "POST" : "GET",
    headers: { "X-APKForge-Token": TOKEN, ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const d = data.detail;
    throw new Error(typeof d === "string" ? d : JSON.stringify(d || data) || res.statusText);
  }
  return data;
}

async function upload(file) {
  const res = await fetch(`/api/uploads?name=${encodeURIComponent(file.name)}`, {
    method: "POST",
    headers: { "X-APKForge-Token": TOKEN, "Content-Type": "application/octet-stream" },
    body: file,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || res.statusText);
  return data.path;
}

const ACTIVE = new Set(["QUEUED", "RUNNING"]);

// Submit a job, poll it, then render it into `out`. `render` overrides the kind's renderer.
async function runJob(path, body, out, button, render) {
  out.replaceChildren(el("div", { class: "panel" }, badge("QUEUED"), " submitting…"));
  button.disabled = true;
  try {
    let job = await api(path, body);
    while (ACTIVE.has(job.status)) {
      const id = job.id;
      const cancel = el("button", { type: "button", class: "secondary", disabled: job.cancel_requested,
        onclick: async () => { cancel.disabled = true; await api(`/api/jobs/${id}/cancel`, {}).catch(() => {}); },
      }, job.cancel_requested ? "Cancelling…" : "Cancel");
      out.replaceChildren(el("div", { class: "panel" }, badge(job.status), ` job ${job.id} `, cancel,
        el("span", { class: "muted" }, " — analysis of large APKs can take minutes")));
      await new Promise((r) => setTimeout(r, 1000));
      job = await api(`/api/jobs/${job.id}`);
    }
    showJob(job, out, render);
  } catch (e) {
    out.replaceChildren(el("div", { class: "panel error" }, String(e.message || e)));
  } finally {
    button.disabled = false;
  }
}

function downloadButton(job) {
  return el("button", { type: "button", class: "secondary", onclick: () => {
    const blob = new Blob([JSON.stringify(job, null, 2)], { type: "application/json" });
    const a = el("a", { href: URL.createObjectURL(blob), download: `apkforge-${job.kind}-${job.id}.json` });
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  } }, "Download JSON");
}

function showJob(job, out, render) {
  const head = el("div", { class: "toolbar" }, badge(job.status), el("span", { class: "muted mono" }, ` ${job.kind} · ${job.id}`),
    el("span", { class: "spacer" }), downloadButton(job));
  if (job.status === "ERROR") {
    out.replaceChildren(el("div", { class: "panel" }, head, el("h2", {}, "Job failed"),
      el("p", { class: "error" }, job.error), rawJson(job)));
    return;
  }
  const notice = job.status === "CANCELLED"
    ? el("p", { class: "notice" }, "Cancelled. Any result below is what the job produced before it stopped.") : null;
  const body = job.result === null || job.result === undefined ? []
    : (render || RENDER[job.kind] || ((r) => [rawJson(r)]))(job.result);
  out.replaceChildren(el("div", { class: "panel" }, head, notice, body));
}

// -- renderers -----------------------------------------------------------------------

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function renderAnalyze(r) {
  const s = r.security_summary || {};
  const findings = [...(r.security_findings || [])]
    .sort((a, b) => (SEV_ORDER[String(a.severity).toLowerCase()] ?? 9) - (SEV_ORDER[String(b.severity).toLowerCase()] ?? 9));
  return [
    el("h2", {}, r.package_name || "(unknown package)", " ", badge(r.status)),
    kv([["Version", `${r.version_name || "?"} (${r.version_code || "?"})`],
      ["Inspection", r.inspection_status], ["Privacy", r.privacy_status],
      ["Security", r.security_status]]),
    el("div", { class: "stats" },
      stat(r.inspection_summary?.total_files ?? "–", "files"),
      stat(r.inspection_summary?.dex_files ?? "–", "DEX files"),
      stat(r.inspection_summary?.native_libraries ?? "–", "native libs"),
      stat(r.privacy_summary?.declared_permissions ?? "–", "permissions"),
      stat(r.privacy_summary?.detected_sdks ?? "–", "SDKs/trackers"),
      stat(r.privacy_summary?.total_endpoints ?? "–", "endpoints"),
      stat(s.total_findings ?? 0, "findings"),
      stat(`${s.critical_count ?? 0}/${s.high_count ?? 0}/${s.medium_count ?? 0}`, "crit/high/med")),
    findings.length
      ? table(["Severity", "Confidence", "Finding", "Category"], findings.map((f) => el("tr", {},
        el("td", {}, badge(f.severity)), el("td", {}, f.confidence),
        el("td", {}, el("details", {}, el("summary", {}, f.title, " ", el("span", { class: "muted mono" }, f.id)),
          el("p", {}, f.description), f.assessment ? el("p", { class: "muted" }, f.assessment) : null,
          (f.evidence || []).length ? el("pre", {}, JSON.stringify(f.evidence, null, 2)) : null)),
        el("td", {}, f.category))))
      : el("p", { class: "muted" }, "No security findings."),
    el("p", { class: "notice" }, "Static analysis only: neither findings nor their absence prove an APK safe or unsafe."),
    list("Errors", r.errors, "error"), list("Warnings", r.warnings), list("Limitations", r.limitations),
    rawJson(r),
  ];
}

function renderDiff(r) {
  const nonzero = Object.entries(r.summary || {})
    .filter(([k, v]) => typeof v === "number" && v !== 0 && k !== "text_lines");
  const filter = el("input", { type: "text", class: "filter", placeholder: "Filter observations…" });
  const rows = (r.observations || []).map((o) => el("tr", {},
    el("td", {}, o.category), el("td", {}, o.kind), el("td", { class: "mono" }, o.identifier)));
  filter.addEventListener("input", () => {
    const q = filter.value.toLowerCase();
    for (const row of rows) row.hidden = q && !row.textContent.toLowerCase().includes(q);
  });
  return [
    el("h2", {}, "Diff ", badge(r.status)),
    kv([["Original", `${r.apk_a?.package_name || "?"} ${r.apk_a?.version_name || ""} (${r.apk_a?.version_code ?? "?"})`],
      ["Modified", `${r.apk_b?.package_name || "?"} ${r.apk_b?.version_name || ""} (${r.apk_b?.version_code ?? "?"})`],
      ["Certificate", r.summary?.certificate_status]]),
    nonzero.length ? el("div", { class: "stats" }, nonzero.map(([k, v]) => stat(v, k.replaceAll("_", " "))))
      : el("p", { class: "muted" }, "No semantic differences counted."),
    el("h2", {}, `Observations (${rows.length})`),
    filter,
    table(["Category", "Kind", "Identifier"], rows),
    list("Errors", r.errors, "error"), list("Warnings", r.warnings), list("Limitations", r.limitations),
    rawJson(r),
  ];
}

function renderModKitResult(r) {
  return [
    el("h2", {}, `${r.identity?.modkit_id} / ${r.operation} `, badge(r.status)),
    kv([["Reason", r.reason], ["Failure", r.failure], ["Execution", r.execution_id],
      ["Input SHA-256", r.original?.sha256], ["Output", r.published?.path],
      ["Output SHA-256", r.published?.sha256], ["Workspace", r.workspace_path]]),
    (r.declaration?.notes || []).length ? list("ModKit notes (untrusted)", r.declaration.notes) : null,
    (r.validation || []).length ? table(["Validation check", "Result", "Detail"],
      r.validation.map((c) => el("tr", {}, el("td", { class: "mono" }, c.id),
        el("td", {}, badge(c.passed ? "SUCCESS" : "FAILED")), el("td", {}, c.detail)))) : null,
    list("Limitations", r.limitations), rawJson(r),
  ];
}

function renderChain(r) {
  return [
    el("h2", {}, `Chain ${r.chain_id} `, badge(r.status)),
    kv([["Reason", r.reason], ["Output", r.published?.path], ["Output SHA-256", r.published?.sha256],
      ["Chain directory", r.chain_dir]]),
    table(["#", "ModKit", "Operation", "Status", "Output SHA-256"], (r.steps || []).map((s, i) => el("tr", {},
      el("td", {}, i), el("td", {}, s.identity?.modkit_id), el("td", {}, s.operation),
      el("td", {}, badge(s.status), s.reason && s.status !== "SUCCESS" ? el("div", { class: "muted" }, s.reason) : null),
      el("td", { class: "mono" }, s.published?.sha256 || "–")))),
    el("h2", { style: "margin-top:16px" }, "Conflicts ", badge(r.conflict_status)),
    (r.conflicts || []).length ? table(["Category", "Identifier", "Kind", "Steps", "Container"],
      r.conflicts.map((c) => el("tr", {}, el("td", {}, c.category), el("td", { class: "mono" }, c.identifier),
        el("td", {}, badge(c.kind === "reverted" ? "REVERTED" : "OVERLAP")),
        el("td", {}, c.steps.map((s, i) => `${s}:${c.changes[i]}`).join(" → ")),
        el("td", {}, c.container ? "yes" : "")))) : null,
    list("Conflict check gaps", r.conflict_gaps),
    rawJson(r),
  ];
}

const RENDER = { analyze: renderAnalyze, diff: renderDiff, "modkit-run": renderModKitResult,
  "modkit-chain": renderChain, "modkit-patches": (r) => renderPatches(r, null) };

// -- patch bundles (Morphe list_patches) ----------------------------------------------

// `enableInput` (optional): the form's "enable" field the picker fills.
function renderPatches(listing, enableInput) {
  const already = new Set((enableInput?.value || "").split(",").map((n) => n.trim()).filter(Boolean));
  const filter = el("input", { type: "text", class: "filter", placeholder: "Filter patches…" });
  const rows = (listing.patches || []).map((p) => {
    const box = enableInput ? el("input", { type: "checkbox", value: p.name, checked: already.has(p.name) }) : null;
    const compat = (p.compatible || []).map((c) => c.package + ((c.versions || []).length ? ` (${c.versions.join(", ")})` : "")).join("; ");
    return el("tr", {},
      enableInput ? el("td", {}, box) : null,
      el("td", {}, p.index), el("td", {}, p.name, p.description ? el("div", { class: "muted" }, p.description) : null),
      el("td", {}, p.enabled ? "yes" : "no"),
      el("td", {}, compat || el("span", { class: "muted" }, "any app")),
      el("td", { class: "mono" }, (p.options || []).map((o) => `${o.key}${o.required ? "*" : ""}${o.default ? `=${o.default}` : ""}`).join(", ") || "–"));
  });
  filter.addEventListener("input", () => {
    const q = filter.value.toLowerCase();
    for (const row of rows) row.hidden = q && !row.textContent.toLowerCase().includes(q);
  });
  const use = enableInput ? el("button", { type: "button", class: "primary", onclick: () => {
    const names = [...rows].map((r) => r.querySelector("input[type=checkbox]")).filter((b) => b.checked).map((b) => b.value);
    enableInput.value = names.join(", ");
    enableInput.dispatchEvent(new Event("input", { bubbles: true }));
    use.textContent = `Enabled ${names.length} patch(es)`;
  } }, "Use selected as “enable”") : null;
  return [
    el("h2", {}, `${(listing.patches || []).length} patches`, listing.resolved_version ? ` · ${listing.resolved_version}` : ""),
    filter,
    table([enableInput ? "" : null, "#", "Patch", "Default", "Compatible with", "Options (key=default)"].filter((h) => h !== null), rows),
    use,
  ];
}

// -- ModKit parameter forms (run form and chain steps) --------------------------------

let MODKITS = [];
const kitById = (id) => MODKITS.find((k) => k.identity.modkit_id === id);
const runnableKits = () => MODKITS.filter((k) => (k.operations || []).length);

// A form for one operation's ParameterSpecs; `values` prefills it. Returns the node and a
// collect() that yields the non-empty values.
function paramForm(modkitId, op, values, onChange) {
  const box = el("div", {});
  const inputs = {};
  for (const p of op?.parameters || []) {
    const id = `p-${Math.random().toString(36).slice(2)}`;
    let input;
    if (p.choices && p.choices.length) {
      input = el("select", { id }, el("option", { value: "" }, "(default)"), p.choices.map((c) => el("option", { value: c }, c)));
    } else {
      input = el("input", { id, type: p.sensitive ? "password" : "text", required: p.required, autocomplete: "off" });
    }
    input.value = values?.[p.name] ?? "";
    if (onChange) input.addEventListener("input", onChange);
    if (onChange) input.addEventListener("change", onChange);
    inputs[p.name] = input;
    box.append(el("label", { for: id }, p.name, p.required ? " *" : "", p.sensitive ? " (secret)" : "",
      p.description ? el("span", { class: "muted" }, ` — ${p.description}`) : null), input);
    if (p.name === "patches") {
      const out = el("div", {});
      const btn = el("button", { type: "button", class: "secondary", onclick: () => {
        if (!input.value.trim()) { out.replaceChildren(el("p", { class: "error" }, "Enter a patch bundle first.")); return; }
        runJob("/api/jobs/modkit-patches", { modkit: modkitId, patches: input.value.trim() }, out, btn,
          (listing) => renderPatches(listing, inputs.enable));
      } }, "List patches in this bundle");
      box.append(el("div", { class: "toolbar" }, btn), out);
    }
  }
  return { node: box, collect: () => Object.fromEntries(Object.entries(inputs).filter(([, i]) => i.value !== "").map(([k, i]) => [k, i.value])) };
}

function kitOptions(select, selected) {
  select.replaceChildren(...runnableKits().map((k) => el("option", { value: k.identity.modkit_id }, k.identity.modkit_id)));
  if (selected) select.value = selected;
}
function opOptions(select, kit, selected) {
  select.replaceChildren(...(kit?.operations || []).map((o) => el("option", { value: o.id }, o.id)));
  if (selected) select.value = selected;
}

// -- ModKits tab ---------------------------------------------------------------------

let RUN_FORM = null;

function fillRunForm() {
  const kit = kitById($("mk-id").value);
  const op = kit?.operations.find((o) => o.id === $("mk-op").value);
  RUN_FORM = paramForm(kit?.identity.modkit_id, op, {});
  $("mk-params").replaceChildren(RUN_FORM.node);
}

let MODKITS_LOADING = null;
function loadModKits() {
  MODKITS_LOADING ||= (async () => {
    try {
      MODKITS = await api("/api/modkits");
    } catch (e) {
      MODKITS_LOADING = null;
      $("modkit-list").replaceChildren(el("p", { class: "error" }, e.message));
      return;
    }
    $("modkit-list").replaceChildren(MODKITS.length
      ? table(["ID", "Name", "Version", "Status", "Capabilities"], MODKITS.map((k) => el("tr", {},
        el("td", { class: "mono" }, k.identity.modkit_id), el("td", {}, k.identity.display_name),
        el("td", {}, k.identity.installed_version || "–"),
        el("td", {}, badge(k.availability.status), k.availability.reason ? el("div", { class: "muted" }, k.availability.reason) : null),
        el("td", {}, (k.capabilities || []).join(", ") || "–"))))
      : el("p", { class: "muted" }, "No ModKits configured. See docs/modkits.md."));
    kitOptions($("mk-id"));
    opOptions($("mk-op"), kitById($("mk-id").value));
    fillRunForm();
    if (!CHAIN.length && runnableKits().length) addStep();
    renderSteps();
  })();
  return MODKITS_LOADING;
}

// -- Chain tab: step cards (JSON stays available as an advanced view) -----------------

let CHAIN = [];
let CHAIN_JSON = false;

function addStep() {
  const kit = runnableKits()[0];
  CHAIN.push({ modkit: kit?.identity.modkit_id || "", operation: kit?.operations[0]?.id || "", parameters: {}, allow_noop: false });
}

function renderSteps() {
  const box = $("chain-step-list");
  if (CHAIN_JSON) return;
  if (!runnableKits().length) {
    box.replaceChildren(el("p", { class: "muted" }, "No runnable ModKits configured."));
    return;
  }
  box.replaceChildren(...CHAIN.map((step, i) => {
    const kitSel = el("select", {});
    const opSel = el("select", {});
    kitOptions(kitSel, step.modkit);
    const kit = kitById(kitSel.value);
    opOptions(opSel, kit, step.operation);
    step.modkit = kitSel.value;
    step.operation = opSel.value;
    const form = paramForm(step.modkit, kit?.operations.find((o) => o.id === step.operation), step.parameters,
      () => { step.parameters = form.collect(); });
    kitSel.addEventListener("change", () => {
      step.modkit = kitSel.value; step.operation = kitById(kitSel.value)?.operations[0]?.id || ""; step.parameters = {};
      renderSteps();
    });
    opSel.addEventListener("change", () => { step.operation = opSel.value; step.parameters = {}; renderSteps(); });
    const noop = el("input", { type: "checkbox", checked: step.allow_noop, onchange: () => { step.allow_noop = noop.checked; } });
    const move = (d) => { const j = i + d; [CHAIN[i], CHAIN[j]] = [CHAIN[j], CHAIN[i]]; renderSteps(); };
    return el("fieldset", { class: "step" },
      el("legend", {}, `Step ${i}`),
      el("div", { class: "toolbar" },
        el("button", { type: "button", class: "secondary", disabled: i === 0, onclick: () => move(-1), "aria-label": `Move step ${i} up` }, "↑"),
        el("button", { type: "button", class: "secondary", disabled: i === CHAIN.length - 1, onclick: () => move(1), "aria-label": `Move step ${i} down` }, "↓"),
        el("button", { type: "button", class: "secondary", disabled: CHAIN.length === 1,
          onclick: () => { CHAIN.splice(i, 1); renderSteps(); }, "aria-label": `Remove step ${i}` }, "Remove")),
      el("div", { class: "row" }, el("div", {}, el("label", {}, "ModKit"), kitSel), el("div", {}, el("label", {}, "Operation"), opSel)),
      form.node,
      el("label", { class: "check" }, noop, " Accept an unchanged output (NO_OP)"));
  }));
}

function chainSteps() {
  if (!CHAIN_JSON) return CHAIN.map((s) => ({ ...s }));
  return JSON.parse($("chain-steps").value);
}

function toggleChainJson() {
  if (!CHAIN_JSON) {
    $("chain-steps").value = JSON.stringify(CHAIN, null, 2);
  } else {
    try {
      const parsed = JSON.parse($("chain-steps").value);
      if (!Array.isArray(parsed)) throw new Error("expected a JSON array of steps");
      CHAIN = parsed.map((s) => ({ modkit: s.modkit, operation: s.operation, parameters: s.parameters || {}, allow_noop: !!s.allow_noop,
        ...(s.timeout_seconds ? { timeout_seconds: s.timeout_seconds } : {}) }));
    } catch (e) {
      $("out-chain").replaceChildren(el("div", { class: "panel error" }, `Steps are not valid JSON: ${e.message}`));
      return;
    }
  }
  CHAIN_JSON = !CHAIN_JSON;
  $("chain-steps").hidden = !CHAIN_JSON;
  $("chain-step-list").hidden = CHAIN_JSON;
  $("chain-add").hidden = CHAIN_JSON;
  $("chain-json-toggle").textContent = CHAIN_JSON ? "Edit as form" : "Edit as JSON";
  renderSteps();
}

// -- Jobs tab ------------------------------------------------------------------------

async function loadJobs() {
  try {
    const jobs = await api("/api/jobs");
    $("job-list").replaceChildren(jobs.length
      ? table(["Created", "Kind", "Status", "What", ""], jobs.map((j) => el("tr", {
        class: "clickable",
        onclick: async () => showJob(await api(`/api/jobs/${j.id}`), $("out-jobs")),
      }, el("td", { class: "mono" }, j.created), el("td", {}, j.kind), el("td", {}, badge(j.status)),
      el("td", { class: "mono" }, JSON.stringify(j.summary)),
      el("td", {}, ACTIVE.has(j.status) ? el("button", { type: "button", class: "secondary", disabled: j.cancel_requested,
        onclick: async (ev) => { ev.stopPropagation(); await api(`/api/jobs/${j.id}/cancel`, {}).catch(() => {}); loadJobs(); },
      }, j.cancel_requested ? "Cancelling…" : "Cancel") : null))))
      : el("p", { class: "muted" }, "No jobs yet."));
  } catch (e) {
    $("job-list").replaceChildren(el("p", { class: "error" }, e.message));
  }
}

// -- wiring --------------------------------------------------------------------------

function selectTab(name) {
  for (const b of document.querySelectorAll("nav button")) b.setAttribute("aria-selected", b.dataset.tab === name);
  for (const s of document.querySelectorAll("main section")) s.hidden = s.id !== `tab-${name}`;
  if (name === "jobs") loadJobs();
  if (name === "modkits" || name === "chain") loadModKits();
}

function onSubmit(formId, handler) {
  $(formId).addEventListener("submit", (ev) => {
    ev.preventDefault();
    handler(ev.target.querySelector("button[type=submit]"));
  });
}

// An "Upload…" button next to every APK path field: the server stores the file in a
// session-only directory and the field gets that path.
function addUploadButtons() {
  for (const input of document.querySelectorAll("input[data-upload]")) {
    const picker = el("input", { type: "file", accept: ".apk,application/vnd.android.package-archive", hidden: true });
    const status = el("span", { class: "muted" });
    const btn = el("button", { type: "button", class: "secondary", onclick: () => picker.click() }, "Upload…");
    picker.addEventListener("change", async () => {
      const file = picker.files[0];
      if (!file) return;
      btn.disabled = true;
      status.textContent = ` uploading ${file.name}…`;
      try {
        input.value = await upload(file);
        status.textContent = ` uploaded (${(file.size / 1048576).toFixed(1)} MB)`;
      } catch (e) {
        status.textContent = "";
        status.append(el("span", { class: "error" }, ` upload failed: ${e.message}`));
      } finally {
        btn.disabled = false;
        picker.value = "";
      }
    });
    input.after(el("div", { class: "toolbar" }, btn, status, picker));
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  for (const b of document.querySelectorAll("nav button")) b.addEventListener("click", () => selectTab(b.dataset.tab));
  $("mk-id").addEventListener("change", () => { opOptions($("mk-op"), kitById($("mk-id").value)); fillRunForm(); });
  $("mk-op").addEventListener("change", fillRunForm);
  $("chain-add").addEventListener("click", () => { addStep(); renderSteps(); });
  $("chain-json-toggle").addEventListener("click", toggleChainJson);
  addUploadButtons();

  onSubmit("form-analyze", (btn) => runJob("/api/jobs/analyze", { apk: $("analyze-apk").value.trim() }, $("out-analyze"), btn));
  onSubmit("form-diff", (btn) => runJob("/api/jobs/diff",
    { original: $("diff-original").value.trim(), modified: $("diff-modified").value.trim() }, $("out-diff"), btn));
  onSubmit("form-modkit", (btn) => runJob("/api/jobs/modkit-run", {
    modkit: $("mk-id").value, operation: $("mk-op").value, apk: $("mk-apk").value.trim(),
    output_dir: $("mk-out").value.trim(), parameters: RUN_FORM ? RUN_FORM.collect() : {}, allow_noop: $("mk-noop").checked,
  }, $("out-modkit"), btn));
  onSubmit("form-chain", (btn) => {
    let steps;
    try {
      steps = chainSteps();
    } catch (e) {
      $("out-chain").replaceChildren(el("div", { class: "panel error" }, `Steps are not valid JSON: ${e.message}`));
      return;
    }
    runJob("/api/jobs/modkit-chain", { apk: $("chain-apk").value.trim(), output_dir: $("chain-out").value.trim(),
      steps, check_conflicts: $("chain-conflicts").checked }, $("out-chain"), btn);
  });

  if (!TOKEN) {
    $("fatal").replaceChildren(el("div", { class: "panel error" },
      "No access token. Open the URL printed by `apkforge gui` (it ends in #token=…)."));
    return;
  }
  try {
    const h = await api("/api/health");
    $("version").textContent = `v${h.version}`;
  } catch (e) {
    $("fatal").replaceChildren(el("div", { class: "panel error" }, `Server rejected the session: ${e.message}`));
  }
});
