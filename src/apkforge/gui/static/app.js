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

async function runJob(path, body, out, button) {
  out.replaceChildren(el("div", { class: "panel" }, badge("QUEUED"), " submitting…"));
  button.disabled = true;
  try {
    let job = await api(path, body);
    while (job.status === "QUEUED" || job.status === "RUNNING") {
      out.replaceChildren(el("div", { class: "panel" }, badge(job.status), ` job ${job.id}`,
        el("span", { class: "muted" }, " — analysis of large APKs can take minutes")));
      await new Promise((r) => setTimeout(r, 1000));
      job = await api(`/api/jobs/${job.id}`);
    }
    showJob(job, out);
  } catch (e) {
    out.replaceChildren(el("div", { class: "panel error" }, String(e.message || e)));
  } finally {
    button.disabled = false;
  }
}

function showJob(job, out) {
  if (job.status === "ERROR") {
    out.replaceChildren(el("div", { class: "panel" }, el("h2", {}, "Job failed"),
      el("p", { class: "error" }, job.error), rawJson(job)));
    return;
  }
  const render = RENDER[job.kind] || ((r) => [rawJson(r)]);
  out.replaceChildren(el("div", { class: "panel" }, render(job.result)));
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
  "modkit-chain": renderChain };

// -- ModKits tab ---------------------------------------------------------------------

let MODKITS = [];

function renderParams() {
  const kit = MODKITS.find((k) => k.identity.modkit_id === $("mk-id").value);
  const op = kit?.operations.find((o) => o.id === $("mk-op").value);
  const box = $("mk-params");
  box.replaceChildren();
  for (const p of op?.parameters || []) {
    const id = `mk-param-${p.name}`;
    let input;
    if (p.choices && p.choices.length) {
      input = el("select", { id, "data-param": p.name },
        el("option", { value: "" }, "(default)"), p.choices.map((c) => el("option", { value: c }, c)));
    } else {
      input = el("input", { id, "data-param": p.name, type: p.sensitive ? "password" : "text",
        required: p.required, autocomplete: "off" });
    }
    box.append(el("label", { for: id }, p.name, p.required ? " *" : "", p.sensitive ? " (secret)" : "",
      p.description ? el("span", { class: "muted" }, ` — ${p.description}`) : null), input);
  }
}

function fillOperations() {
  const kit = MODKITS.find((k) => k.identity.modkit_id === $("mk-id").value);
  $("mk-op").replaceChildren(...(kit?.operations || []).map((o) => el("option", { value: o.id }, o.id)));
  renderParams();
}

async function loadModKits() {
  try {
    MODKITS = await api("/api/modkits");
  } catch (e) {
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
  const runnable = MODKITS.filter((k) => (k.operations || []).length);
  $("mk-id").replaceChildren(...runnable.map((k) => el("option", { value: k.identity.modkit_id }, k.identity.modkit_id)));
  fillOperations();
}

// -- Jobs tab ------------------------------------------------------------------------

async function loadJobs() {
  try {
    const jobs = await api("/api/jobs");
    $("job-list").replaceChildren(jobs.length
      ? table(["Created", "Kind", "Status", "What"], jobs.map((j) => el("tr", {
        class: "clickable",
        onclick: async () => showJob(await api(`/api/jobs/${j.id}`), $("out-jobs")),
      }, el("td", { class: "mono" }, j.created), el("td", {}, j.kind), el("td", {}, badge(j.status)),
      el("td", { class: "mono" }, JSON.stringify(j.summary)))))
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
  if (name === "modkits" && !MODKITS.length) loadModKits();
}

function onSubmit(formId, handler) {
  $(formId).addEventListener("submit", (ev) => {
    ev.preventDefault();
    handler(ev.target.querySelector("button[type=submit]"));
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  for (const b of document.querySelectorAll("nav button")) b.addEventListener("click", () => selectTab(b.dataset.tab));
  $("mk-id").addEventListener("change", fillOperations);
  $("mk-op").addEventListener("change", renderParams);

  onSubmit("form-analyze", (btn) => runJob("/api/jobs/analyze", { apk: $("analyze-apk").value.trim() }, $("out-analyze"), btn));
  onSubmit("form-diff", (btn) => runJob("/api/jobs/diff",
    { original: $("diff-original").value.trim(), modified: $("diff-modified").value.trim() }, $("out-diff"), btn));
  onSubmit("form-modkit", (btn) => {
    const parameters = {};
    for (const input of $("mk-params").querySelectorAll("[data-param]")) {
      if (input.value !== "") parameters[input.dataset.param] = input.value;
    }
    runJob("/api/jobs/modkit-run", {
      modkit: $("mk-id").value, operation: $("mk-op").value, apk: $("mk-apk").value.trim(),
      output_dir: $("mk-out").value.trim(), parameters, allow_noop: $("mk-noop").checked,
    }, $("out-modkit"), btn);
  });
  onSubmit("form-chain", (btn) => {
    let steps;
    try {
      steps = JSON.parse($("chain-steps").value);
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
