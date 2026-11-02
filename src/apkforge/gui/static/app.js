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
// Pasting a new server's URL into this tab only changes the hash: reload to pick it up.
window.addEventListener("hashchange", () => { if (/token=/.test(location.hash)) location.reload(); });

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
  "NO_SIGNIFICANT_STATIC_FINDINGS", "UNCHANGED", "planned", "verified", "VERIFIED", "PLANNED", "ELIGIBLE",
  "FOUND", "INSTALLED", "PASS", "valid", "satisfied"]);
const WARN = new Set(["PARTIAL", "partial", "QUEUED", "RUNNING", "CONTAINER_ONLY", "NOT_CHECKED",
  "INCOMPLETE", "medium", "low", "MEDIUM", "LOW", "CANCELLED", "CONDITIONALLY_ELIGIBLE",
  "partially_remediated", "VERIFIED_WITH_LIMITATIONS", "NOT_INSTALLED", "SKIPPED", "informational", "INFO"]);
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
    throw new Error(typeof d === "string" ? d : d ? JSON.stringify(d) : `${res.status} ${res.statusText}`);
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

// The output APK of an apply or a ModKit run/chain; the server decides (see _job_output).
function apkButton(job) {
  const hasOutput = job.status === "DONE" && ((job.kind === "apply" && job.summary.output) || job.result?.published?.path);
  if (!hasOutput) return null;
  return el("button", { type: "button", class: "secondary", onclick: async (ev) => {
    ev.target.disabled = true;
    try {
      const { url } = await api(`/api/jobs/${job.id}/download`, {});
      el("a", { href: url }).click();  // single-use ticket; the response is an attachment
    } catch (e) {
      ev.target.replaceWith(el("span", { class: "error" }, e.message));
    } finally {
      ev.target.disabled = false;
    }
  } }, "Download APK");
}

function showJob(job, out, render) {
  const head = el("div", { class: "toolbar" }, badge(job.status), el("span", { class: "muted mono" }, ` ${job.kind} · ${job.id}`),
    el("span", { class: "spacer" }), apkButton(job), downloadButton(job));
  if (job.status === "ERROR") {
    out.replaceChildren(el("div", { class: "panel" }, head, el("h2", {}, "Job failed"),
      el("p", { class: "error" }, job.error), rawJson(job)));
    return;
  }
  const notice = job.status === "CANCELLED"
    ? el("p", { class: "notice" }, "Cancelled. Any result below is what the job produced before it stopped.") : null;
  const body = job.result === null || job.result === undefined ? []
    : PREVIEW[job.kind] && !render ? PREVIEW[job.kind](job)
      : (render || RENDER[job.kind] || ((r) => [rawJson(r)]))(job.result);
  out.replaceChildren(el("div", { class: "panel" }, head, notice, body));
}

// -- renderers -----------------------------------------------------------------------

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function renderAnalyze(r, apk) {
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
    // Security findings do not name the privacy findings remediations work on, so the
    // handoff is per APK: Remediate lists that APK's remediable findings.
    apk ? el("div", { class: "toolbar" }, el("button", { type: "button", class: "secondary", onclick: () => {
      selectTab("remediate");
      $("rem-apk").value = apk;
      $("form-remediate").requestSubmit();
    } }, "Open in Remediate"), el("span", { class: "muted" }, " privacy findings of this APK and their remediations")) : null,
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

const RENDER = { diff: renderDiff, "modkit-run": renderModKitResult,
  "modkit-chain": renderChain, "modkit-patches": (r) => renderPatches(r, null),
  "remediation-findings": renderRemediationFindings, "modification-plan": renderModificationPlan,
  verify: renderVerify, "verify-transformation": renderH4, references: renderReferences };

// -- 9.2: preview, then apply -----------------------------------------------------------

// Shown under a finished, applicable preview. The server applies exactly what the preview
// job saw (same inputs, same plan, APK unchanged); the page only adds the output path.
function applyPanel(job, what) {
  const out = el("div", {});
  const id = `apply-${job.id}`;
  const input = el("input", { type: "text", id, required: true, placeholder: "/path/to/new-output.apk" });
  const btn = el("button", { type: "submit", class: "primary" }, `Apply ${what}`);
  const form = el("form", { class: "panel apply" },
    el("h2", {}, "Apply"),
    el("p", { class: "hint" }, "Writes a new APK; the input is never modified. Applies exactly the preview above, once. ",
      "If the input APK has changed since the preview, the server refuses."),
    el("label", { for: id }, "Output APK (absolute path, must not exist)"), input, btn, out);
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    runJob("/api/jobs/apply", { preview_job: job.id, output: input.value.trim() }, out, btn)
      .then(() => { if (out.querySelector(".badge")?.textContent === "DONE") btn.hidden = true; });
  });
  return form;
}

function notApplicable(reason) {
  return el("p", { class: "notice" }, `Cannot be applied: ${reason}`);
}

function renderRemediationFindings(findings) {
  if (!findings.length) return [el("p", { class: "muted" }, "No privacy findings.")];
  const apk = $("rem-apk").value.trim();
  return [
    el("h2", {}, `${findings.length} privacy findings`),
    table(["Severity", "Finding", "Remediations"], findings.map(({ finding: f, remediations }) => el("tr", {},
      el("td", {}, badge(f.severity)),
      el("td", {}, el("details", {}, el("summary", {}, f.title, " ", el("span", { class: "muted mono" }, f.id)),
        el("p", {}, f.description), f.source_component ? el("p", { class: "mono" }, f.source_component) : null)),
      el("td", {}, remediations.length ? remediations.map((c) => el("div", {},
        el("button", { type: "button", class: "secondary", disabled: !c.is_supported,
          onclick: (ev) => runJob("/api/jobs/remediation-plan",
            { apk, finding_id: f.id, remediation_id: c.remediation.id }, $("out-remediate-plan"), ev.target),
        }, `Plan ${c.remediation.id}`), " ", c.remediation.name,
        c.is_supported ? null : el("div", { class: "muted" }, c.unsupported_reason)))
        : el("span", { class: "muted" }, "none"))))),
  ];
}

const PREVIEW = {
  "remediation-plan": (job) => {
    const p = job.result;
    return [
      el("h2", {}, `${p.remediation_id} ${p.remediation_name} `, badge(p.state)),
      kv([["Finding", `${p.finding_id} — ${p.finding_title}`], ["Category", p.finding_category],
        ["Package", p.package_name], ["APK SHA-256", p.source_apk_sha256]]),
      (p.preconditions || []).length ? table(["Precondition", "", "Expected", "Actual"], p.preconditions.map((c) => el("tr", {},
        el("td", {}, c.name, c.reason ? el("div", { class: "muted" }, c.reason) : null),
        el("td", {}, badge(c.satisfied ? "satisfied" : "not satisfied")),
        el("td", { class: "mono" }, c.expected), el("td", { class: "mono" }, c.actual)))) : null,
      list("Planned changes", p.planned_changes), list("Expected diff", p.expected_diff),
      list("Verification", p.verification_plan), list("Warnings", p.warnings),
      list("Compatibility", p.compatibility_notes), list("Limitations", p.limitations),
      p.state === "planned" ? applyPanel(job, "remediation") : notApplicable(`the plan is ${p.state}`),
      rawJson(p),
    ];
  },
  "transform-plan": (job) => {
    const r = job.result;
    const d = (r.decisions || [])[0];
    if (!d) return [list("Errors", r.errors, "error"), rawJson(r)];
    return [
      el("h2", {}, `${d.transformation_id} `, el("span", { class: "mono" }, d.target ? d.target.raw : "(invalid target)"), " ", badge(d.eligibility)),
      el("p", {}, d.statement),
      (d.reasons || []).length ? table(["Reason", "Requirement", "Detail"], d.reasons.map((x) => el("tr", {},
        el("td", {}, badge(x.state), " ", x.code), el("td", {}, x.requirement), el("td", {}, x.message)))) : null,
      d.plan ? el("div", {}, el("h2", {}, "Planned changes"),
        table(["Type", "Target", "Artifact"], d.plan.planned_changes.map((c) => el("tr", {},
          el("td", {}, c.type), el("td", { class: "mono" }, c.target), el("td", { class: "mono" }, c.artifact || "–")))),
        list("Expected changes", d.plan.expected_changes)) : null,
      list("Errors", r.errors, "error"),
      d.plan && !(r.errors || []).length ? applyPanel(job, "transformation") : notApplicable(`no applicable plan (${d.eligibility})`),
      el("p", { class: "notice" }, "Eligibility means the static evidence supports the change; it does not establish that the target is malicious, unnecessary or safe to remove."),
      rawJson(r),
    ];
  },
  "build-check": (job) => {
    const t = job.result.toolchain;
    return [
      el("h2", {}, "Build toolchain ", badge(t.valid ? "valid" : "invalid")),
      kv([["Signing", job.result.signing || "none configured"]]),
      table(["Tool", "Status", "Version", "Path / notes"], Object.entries(t.tools || {}).map(([name, d]) => el("tr", {},
        el("td", {}, name), el("td", {}, badge(d.status)), el("td", {}, d.version || ""),
        el("td", { class: "mono" }, `${d.path || ""} ${d.notes || ""}`)))),
      list("Errors", t.errors, "error"), list("Warnings", t.warnings),
      t.valid ? applyPanel(job, "no-op rebuild") : notApplicable("the toolchain is not valid"),
    ];
  },
};

// Remediation, transformation and build results differ; show the common parts.
function renderApplied(r) {
  const status = r.state || r.status || (r.success === true ? "SUCCESS" : r.success === false ? "FAILED" : "?");
  const output = r.output_apk_path || r.output_apk;
  const failure = r.failure ? `${r.failure.code} at ${r.failure.stage}: ${r.failure.message}` : r.failure_cause;
  return [
    el("h2", {}, "Result ", badge(status)),
    kv([["Output APK", output], ["Failure", failure], ["Workspace", r.workspace]]),
    (r.verification || []).length ? table(["Check", "Expected", "Actual", "Result"], r.verification.map((v) => el("tr", {},
      el("td", {}, v.check, v.mandatory ? "" : el("span", { class: "muted" }, " (optional)")),
      el("td", { class: "mono" }, v.expected), el("td", { class: "mono" }, v.actual), el("td", {}, badge(v.status))))) : null,
    (r.stages || []).length ? table(["Stage", "Status", "Time"], r.stages.map((st) => el("tr", {},
      el("td", {}, st.stage), el("td", {}, badge(st.status)), el("td", {}, st.duration_seconds != null ? `${st.duration_seconds.toFixed(2)}s` : "")))) : null,
    list("Failures", r.failures, "error"), list("Errors", r.errors, "error"), list("Warnings", r.warnings),
    list("Limitations", r.limitations),
    rawJson(r),
  ];
}

// Project files a Modify apply edited, handed to the next Verify run (see "Verify output").
let VERIFY_PLANNED_FILES = [];

PREVIEW.analyze = (job) => renderAnalyze(job.result, job.summary.apk);

PREVIEW.apply = (job) => {
  const r = job.result;
  const out = el("div", {});
  const h4 = job.summary.preview_kind === "transform-plan" && r.status === "VERIFIED"
    ? el("div", { class: "panel" }, el("h2", {}, "Verify (H.4)"),
      el("p", { class: "hint" }, "Rebuilds an unmodified control of the original and classifies every difference as noise, expected, unexpected or unknown (same as apkforge verify ORIGINAL TRANSFORMED --plan PLAN --build-control)."),
      el("button", { type: "button", class: "primary", onclick: (ev) =>
        runJob("/api/jobs/verify-transformation", { apply_job: job.id }, out, ev.target) }, "Verify transformation"), out)
    : null;
  // A Phase D apply knows what it meant to change: verify the output against exactly that.
  const expected = (r.modifiers || []).flatMap((m) => m.plan?.expected_changes || []);
  const plannedFiles = [...new Set((r.modifiers || []).flatMap((m) => (m.plan?.file_changes || []).map((f) => f.path)))];
  const declared = job.summary.preview_kind === "modify-preview" && r.output_apk
    ? el("div", { class: "panel" }, el("h2", {}, "Verify against the declared changes"),
      el("p", { class: "hint" }, `Pair verification of the output with the ${expected.length} change(s) the modifiers declared, so only other changes count as unexpected.`),
      el("button", { type: "button", class: "primary", onclick: () => {
        selectTab("verify");
        $("verify-original").value = job.summary.apk;
        $("verify-modified").value = r.output_apk;
        $("verify-expected").value = JSON.stringify(expected, null, 2);
        $("verify-noise").checked = true;
        VERIFY_PLANNED_FILES = plannedFiles;
        $("form-verify").requestSubmit();
      } }, "Verify output"))
    : null;
  return [...renderApplied(r), h4, declared];
};

PREVIEW["modify-preview"] = (job) => {
  const r = job.result;
  return [
    el("h2", {}, "Dry run ", badge(r.status)),
    kv([["Order", (r.order || []).join(" → ")], ["APK", r.apk]]),
    table(["Modifier", "Readiness", "Intended changes", "Preconditions"], (r.modifiers || []).map((m) => el("tr", {},
      el("td", {}, m.info.id, el("div", { class: "muted" }, m.info.name)),
      el("td", {}, badge(m.plan?.readiness ?? m.step.status), m.plan?.refusal_code ? el("div", { class: "muted" }, m.plan.refusal_code) : null),
      el("td", {}, el("ul", {}, (m.plan?.changes || []).map((c) => el("li", {}, c))),
        list("Problems", m.plan?.problems, "error"), list("Warnings", m.plan?.warnings)),
      el("td", {}, (m.plan?.preconditions || []).map((c) => el("div", {}, badge(c.satisfied ? "satisfied" : "not satisfied"), ` ${c.name}`)))))),
    (r.conflicts || []).length ? el("div", {}, el("h2", {}, "Conflicts"), table(["Kind", "Modifiers", "Subject", "Reason"],
      r.conflicts.map((c) => el("tr", {}, el("td", {}, c.kind), el("td", {}, c.modifiers.join(", ")),
        el("td", { class: "mono" }, c.subject), el("td", {}, c.reason))))) : null,
    list("Failures", r.failures, "error"), list("Warnings", r.warnings),
    r.status === "dry_run" ? applyPanel(job, "modifiers") : notApplicable(`the dry run ended ${r.status}`),
    rawJson(r),
  ];
};

function renderModificationPlan(p) {
  return [
    el("h2", {}, `${p.changes.length} suggested changes `, badge(p.status)),
    p.changes.length ? table(["Risk", "Change", "Target", "Reason"], p.changes.map((c) => el("tr", {},
      el("td", {}, badge(c.risk)), el("td", {}, c.change_type, el("div", { class: "muted" }, c.operation)),
      el("td", { class: "mono" }, c.target),
      el("td", {}, c.reason, c.risk_explanation ? el("div", { class: "muted" }, c.risk_explanation) : null))))
      : el("p", { class: "muted" }, "No changes suggested."),
    list("Conflicts", (p.conflicts || []).map((c) => JSON.stringify(c))), list("Warnings", p.warnings),
    list("Limitations", p.limitations),
    el("p", { class: "notice" }, "Read-only suggestions. Make a change with Modify (Phase D modifiers) or Remediate, which preview it first."),
    rawJson(p),
  ];
}

function matrixTable(m) {
  return [
    el("h2", {}, "Verification ", badge(m.overall)), el("p", {}, m.overall_reason),
    table(["Check", "Status", "Summary"], Object.entries(m.checks || {}).map(([name, c]) => el("tr", {},
      el("td", {}, name), el("td", {}, badge(c.status)), el("td", {}, c.summary)))),
    list("Limitations", m.limitations),
  ];
}

function changesTable(title, rows) {
  if (!rows || !rows.length) return null;
  return el("details", { open: true }, el("summary", {}, `${title} (${rows.length})`),
    table(["Category", "Kind", "Identifier", "Reason"], rows.map((o) => el("tr", {},
      el("td", {}, o.category), el("td", {}, o.kind), el("td", { class: "mono" }, o.identifier), el("td", {}, o.reason || "")))));
}

function renderVerify(r) {
  if (r.checks) return [...matrixTable(r), rawJson(r)];  // single APK: structural + signature
  return [
    ...matrixTable(r.verification),
    kv([["Original", r.original?.path], ["Modified", r.modified?.path], ["Noise baseline", r.baseline ? "measured" : "none"]]),
    changesTable("Unexpected", r.unexpected), changesTable("Unknown", r.unknown),
    (r.expected || []).length ? el("details", {}, el("summary", {}, `Declared changes (${r.expected.length})`),
      table(["Category", "Kind", "Identifier"], r.expected.map((e) => el("tr", {},
        el("td", {}, e.category), el("td", {}, e.kind), el("td", { class: "mono" }, e.identifier))))) : null,
    list("Limitations", r.limitations),
    el("p", { class: "notice" }, "Verification shows structural/signing validity and plan conformance within the comparators' coverage; it does not prove the app is safe."),
    rawJson(r),
  ];
}

function renderH4(r) {
  const diffs = (rows) => rows.map((d) => ({ ...d.observation, reason: `${d.leg}: ${d.classification}` }));
  return [
    el("h2", {}, `H.4 ${r.transformation_id || ""} `, badge(r.status)), el("p", {}, r.status_reason),
    table(["Domain", "Status", "Completeness", "Reasons"], Object.values(r.domains || {}).map((d) => el("tr", {},
      el("td", {}, d.domain, d.mandatory ? "" : el("span", { class: "muted" }, " (optional)")),
      el("td", {}, badge(d.status)), el("td", {}, badge(d.completeness)), el("td", {}, (d.reasons || []).join("; "))))),
    changesTable("Unexpected", diffs(r.unexpected_changes || [])), changesTable("Unknown", diffs(r.unknown_changes || [])),
    list("Errors", r.errors, "error"), list("Limitations", r.limitations),
    el("p", { class: "notice" }, r.statement),
    rawJson(r),
  ];
}

// -- References tab (H.1): pick transformation targets ---------------------------------------

const MAX_CLASS_ROWS = 200;

// Fill the Transform tab and plan (planning only reads). H-TRANS-003 needs a replacement
// method first, so that one stops at the form.
function planTransform(apk, id, target) {
  selectTab("transform");
  $("tr-apk").value = apk;
  $("tr-id").value = id;
  $("tr-id").dispatchEvent(new Event("change"));
  $("tr-target").value = target;
  if (id === "H-TRANS-003") $("tr-replacement").focus();
  else $("form-transform").requestSubmit();
}

function renderReferences(r) {
  const apk = r.apk_path;
  const filter = el("input", { type: "text", class: "filter", placeholder: "Filter classes…" });
  const onlyFree = el("input", { type: "checkbox", checked: true });
  const body = el("div", {});
  const callSites = async (cls, m, box, btn) => {
    btn.disabled = true;
    try {
      const q = new URLSearchParams({ class_name: cls, method: m.name + m.descriptor });
      const rows = await api(`/api/references/${r.ref_id}/call-sites?${q}`);
      box.replaceChildren(rows.length ? table(["Invoked", "Line", ""], rows.map((c) => el("tr", {},
        el("td", { class: "mono" }, c.invoked), el("td", {}, c.line ?? ""),
        el("td", {}, el("button", { type: "button", class: "secondary", onclick: () => planTransform(apk, "H-TRANS-003", c.target) },
          "Replace call (H-TRANS-003)…")))))
        : el("p", { class: "muted" }, "No invocations in this method."));
    } catch (e) {
      box.replaceChildren(el("p", { class: "error" }, e.message));
    } finally {
      btn.disabled = false;
    }
  };
  const draw = () => {
    const q = filter.value.toLowerCase();
    const rows = r.classes.filter((c) => (!onlyFree.checked || c.references + c.indirect === 0) && c.name.toLowerCase().includes(q));
    body.replaceChildren(
      el("p", { class: "muted" }, `${rows.length} of ${r.classes.length} classes`, rows.length > MAX_CLASS_ROWS ? ` (first ${MAX_CLASS_ROWS} shown; filter to narrow)` : ""),
      table(["Class", "Incoming", ""], rows.slice(0, MAX_CLASS_ROWS).map((c) => el("tr", {},
        el("td", {}, el("details", {}, el("summary", { class: "mono" }, c.name),
          c.superclass ? el("div", { class: "muted mono" }, `extends ${c.superclass}`) : null,
          c.methods.length ? table(["Method", "Calls", ""], c.methods.map((m) => {
            const box = el("div", {});
            const sites = el("button", { type: "button", class: "secondary", onclick: (ev) => callSites(c.name, m, box, ev.target) }, "Call sites…");
            return el("tr", {}, el("td", { class: "mono" }, m.name + m.descriptor, box), el("td", {}, m.calls),
              el("td", {}, el("div", { class: "toolbar" },
                el("button", { type: "button", class: "secondary", onclick: () => planTransform(apk, "H-TRANS-002", `${c.name}->${m.name}${m.descriptor}`) }, "Plan removal (H-TRANS-002)"),
                sites)));
          })) : el("p", { class: "muted" }, "No methods."))),
        el("td", {}, `${c.references}`, c.indirect ? el("span", { class: "muted" }, ` + ${c.indirect} indirect`) : null,
          c.analysis_state !== "COMPLETE" ? el("div", {}, badge(c.analysis_state)) : null),
        el("td", {}, el("button", { type: "button", class: "secondary", onclick: () => planTransform(apk, "H-TRANS-001", c.name) }, "Plan removal (H-TRANS-001)"))))));
  };
  filter.addEventListener("input", draw);
  onlyFree.addEventListener("change", draw);
  draw();
  return [
    el("h2", {}, `${r.apk.package_name || r.apk.file_name || ""} `, badge(r.analysis_state)),
    kv([["Components", Object.entries(r.component_states).map(([k, v]) => `${k} ${v}`).join(" · ")],
      ["Reflection / native evidence", `${r.reflection} / ${r.native}`]]),
    el("p", { class: "notice" }, "Incoming counts are what H.1 observed statically, without string mentions. They suggest candidates; the H.2 plan re-checks every requirement and decides."),
    el("div", { class: "toolbar" }, filter, el("label", { class: "check" }, onlyFree, " Unreferenced only")),
    body,
    list("Errors", r.errors, "error"), list("Limitations", r.limitations),
  ];
}

// -- Modify tab: Phase D modifiers ---------------------------------------------------------

let MODIFIERS_LOADING = null;
const MODIFIER_FORMS = {};
function loadModifiers() {
  MODIFIERS_LOADING ||= (async () => {
    let infos;
    try {
      infos = await api("/api/modifiers");
    } catch (e) {
      MODIFIERS_LOADING = null;
      $("modifier-list").replaceChildren(el("p", { class: "error" }, e.message));
      return;
    }
    $("modifier-list").replaceChildren(...infos.map((m) => {
      const use = el("input", { type: "checkbox", value: m.id });
      const inputs = Object.fromEntries(Object.keys(m.parameters || {}).map((k) => [k, el("input", { type: "text", autocomplete: "off" })]));
      MODIFIER_FORMS[m.id] = { use, inputs };
      return el("fieldset", { class: "step" },
        el("legend", {}, el("label", { class: "check" }, use, ` ${m.id} — ${m.name}`)),
        el("p", { class: "hint" }, m.description, ` Risk: ${m.risk}. Verification: ${m.verification_available ? "yes" : "no"}.`),
        Object.entries(m.parameters || {}).flatMap(([k, desc]) => {
          const id = `mod-${m.id}-${k}`;
          inputs[k].id = id;
          return [el("label", { for: id }, k, el("span", { class: "muted" }, ` — ${desc}`)), inputs[k]];
        }));
    }));
  })();
  return MODIFIERS_LOADING;
}

function selectedModifiers() {
  return Object.entries(MODIFIER_FORMS).filter(([, f]) => f.use.checked).map(([id, f]) => ({
    id, parameters: Object.fromEntries(Object.entries(f.inputs).filter(([, i]) => i.value.trim()).map(([k, i]) => [k, i.value.trim()])),
  }));
}

// -- patch bundles (Morphe list_patches) ----------------------------------------------

// `enableInput` (optional): the form's "enable" field the picker fills.
// "k1=v1, k2=v2" (the Morphe `options` parameter) <-> Map; entries without "=" are dropped,
// as the adapter does.
function parseOptions(text) {
  return new Map((text || "").split(",").map((e) => e.trim()).filter((e) => e.includes("="))
    .map((e) => [e.slice(0, e.indexOf("=")).trim(), e.slice(e.indexOf("=") + 1).trim()]).filter(([k]) => k));
}

// Fields for the options of the ticked patches, one per key: Morphe's `-O key=value` applies
// to the whole run, so patches sharing a key share the field.
function optionFields(patches, current) {
  const byKey = new Map();
  for (const p of patches) for (const o of p.options || []) {
    if (!byKey.has(o.key)) byKey.set(o.key, { option: o, patches: [] });
    byKey.get(o.key).patches.push(p.name);
  }
  const fields = new Map();
  const node = el("div", {}, [...byKey].map(([key, { option: o, patches: users }]) => {
    const id = `opt-${Math.random().toString(36).slice(2)}`;
    const dflt = o.default ? `(default: ${o.default})` : "(default)";
    // Possible values are presets, not a closed list (Clone app's packageName offers only
    // "Default"): free text with the presets as suggestions.
    const presets = (o.possible_values || []).length
      ? el("datalist", { id: `${id}-presets` }, o.possible_values.map((v) => el("option", { value: v.value }, v.label || v.value))) : null;
    const input = /bool/i.test(o.type) && !presets
      ? el("select", { id }, el("option", { value: "" }, dflt), el("option", { value: "true" }, "true"), el("option", { value: "false" }, "false"))
      : el("input", { id, type: "text", placeholder: o.default || "", autocomplete: "off", list: presets ? `${id}-presets` : null });
    if (current.has(key)) {
      if (input.tagName === "SELECT" && ![...input.options].some((x) => x.value === current.get(key))) input.append(el("option", { value: current.get(key) }, current.get(key)));
      input.value = current.get(key);
    }
    fields.set(key, { input, option: o });
    return el("div", {}, el("label", { for: id }, el("span", { class: "mono" }, key), o.required ? " *" : "",
      o.title && o.title !== key ? ` — ${o.title}` : "", el("span", { class: "muted" }, ` (${[o.type, users.join(", ")].filter(Boolean).join("; ")})`)),
    o.description ? el("div", { class: "hint" }, o.description) : null, input, presets);
  }));
  return { node, fields };
}

function renderPatches(listing, enableInput, optionsInput) {
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
  const ticked = () => (listing.patches || []).filter((p, i) => rows[i].querySelector("input[type=checkbox]")?.checked);
  const optBox = el("div", {});
  const problems = el("div", {});
  let form = { fields: new Map() };
  const drawOptions = () => {
    // keep what was typed so far, over what the options parameter held
    const current = parseOptions(optionsInput?.value);
    for (const [k, f] of form.fields) current.set(k, f.input.value);
    form = optionFields(ticked(), current);
    optBox.replaceChildren(...(form.fields.size && optionsInput
      ? [el("h2", {}, "Options of the selected patches"), el("p", { class: "hint" }, "Empty means the patch's default. Applies to every selected patch with that key."), form.node]
      : []));
  };
  if (enableInput) {
    for (const r of rows) r.querySelector("input[type=checkbox]").addEventListener("change", drawOptions);
    drawOptions();
  }
  const use = enableInput ? el("button", { type: "button", class: "primary", onclick: () => {
    const errors = [];
    const chosen = new Map();
    for (const [key, { input, option }] of form.fields) {
      const v = input.value.trim();
      if (v.includes(",")) errors.push(`${key}: a value cannot contain a comma (the options parameter is comma-separated)`);
      else if (!v && option.required && !option.default) errors.push(`${key} is required`);
      else if (v) chosen.set(key, v);
    }
    problems.replaceChildren(...errors.map((e) => el("p", { class: "error" }, e)));
    if (errors.length) return;
    const names = ticked().map((p) => p.name);
    enableInput.value = names.join(", ");
    enableInput.dispatchEvent(new Event("input", { bubbles: true }));
    if (optionsInput) {
      // options typed by hand for keys not shown here stay
      const merged = new Map([...parseOptions(optionsInput.value)].filter(([k]) => !form.fields.has(k)));
      for (const [k, v] of chosen) merged.set(k, v);
      optionsInput.value = [...merged].map(([k, v]) => `${k}=${v}`).join(", ");
      optionsInput.dispatchEvent(new Event("input", { bubbles: true }));
    }
    use.textContent = `Enabled ${names.length} patch(es)${chosen.size ? `, ${chosen.size} option(s)` : ""}`;
  } }, optionsInput ? "Use selected as “enable” and “options”" : "Use selected as “enable”") : null;
  return [
    el("h2", {}, `${(listing.patches || []).length} patches`, listing.resolved_version ? ` · ${listing.resolved_version}` : ""),
    filter,
    table([enableInput ? "" : null, "#", "Patch", "Default", "Compatible with", "Options (key=default)"].filter((h) => h !== null), rows),
    optBox, problems, use,
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
          (listing) => renderPatches(listing, inputs.enable, inputs.options));
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
  if (name === "modify") loadModifiers();
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
  onSubmit("form-remediate", (btn) => {
    $("out-remediate-plan").replaceChildren();
    runJob("/api/jobs/remediation-findings", { apk: $("rem-apk").value.trim() }, $("out-remediate"), btn);
  });
  onSubmit("form-transform", (btn) => runJob("/api/jobs/transform-plan", {
    apk: $("tr-apk").value.trim(), transformation_id: $("tr-id").value, target: $("tr-target").value.trim(),
    replacement: $("tr-replacement").value.trim() || null,
  }, $("out-transform"), btn));
  $("tr-id").addEventListener("change", () => { $("tr-replacement-row").hidden = $("tr-id").value !== "H-TRANS-003"; });
  onSubmit("form-references", (btn) => runJob("/api/jobs/references", { apk: $("ref-apk").value.trim() }, $("out-references"), btn));
  onSubmit("form-plan", (btn) => runJob("/api/jobs/modification-plan",
    { apk: $("plan-apk").value.trim(), diff_apk: $("plan-diff").value.trim() || null }, $("out-plan"), btn));
  onSubmit("form-modify", (btn) => {
    const modifiers = selectedModifiers();
    if (!modifiers.length) { $("out-modify").replaceChildren(el("div", { class: "panel error" }, "Select at least one modifier.")); return; }
    runJob("/api/jobs/modify-preview", { apk: $("modify-apk").value.trim(), modifiers,
      allow_partial: $("modify-partial").checked, measure_noise_floor: $("modify-noise").checked }, $("out-modify"), btn);
  });
  onSubmit("form-verify", (btn) => {
    let expected = [];
    try {
      const text = $("verify-expected").value.trim();
      expected = text ? JSON.parse(text) : [];
      if (!Array.isArray(expected)) throw new Error("expected a JSON array");
    } catch (e) {
      $("out-verify").replaceChildren(el("div", { class: "panel error" }, `Expected changes are not valid JSON: ${e.message}`));
      return;
    }
    const planned_files = VERIFY_PLANNED_FILES;
    VERIFY_PLANNED_FILES = [];  // they belong to that one handoff, not to later manual runs
    runJob("/api/jobs/verify", { original: $("verify-original").value.trim(), modified: $("verify-modified").value.trim() || null,
      measure_noise_floor: $("verify-noise").checked, expected, planned_files }, $("out-verify"), btn);
  });
  onSubmit("form-build", (btn) => runJob("/api/jobs/build-check", { apk: $("build-apk").value.trim() }, $("out-build"), btn));
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
