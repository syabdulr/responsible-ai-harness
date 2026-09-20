/**
 * Report UI renderer. Fetches the harness's own generated artifacts from
 * ./data/ (report.json validated against the report contract, plus the
 * evidence bundle's manifest/target-manifest/verify result — see
 * scripts/serve-report-ui.ts), maps them through the pure view-model
 * functions in view-model.js, and renders them. No business logic lives
 * here: this file only builds DOM from an already-computed view model.
 */

import { buildViewModel } from "./view-model.js";

const DATA_BASES = {
  offline: "./data/",
  live: "./data-live/",
};

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatDate(iso) {
  if (typeof iso !== "string") return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function short(hash, n = 12) {
  if (typeof hash !== "string") return "—";
  return hash.length > n ? `${hash.slice(0, n)}…` : hash;
}

async function fetchJson(path) {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(`${path}: HTTP ${String(res.status)}`);
  return res.json();
}

function showToast(message) {
  const toast = document.getElementById("toast");
  if (toast === null) return;
  toast.textContent = message;
  toast.classList.add("visible");
  window.setTimeout(() => { toast.classList.remove("visible"); }, 2200);
}

function renderFatalError(message) {
  const main = document.getElementById("main");
  if (main === null) return;
  main.innerHTML = `
    <div class="shell">
      <div class="card" style="border-color:#f7cfcf;">
        <p class="eyebrow" style="color:#dc2626;">Could not load report</p>
        <h1 class="report-title">Report unavailable</h1>
        <p class="report-summary">${escapeHtml(message)}</p>
        <p class="report-summary">Run <code>npm run demo</code> then reload, or check that <code>scripts/serve-report-ui.ts</code> is still running.</p>
      </div>
    </div>
  `;
}

function renderTopBar(vm) {
  const runEl = document.getElementById("topbar-run");
  const versionEl = document.getElementById("topbar-version");
  const integrityEl = document.getElementById("topbar-integrity");
  if (runEl !== null) runEl.textContent = `${vm.topBar.runId ?? "unknown run"} · ${formatDate(vm.topBar.createdAt)}`;
  if (versionEl !== null) versionEl.textContent = `report schema ${vm.topBar.reportSchemaVersion ?? "—"} · harness ${vm.topBar.harnessVersion ?? "—"}`;
  if (integrityEl !== null) {
    integrityEl.textContent = vm.topBar.verified ? "Bundle verified" : "Verification failed";
    integrityEl.className = `chip ${vm.topBar.verified ? "chip-good" : "chip-bad"}`;
  }
}

function renderHeader(vm, targetManifest) {
  const titleEl = document.getElementById("report-header-title");
  const summaryEl = document.getElementById("report-summary");
  const chipsEl = document.getElementById("meta-chips");
  const target = targetManifest?.target;

  if (titleEl !== null) {
    titleEl.textContent = target !== undefined
      ? `${target.displayName} (${target.kind}${target.version !== undefined ? ` · v${target.version}` : ""})`
      : "Local tool agent";
  }

  const counts = vm.counts;
  const findingWord = (counts?.totalFindings ?? 0) === 1 ? "finding" : "findings";
  const reviewWord = (counts?.totalReviews ?? 0) === 1 ? "case" : "cases";
  if (summaryEl !== null) {
    summaryEl.textContent = counts !== null
      ? `${String(counts.totalCases)} cases assessed · ${String(counts.totalFindings)} ${findingWord} · ${String(counts.totalReviews)} ${reviewWord} routed to human review. ${vm.risk.verdict.detail}`
      : vm.risk.verdict.detail;
  }

  const chips = [
    ["Run ID", vm.topBar.runId ?? "—"],
    ["Generated", formatDate(vm.topBar.createdAt)],
    ["Report schema", vm.topBar.reportSchemaVersion ?? "—"],
    ["Harness version", vm.topBar.harnessVersion ?? "—"],
  ];
  if (target !== undefined) {
    chips.push(["Input modes", [target.inputs?.text ? "text" : null, target.inputs?.images ? "images" : null, target.inputs?.files ? "files" : null].filter(Boolean).join(", ") || "text"]);
    chips.push(["Tools", Array.isArray(target.tools) ? String(target.tools.length) : "0"]);
  }
  if (chipsEl !== null) {
    chipsEl.innerHTML = chips.map(([k, v]) => `
      <div class="meta-chip">
        <dt>${escapeHtml(k)}</dt>
        <dd>${escapeHtml(v)}</dd>
      </div>
    `).join("");
  }
}

function renderRiskHero(vm) {
  const scoreEl = document.getElementById("risk-score");
  const badgeEl = document.getElementById("risk-verdict-badge");
  const detailEl = document.getElementById("risk-verdict-detail");
  const barEl = document.getElementById("risk-bar-fill");
  const jevEl = document.getElementById("jev-summary");

  const pct = vm.risk.score === null ? null : Math.round(vm.risk.score * 100);
  if (scoreEl !== null) scoreEl.textContent = pct === null ? "—" : String(pct);
  if (badgeEl !== null) {
    badgeEl.textContent = vm.risk.verdict.label;
    badgeEl.className = `badge badge-${vm.risk.verdict.tone}`;
  }
  if (detailEl !== null) detailEl.textContent = vm.risk.verdict.detail;
  if (barEl !== null) {
    barEl.style.width = `${String(pct ?? 0)}%`;
    barEl.className = `risk-bar-fill tone-${vm.risk.verdict.tone}`;
  }

  const jev = vm.jev;
  const rows = [
    ["Judge(s) used", jev.judgeIds.length > 0 ? jev.judgeIds.join(", ") : "none"],
    ["Mode", jev.usesLiveJev ? "Live Jev" : "Deterministic stub (offline)"],
    ["Pass / Fail / Uncertain", `${String(jev.byLabel.pass)} / ${String(jev.byLabel.fail)} / ${String(jev.byLabel.uncertain)}`],
    ["Average confidence", jev.avgConfidencePct === null ? "—" : `${String(jev.avgConfidencePct)}%`],
    ["Routed to human review", String(jev.humanReviewCount)],
  ];
  if (jevEl !== null) {
    jevEl.innerHTML = rows.map(([k, v]) => `
      <div class="jev-row">
        <span class="jev-label">${escapeHtml(k)}</span>
        <span class="jev-value">${escapeHtml(v)}</span>
      </div>
    `).join("");
  }
}

function domainStatusText(d) {
  switch (d.status) {
    case "not_evaluated": return "Not yet evaluated";
    case "no_cases": return "No cases in this run";
    case "clean": return "Clean";
    case "findings": return `${String(d.totalFindings)} finding${d.totalFindings === 1 ? "" : "s"}`;
    default: return "";
  }
}

function renderDomains(vm) {
  const grid = document.getElementById("domain-grid");
  if (grid === null) return;
  grid.innerHTML = vm.domains.map((d) => `
    <div class="domain-card ${d.inScope ? "" : "out-of-scope"}">
      <div class="domain-card-head">
        <span class="domain-card-title">${escapeHtml(d.label)}</span>
        <span class="badge badge-${d.status === "findings" ? d.worstSeverityTone : "none"}">${escapeHtml(domainStatusText(d))}</span>
      </div>
      <p class="domain-card-desc">${escapeHtml(d.description)}</p>
      <div class="domain-card-stats">
        <div class="domain-stat">
          <span class="domain-stat-value">${String(d.totalCases)}</span>
          <span class="domain-stat-label">Cases</span>
        </div>
        <div class="domain-stat">
          <span class="domain-stat-value">${String(d.reviewCount)}</span>
          <span class="domain-stat-label">In review</span>
        </div>
      </div>
    </div>
  `).join("");
}

function ruleResultsHtml(ruleResults) {
  if (!Array.isArray(ruleResults) || ruleResults.length === 0) return "<p class=\"rec-reasons\">No rule results.</p>";
  return `<ul class="rule-list">${ruleResults.map((r) => `
    <li>
      <span class="rule-outcome rule-outcome-${escapeHtml(r.outcome)}">${escapeHtml(r.outcome)}</span>
      <span>${escapeHtml(r.ruleId)} — ${escapeHtml(r.reasonCode)}</span>
    </li>
  `).join("")}</ul>`;
}

function evidenceRefsHtml(refs) {
  if (!Array.isArray(refs) || refs.length === 0) return "<p class=\"rec-reasons\">No evidence references.</p>";
  return `<div class="evidence-refs">${refs.map((r) => `<span class="evidence-ref">${escapeHtml(r)}</span>`).join("")}</div>`;
}

function questionProbsHtml(questionProbabilities) {
  if (!Array.isArray(questionProbabilities) || questionProbabilities.length === 0) return "";
  return `<ul class="question-probs">${questionProbabilities.map((q) => {
    const pct = Math.round((q.probability ?? 0) * 100);
    return `
    <li>
      <span class="qid">${escapeHtml(q.questionId)}</span>
      <span class="qval">${String(pct)}%</span>
      <span class="qbar-track"><span class="qbar-fill" style="width:${String(pct)}%"></span></span>
    </li>`;
  }).join("")}</ul>`;
}

function renderFindings(vm) {
  const list = document.getElementById("findings-list");
  if (list === null) return;
  list.innerHTML = vm.findings.map((f) => `
    <details class="finding-row" id="finding-${escapeHtml(f.caseId)}">
      <summary class="finding-summary">
        <span class="finding-case-id"><span class="chev" aria-hidden="true">›</span>${escapeHtml(f.caseId)}</span>
        <span class="finding-category">
          <span class="field-label">Domain</span>
          ${escapeHtml(f.domainLabel)} · ${escapeHtml(f.categoryLabel)}
        </span>
        <span>
          <span class="field-label">Severity</span>
          <span class="badge badge-${f.severityTone}">${escapeHtml(f.hasFinding ? f.severity : "none")}</span>
        </span>
        <span class="finding-control">
          <span class="field-label">Control / questions</span>
          ${escapeHtml(f.affectedControl ?? (f.questionIds.length > 0 ? f.questionIds.join(", ") : "—"))}
        </span>
        <span class="finding-evidence-count">
          <span class="field-label">Evidence</span>
          ${String(f.evidenceCount)}
        </span>
        <span class="finding-confidence">
          <span class="field-label">Confidence</span>
          ${f.confidencePct === null ? "—" : `${String(f.confidencePct)}%`}
        </span>
        <span class="finding-review">
          <span class="field-label">Review</span>
          ${escapeHtml(f.reviewState.replace(/_/g, " "))}
        </span>
      </summary>
      <div class="finding-detail">
        <div class="finding-detail-block">
          <h4>Hard-rule results</h4>
          ${ruleResultsHtml(f.ruleResults)}
        </div>
        ${f.judgeLabel !== null ? `
        <div class="finding-detail-block">
          <h4>Judge (${escapeHtml(f.judgeId ?? "unknown")}${f.judgeModel !== null ? ` · ${escapeHtml(f.judgeModel)}` : ""})</h4>
          <p class="rec-reasons">${escapeHtml(f.judgeLabel)}${f.confidencePct !== null ? ` — confidence ${String(f.confidencePct)}%` : ""}${f.reasonCodes.length > 0 ? ` — ${f.reasonCodes.map(escapeHtml).join(", ")}` : ""}</p>
          ${questionProbsHtml(f.questionProbabilities)}
        </div>` : ""}
        <div class="finding-detail-block">
          <h4>Evidence references</h4>
          ${evidenceRefsHtml(f.evidenceRefs)}
        </div>
        ${f.reproductionSteps.length > 0 ? `
        <div class="finding-detail-block">
          <h4>Reproduction</h4>
          <ol class="repro-steps">${f.reproductionSteps.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ol>
        </div>` : ""}
      </div>
    </details>
  `).join("");
}

function actionLabel(action) {
  switch (action) {
    case "block_release": return "Block release";
    case "human_review_required": return "Human review required";
    case "monitor": return "Monitor";
    case "no_action": return "No action";
    default: return action;
  }
}

function renderRecommendations(vm) {
  const list = document.getElementById("rec-list");
  if (list === null) return;
  list.innerHTML = vm.recommendations.map((r) => `
    <div class="rec-card ${r.scope === "run" ? "run-level" : ""} action-${escapeHtml(r.action)}">
      <div class="rec-main">
        <span class="rec-title">${r.scope === "run" ? "Run-level verdict" : escapeHtml(r.caseId ?? "")}</span>
        <span class="rec-reasons">${r.reasonCodes.length > 0 ? escapeHtml(r.reasonCodes.join(", ")) : "No specific reason codes."}</span>
      </div>
      <div class="rec-side">
        ${r.severity !== "none" ? `<span class="badge badge-${escapeHtml(r.severity)}">${escapeHtml(r.severity)}</span>` : ""}
        <span class="badge ${r.action === "block_release" ? "badge-critical" : "badge-medium"}">${escapeHtml(actionLabel(r.action))}</span>
      </div>
    </div>
  `).join("");
}

function renderIntegrity(vm) {
  const el = document.getElementById("integrity-card");
  if (el === null) return;
  const toolVersionsHtml = Object.entries(vm.integrity.toolVersions).map(([k, v]) => `
    <div class="integrity-row"><span class="k">${escapeHtml(k)}</span><span class="v">${escapeHtml(v)}</span></div>
  `).join("") || "<p class=\"rec-reasons\">No tool versions recorded.</p>";

  el.innerHTML = `
    <div class="integrity-group">
      <h4>Report contract</h4>
      <div class="integrity-row"><span class="k">Schema version</span><span class="v">${escapeHtml(vm.integrity.reportSchemaVersion ?? "—")}</span></div>
      <div class="integrity-row"><span class="k">Report sha256</span><span class="v" title="${escapeHtml(vm.integrity.reportSha256 ?? "")}">${escapeHtml(short(vm.integrity.reportSha256, 20))}</span></div>
      <div class="integrity-row"><span class="k">Harness version</span><span class="v">${escapeHtml(vm.integrity.harnessVersion ?? "—")}</span></div>
    </div>
    <div class="integrity-group">
      <h4>Evidence bundle</h4>
      ${vm.integrity.manifest === null ? "<p class=\"rec-reasons\">No bundle manifest available.</p>" : `
      <div class="integrity-row"><span class="k">Redaction state</span><span class="v">${escapeHtml(vm.integrity.manifest.redactionState)}</span></div>
      <div class="integrity-row"><span class="k">Entries digest</span><span class="v" title="${escapeHtml(vm.integrity.manifest.entriesDigest)}">${escapeHtml(short(vm.integrity.manifest.entriesDigest, 20))}</span></div>
      <div class="integrity-row"><span class="k">Artifact count</span><span class="v">${String(vm.integrity.manifest.entryCount)}</span></div>
      `}
    </div>
    <div class="integrity-group">
      <h4>Offline verification</h4>
      ${vm.integrity.verify === null ? "<p class=\"rec-reasons\">Not verified.</p>" : `
      <div class="integrity-row"><span class="k">Status</span><span class="v">${vm.integrity.verify.ok ? "OK" : "FAILED"}</span></div>
      <div class="integrity-row"><span class="k">Entries checked</span><span class="v">${String(vm.integrity.verify.checked)}</span></div>
      ${vm.integrity.verify.failures.length > 0 ? `<div class="integrity-row"><span class="k">Failures</span><span class="v">${escapeHtml(vm.integrity.verify.failures.join("; "))}</span></div>` : ""}
      `}
    </div>
    <div class="integrity-group">
      <h4>Tool versions</h4>
      ${toolVersionsHtml}
    </div>
  `;
}

function renderLimitations(vm) {
  const el = document.getElementById("limitations-list");
  if (el === null) return;
  el.innerHTML = vm.limitations.map((l) => `<li>${escapeHtml(l)}</li>`).join("");
}

// Mutable state the export buttons read at click time, so switching data
// sources doesn't require adding/removing event listeners.
const currentExport = { text: "", runId: undefined };

function wireExportButtonsOnce() {
  const buttons = [document.getElementById("export-btn-top"), document.getElementById("export-btn-mobile")];
  const doExport = () => {
    if (currentExport.text === "") return;
    const blob = new Blob([currentExport.text], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${currentExport.runId ?? "report"}.report.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    showToast("Report exported");
  };
  for (const btn of buttons) {
    if (btn === null) continue;
    btn.addEventListener("click", doExport);
  }
}

/** Force every finding <details> open for print, then restore prior state after. */
function wirePrintDisclosure() {
  let openedByPrint = [];
  window.addEventListener("beforeprint", () => {
    const all = document.querySelectorAll(".finding-row");
    openedByPrint = [];
    all.forEach((el) => {
      if (!el.open) {
        el.open = true;
        openedByPrint.push(el);
      }
    });
  });
  window.addEventListener("afterprint", () => {
    for (const el of openedByPrint) el.open = false;
    openedByPrint = [];
  });
}

async function fetchSources() {
  try {
    const res = await fetch("./data/sources.json", { cache: "no-store" });
    if (!res.ok) return { sources: [{ id: "offline", available: true }] };
    return await res.json();
  } catch {
    return { sources: [{ id: "offline", available: true }] };
  }
}

/** Load and render one data source ("offline" or "live"). */
async function loadSource(sourceId) {
  const base = DATA_BASES[sourceId] ?? DATA_BASES.offline;
  let report;
  let manifest;
  let targetManifest;
  let verify;
  let reportText;
  try {
    const [reportRes, manifestJson, targetJson, verifyJson] = await Promise.all([
      fetch(`${base}report.json`, { cache: "no-store" }),
      fetchJson(`${base}bundle-manifest.json`).catch(() => undefined),
      fetchJson(`${base}target-manifest.json`).catch(() => undefined),
      fetchJson(`${base}verify.json`).catch(() => undefined),
    ]);
    if (!reportRes.ok) throw new Error(`report.json: HTTP ${String(reportRes.status)}`);
    reportText = await reportRes.text();
    report = JSON.parse(reportText);
    manifest = manifestJson;
    targetManifest = targetJson;
    verify = verifyJson;
  } catch (error) {
    renderFatalError(error instanceof Error ? error.message : "Unknown error loading report data.");
    return;
  }

  const vm = buildViewModel(report, manifest, verify);
  renderTopBar(vm);
  renderHeader(vm, targetManifest);
  renderRiskHero(vm);
  renderDomains(vm);
  renderFindings(vm);
  renderRecommendations(vm);
  renderIntegrity(vm);
  renderLimitations(vm);

  currentExport.text = reportText;
  currentExport.runId = vm.topBar.runId ?? undefined;
  const exportButtons = [document.getElementById("export-btn-top"), document.getElementById("export-btn-mobile")];
  for (const btn of exportButtons) if (btn !== null) btn.disabled = false;

  const liveBadge = document.getElementById("live-jev-badge");
  if (liveBadge !== null) liveBadge.hidden = sourceId !== "live";

  const offlineTab = document.getElementById("source-tab-offline");
  const liveTab = document.getElementById("source-tab-live");
  if (offlineTab !== null) offlineTab.setAttribute("aria-selected", String(sourceId === "offline"));
  if (liveTab !== null) liveTab.setAttribute("aria-selected", String(sourceId === "live"));
}

async function main() {
  wireExportButtonsOnce();
  wirePrintDisclosure();

  const { sources } = await fetchSources();
  const liveAvailable = Array.isArray(sources) && sources.some((s) => s.id === "live" && s.available === true);

  const switchEl = document.getElementById("source-switch");
  if (liveAvailable && switchEl !== null) {
    switchEl.hidden = false;
    document.getElementById("source-tab-offline")?.addEventListener("click", () => { loadSource("offline").catch(() => undefined); });
    document.getElementById("source-tab-live")?.addEventListener("click", () => { loadSource("live").catch(() => undefined); });
  }

  // Offline is always the default view — a live bundle, even a verified
  // one, is never shown on load without an explicit click.
  await loadSource("offline");
}

main().catch((error) => {
  renderFatalError(error instanceof Error ? error.message : "Unknown error.");
});
