let currentAnalysisResult = null;
let sampleCache = {};

document.addEventListener("DOMContentLoaded", async () => {
  setupEditor();
  await loadSamples();
  loadSample('vulnerable_auth.py');
});

function setupEditor() {
  const codeInput = document.getElementById("codeInput");
  const editorStats = document.getElementById("editorStats");

  const updateMetrics = () => {
    const lines = codeInput.value ? codeInput.value.split("\n").length : 0;
    const chars = codeInput.value ? codeInput.value.length : 0;
    editorStats.textContent = `${lines} lines (${chars} chars)`;
  };

  codeInput.addEventListener("input", updateMetrics);
  updateMetrics();
}

function clearEditor() {
  const codeInput = document.getElementById("codeInput");
  codeInput.value = "";
  codeInput.dispatchEvent(new Event("input"));
}

async function loadSamples() {
  try {
    const res = await fetch("/api/samples");
    if (res.ok) {
      sampleCache = await res.json();
    }
  } catch (err) {
    console.error("Failed to load sample registry:", err);
  }
}

function loadSample(filename) {
  if (sampleCache[filename]) {
    const codeInput = document.getElementById("codeInput");
    const activeFileName = document.getElementById("activeFileName");
    codeInput.value = sampleCache[filename];
    if (activeFileName) activeFileName.textContent = filename;
    codeInput.dispatchEvent(new Event("input"));
  }
}

function switchTab(tabId) {
  document.querySelectorAll(".tab-link").forEach(btn => btn.classList.remove("active"));
  document.querySelectorAll(".tab-pane").forEach(pane => pane.classList.remove("active"));

  event.currentTarget.classList.add("active");
  const targetPane = document.getElementById(`tab-${tabId}`);
  if (targetPane) {
    targetPane.classList.add("active");
  }
}

async function runPipeline() {
  const codeInput = document.getElementById("codeInput").value;
  const provider = document.getElementById("providerSelect").value;
  const btnAnalyze = document.getElementById("btnAnalyze");
  const statusDot = document.getElementById("statusDot");
  const statusText = document.getElementById("statusText");

  if (!codeInput.trim()) {
    alert("Please provide source code for analysis.");
    return;
  }

  // Set running state
  btnAnalyze.disabled = true;
  btnAnalyze.innerHTML = `
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="spin"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
    <span>Analyzing...</span>
  `;
  statusDot.className = "status-indicator-dot active";
  statusText.textContent = "Pipeline Active";

  setPhaseStatus("running");

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code: codeInput,
        filename: "solution.py",
        language: "python",
        provider: provider
      })
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || "Analysis request failed");
    }

    const data = await response.json();
    currentAnalysisResult = data;
    renderAnalysis(data);

    statusDot.className = "status-indicator-dot done";
    statusText.textContent = `Completed (${data.findings.length} findings)`;
    setPhaseStatus("done");
  } catch (err) {
    statusDot.className = "status-indicator-dot";
    statusText.textContent = "Execution Error";
    alert("Pipeline Error: " + err.message);
    setPhaseStatus("error");
  } finally {
    btnAnalyze.disabled = false;
    btnAnalyze.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
      <span>Run Code Audit</span>
    `;
  }
}

let phaseTimerIds = [];

function setPhaseStatus(state) {
  // Clear any pending transition timers
  phaseTimerIds.forEach(id => clearTimeout(id));
  phaseTimerIds = [];

  const nodes = [
    { id: "node-orch", badge: "badge-orch", run: "ORCHESTRATING", done: "RESOLVED" },
    { id: "node-quality", badge: "badge-quality", run: "PARSING AST", done: "AUDITED" },
    { id: "node-sec", badge: "badge-sec", run: "INSPECTING", done: "AUDITED" },
    { id: "node-refactor", badge: "badge-refactor", run: "SYNTHESIZING", done: "PATCHED" },
    { id: "node-test", badge: "badge-test", run: "GENERATING", done: "GENERATED" }
  ];

  nodes.forEach((n, idx) => {
    const nodeEl = document.getElementById(n.id);
    const badgeEl = document.getElementById(n.badge);
    if (!nodeEl || !badgeEl) return;

    if (state === "running") {
      const tid = setTimeout(() => {
        nodeEl.className = "agent-node active";
        badgeEl.textContent = n.run;
      }, idx * 80);
      phaseTimerIds.push(tid);
    } else if (state === "done") {
      nodeEl.className = "agent-node done";
      badgeEl.textContent = n.done;
    } else {
      nodeEl.className = "agent-node";
      badgeEl.textContent = "STANDBY";
    }
  });
}

function renderAnalysis(data) {
  // 1. KPI Metrics
  document.getElementById("metricSec").textContent = `${data.scores.security}`;
  document.getElementById("barSec").style.width = `${data.scores.security}%`;

  document.getElementById("metricMaint").textContent = `${data.scores.maintainability}`;
  document.getElementById("barMaint").style.width = `${data.scores.maintainability}%`;

  document.getElementById("metricComp").textContent = data.metrics.cyclomatic_complexity;
  document.getElementById("barComp").style.width = `${Math.min(100, data.metrics.cyclomatic_complexity * 10)}%`;

  document.getElementById("overallScore").textContent = `${data.scores.overall}`;
  document.getElementById("barOverall").style.width = `${data.scores.overall}%`;

  // 2. Findings Table
  const findingsCount = document.getElementById("findingsCount");
  const findingsContainer = document.getElementById("findingsContainer");
  const findingsEmpty = document.getElementById("findingsEmpty");
  const findingsTbody = document.getElementById("findingsTbody");

  findingsCount.textContent = data.findings.length;
  findingsTbody.innerHTML = "";

  if (data.findings.length === 0) {
    findingsContainer.style.display = "none";
    findingsEmpty.style.display = "block";
    findingsEmpty.innerHTML = `
      <div class="empty-title">Semua Standar Kualitas & Keamanan Lolos!</div>
      <div class="empty-subtitle">Tidak ditemukan celah kritis OWASP, CWE, maupun pelanggaran gaya penulisan PEP 8.</div>
    `;
  } else {
    findingsEmpty.style.display = "none";
    findingsContainer.style.display = "block";

    data.findings.forEach(f => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><span class="tag-severity ${f.severity}">${f.severity}</span></td>
        <td><span class="finding-rule">${f.rule_id || 'RULE-GEN'}</span></td>
        <td>
          <div class="finding-title-row">${f.title}</div>
          <div class="finding-desc-row">${f.description}</div>
          <div class="finding-remediation">💡 <strong>Rekomendasi Solusi:</strong> ${f.suggestion}</div>
        </td>
        <td><span class="finding-line-tag">${f.line_number ? `L${f.line_number}` : 'N/A'}</span></td>
      `;
      findingsTbody.appendChild(tr);
    });
  }

  // 3. Diff & Refactored Code
  renderDiffView(data.refactor.diff_patch);
  document.getElementById("refactoredCodeDisplay").textContent = data.refactor.refactored_code;

  // 4. Test Suite
  document.getElementById("testCodeDisplay").textContent = data.test_suite.test_code;
  document.getElementById("testCoverageBadge").textContent = `${data.test_suite.test_cases_count} Kasus Uji`;
  document.getElementById("sandboxCard").style.display = "none";

  // 5. Agent Trace
  renderAuditTrail(data.agent_logs);

  // 6. Executive Summary
  renderExecutiveBrief(data);
}

function renderDiffView(diffPatch) {
  const diffDisplay = document.getElementById("diffDisplay");
  if (!diffPatch || diffPatch.startsWith("No modifications")) {
    diffDisplay.innerHTML = `<code>Kode sudah bersih dan memenuhi standar kualitas (tidak memerlukan perubahan).</code>`;
    return;
  }

  const lines = diffPatch.split("\n");
  const formattedLines = lines.map(line => {
    const escaped = escapeHtml(line);
    if (line.startsWith("+") && !line.startsWith("+++")) {
      return `<span class="diff-line-add">${escaped}</span>`;
    } else if (line.startsWith("-") && !line.startsWith("---")) {
      return `<span class="diff-line-del">${escaped}</span>`;
    }
    return `<span>${escaped}</span>`;
  });

  diffDisplay.innerHTML = `<code>${formattedLines.join("\n")}</code>`;
}

function renderAuditTrail(logs) {
  const container = document.getElementById("traceContainer");
  container.innerHTML = "";

  logs.forEach(agentItem => {
    const card = document.createElement("div");
    card.className = "trace-item-card";
    const logLines = agentItem.logs.map(l => `<div class="trace-log-line">${escapeHtml(l)}</div>`).join("");
    card.innerHTML = `
      <div class="trace-item-header">
        <span class="trace-agent-name">${agentItem.agent}</span>
        <span class="trace-agent-role">${agentItem.role}</span>
      </div>
      <div>${logLines}</div>
    `;
    container.appendChild(card);
  });
}

function renderExecutiveBrief(data) {
  const container = document.getElementById("summaryContent");
  const isApproved = data.scores.overall >= 80;
  container.innerHTML = `
    <div style="margin-bottom: 12px;">
      <strong>Status Evaluasi:</strong> 
      <span style="color: ${isApproved ? 'var(--color-success)' : 'var(--color-critical)'}; font-weight: 600;">
        ${isApproved ? 'DISETUJUI UNTUK PRODUCTION (LAYAK RILIS)' : 'PERLU PERBAIKAN (CELAH RISIKO DITEMUKAN)'}
      </span>
    </div>
    <p>Skor indeks kesehatan kode mencapai <strong>${data.scores.overall}/100</strong> berdasarkan empat gerbang evaluasi:</p>
    <ul>
      <li><strong>Postur Keamanan (${data.scores.security}/100):</strong> Mengevaluasi celah kerentanan OWASP Top 10, kebocoran kunci rahasia/token, dan eksekusi perintah berbahaya.</li>
      <li><strong>Keterpeliharaan Kode (${data.scores.maintainability}/100):</strong> Menguji kepatuhan terhadap standar Clean Code PEP 8 dan pemisahan fungsi (*Single Responsibility*).</li>
      <li><strong>Kompleksitas Siklomatis (${data.metrics.cyclomatic_complexity}):</strong> Mengukur kedalaman percabangan logika (*if/else/loops*) untuk mencegah kode rumit.</li>
      <li><strong>Otomasi Pengujian (${data.test_suite.test_cases_count} skenario):</strong> Paket unit test pytest otomatis telah dirancang mencakup skenario normal, nilai ekstrem (*edge cases*), dan validasi input.</li>
    </ul>
  `;
}

async function runSandboxTests() {
  if (!currentAnalysisResult) {
    alert("Please run code audit first.");
    return;
  }

  const btnRun = document.getElementById("btnRunSandbox");
  btnRun.disabled = true;
  btnRun.innerHTML = `<span>Executing...</span>`;

  const card = document.getElementById("sandboxCard");
  const statusEl = document.getElementById("sandboxStatus");
  const durEl = document.getElementById("sandboxDuration");
  const outputEl = document.getElementById("sandboxOutput");

  try {
    const res = await fetch("/api/run-tests", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code: currentAnalysisResult.refactor.refactored_code,
        test_code: currentAnalysisResult.test_suite.test_code
      })
    });

    const data = await res.json();
    card.style.display = "block";
    statusEl.textContent = data.success ? "PASS (All tests green)" : "FAIL";
    statusEl.className = data.success ? "status-pass" : "status-fail";
    durEl.textContent = `${data.duration_ms} ms (${data.passed} passed, ${data.failed} failed)`;
    outputEl.textContent = data.output;
  } catch (err) {
    alert("Sandbox execution failed: " + err.message);
  } finally {
    btnRun.disabled = false;
    btnRun.innerHTML = `
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
      <span>Execute Sandbox Tests</span>
    `;
  }
}

function copyRefactoredCode() {
  if (!currentAnalysisResult) return;
  navigator.clipboard.writeText(currentAnalysisResult.refactor.refactored_code);
  alert("Refactored code copied to clipboard!");
}

function exportReportJSON() {
  if (!currentAnalysisResult) {
    alert("Run analysis before exporting.");
    return;
  }
  const blob = new Blob([JSON.stringify(currentAnalysisResult, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `codesentinel_audit_${Date.now()}.json`;
  a.click();
}

function exportReportMarkdown() {
  if (!currentAnalysisResult) {
    alert("Run analysis before exporting.");
    return;
  }
  const d = currentAnalysisResult;
  let md = `# CodeSentinel Security & Quality Audit Report\n\n`;
  md += `**Target File**: solution.py\n`;
  md += `**Date**: ${new Date().toISOString()}\n`;
  md += `**Composite Index**: ${d.scores.overall}/100\n\n`;
  md += `## Metric Breakdown\n`;
  md += `- Security Score: ${d.scores.security}/100\n`;
  md += `- Maintainability Score: ${d.scores.maintainability}/100\n`;
  md += `- Cyclomatic Complexity: ${d.metrics.cyclomatic_complexity}\n`;
  md += `- Unit Tests Generated: ${d.test_suite.test_cases_count}\n\n`;
  md += `## Observations (${d.findings.length})\n`;
  d.findings.forEach((f, i) => {
    md += `### ${i+1}. [${f.severity}] ${f.title} (${f.rule_id || 'GEN'})\n`;
    md += `- Line: ${f.line_number || 'N/A'}\n`;
    md += `- Description: ${f.description}\n`;
    md += `- Remediation: ${f.suggestion}\n\n`;
  });

  const blob = new Blob([md], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `codesentinel_report_${Date.now()}.md`;
  a.click();
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
