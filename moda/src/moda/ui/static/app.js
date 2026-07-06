const state = {
  file: null,
  result: null,
};

const el = {
  healthDot: document.querySelector("#healthDot"),
  healthText: document.querySelector("#healthText"),
  dropzone: document.querySelector("#dropzone"),
  fileInput: document.querySelector("#fileInput"),
  dropTitle: document.querySelector("#dropTitle"),
  dropMeta: document.querySelector("#dropMeta"),
  analyzeBtn: document.querySelector("#analyzeBtn"),
  resetBtn: document.querySelector("#resetBtn"),
  yaraToggle: document.querySelector("#yaraToggle"),
  fileLedger: document.querySelector("#fileLedger"),
  riskCanvas: document.querySelector("#riskCanvas"),
  riskScore: document.querySelector("#riskScore"),
  riskLabel: document.querySelector("#riskLabel"),
  resultTitle: document.querySelector("#resultTitle"),
  findingCount: document.querySelector("#findingCount"),
  iocCount: document.querySelector("#iocCount"),
  yaraCount: document.querySelector("#yaraCount"),
  downloadPdfBtn: document.querySelector("#downloadPdfBtn"),
  factsGrid: document.querySelector("#factsGrid"),
  riskBreakdown: document.querySelector("#riskBreakdown"),
  findingsList: document.querySelector("#findingsList"),
  responseList: document.querySelector("#responseList"),
  iocList: document.querySelector("#iocList"),
  metadataList: document.querySelector("#metadataList"),
  jsonOutput: document.querySelector("#jsonOutput"),
  copyJsonBtn: document.querySelector("#copyJsonBtn"),
  downloadJsonBtn: document.querySelector("#downloadJsonBtn"),
};

const riskColors = {
  low: "#6fcf97",
  medium: "#d6b46a",
  high: "#bd6b44",
  critical: "#e05a47",
};

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "-";
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function drawRisk(score = 0, level = "low", components = []) {
  const ctx = el.riskCanvas.getContext("2d");
  const size = el.riskCanvas.width;
  const center = size / 2;
  const radius = 76;
  const color = riskColors[level] || riskColors.low;
  ctx.clearRect(0, 0, size, size);

  ctx.beginPath();
  ctx.arc(center, center, radius, 0, Math.PI * 2);
  ctx.lineWidth = 13;
  ctx.strokeStyle = "rgba(244, 239, 228, 0.12)";
  ctx.stroke();

  const visibleComponents = components.filter((item) => Number(item.percentage || 0) > 0);
  if (visibleComponents.length) {
    let start = -Math.PI / 2;
    visibleComponents.forEach((component) => {
      const share = Math.min(Number(component.percentage || 0), 100) / 100;
      const end = start + Math.PI * 2 * share;
      ctx.beginPath();
      ctx.arc(center, center, radius, start, end);
      ctx.lineWidth = 13;
      ctx.lineCap = "butt";
      ctx.strokeStyle = component.color || color;
      ctx.stroke();
      start = end;
    });
  } else {
    ctx.beginPath();
    ctx.arc(center, center, radius, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * (score / 100));
    ctx.lineWidth = 13;
    ctx.lineCap = "round";
    ctx.strokeStyle = color;
    ctx.stroke();
  }

  for (let i = 0; i < 34; i += 1) {
    const angle = (i / 34) * Math.PI * 2;
    const inner = radius + 21;
    const outer = radius + 27;
    ctx.beginPath();
    ctx.moveTo(center + Math.cos(angle) * inner, center + Math.sin(angle) * inner);
    ctx.lineTo(center + Math.cos(angle) * outer, center + Math.sin(angle) * outer);
    ctx.strokeStyle = i % 5 === 0 ? "rgba(214, 180, 106, 0.58)" : "rgba(244, 239, 228, 0.16)";
    ctx.lineWidth = 1;
    ctx.stroke();
  }
}

function toast(message) {
  const node = document.createElement("div");
  node.className = "toast";
  node.textContent = message;
  document.body.appendChild(node);
  setTimeout(() => node.remove(), 2600);
}

async function checkHealth() {
  try {
    const response = await fetch("/api/health");
    if (!response.ok) throw new Error("offline");
    el.healthDot.classList.add("ok");
    el.healthText.textContent = "Engine ready";
  } catch {
    el.healthDot.classList.remove("ok");
    el.healthText.textContent = "Engine offline";
  }
}

function setFile(file) {
  state.file = file;
  el.analyzeBtn.disabled = !file;
  el.dropTitle.textContent = file ? file.name : "Drop document";
  el.dropMeta.textContent = file ? formatBytes(file.size) : "Office, RTF, or PDF";
  const rows = el.fileLedger.querySelectorAll("strong");
  rows[0].textContent = file ? file.name : "None";
  rows[1].textContent = file ? formatBytes(file.size) : "-";
}

function reset() {
  state.file = null;
  state.result = null;
  el.fileInput.value = "";
  setFile(null);
  renderResult(null);
}

async function analyze() {
  if (!state.file) return;
  el.analyzeBtn.disabled = true;
  el.analyzeBtn.textContent = "Analyzing";

  try {
    const params = new URLSearchParams();
    params.set("yara", el.yaraToggle.checked ? "1" : "0");
    const response = await fetch(`/api/analyze?${params.toString()}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-Filename": encodeURIComponent(state.file.name),
      },
      body: await state.file.arrayBuffer(),
    });
    const payload = await response.json();
    if (!response.ok || payload.error) {
      throw new Error(payload.error || "Analysis failed");
    }
    state.result = payload;
    renderResult(payload);
  } catch (error) {
    toast(error.message);
  } finally {
    el.analyzeBtn.disabled = false;
    el.analyzeBtn.innerHTML = '<span aria-hidden="true">◆</span> Analyze';
  }
}

function renderResult(result) {
  if (!result) {
    drawRisk(0, "low");
    el.riskScore.textContent = "--";
    el.riskLabel.textContent = "Ready";
    el.resultTitle.textContent = "Awaiting document";
    el.findingCount.textContent = "0";
    el.iocCount.textContent = "0";
    el.yaraCount.textContent = "0";
    el.downloadPdfBtn.disabled = true;
    el.factsGrid.innerHTML = factMarkup([
      ["Type", "-"],
      ["MIME", "-"],
      ["Duration", "-"],
      ["SHA256", "-"],
    ]);
    el.riskBreakdown.innerHTML = '<div class="empty-state compact">No score contributors</div>';
    el.findingsList.className = "empty-state";
    el.findingsList.textContent = "No analysis loaded";
    el.responseList.className = "empty-state";
    el.responseList.textContent = "No response guidance loaded";
    el.iocList.className = "empty-state";
    el.iocList.textContent = "No indicators loaded";
    el.metadataList.className = "empty-state";
    el.metadataList.textContent = "No metadata loaded";
    el.jsonOutput.textContent = "{}";
    return;
  }

  const risk = result.risk || {};
  const fileInfo = result.file_info || {};
  const score = Math.round(Number(risk.score || 0));
  const level = risk.level || "low";
  const components = risk.breakdown?.components || [];
  drawRisk(score, level, components);
  el.riskScore.textContent = String(score);
  el.riskLabel.textContent = level;
  el.resultTitle.textContent = fileInfo.file_name || "Analysis complete";
  el.findingCount.textContent = String((result.findings || []).length);
  el.iocCount.textContent = String((result.iocs || []).length);
  el.yaraCount.textContent = String((result.yara_matches || []).length);
  el.downloadPdfBtn.disabled = false;
  el.factsGrid.innerHTML = factMarkup([
    ["Type", fileInfo.file_type || "-"],
    ["MIME", fileInfo.mime_type || "-"],
    ["Duration", `${Number(result.analysis?.duration_seconds || 0).toFixed(3)}s`],
    ["SHA256", result.hashes?.sha256 || "-"],
  ]);
  renderRiskBreakdown(risk.breakdown || {});
  renderFindings(result.findings || []);
  renderResponse(risk.breakdown || {}, result.recommendations || []);
  renderIocs(result.iocs || []);
  renderMetadata(result.metadata || {});
  el.jsonOutput.textContent = JSON.stringify(result, null, 2);
}

function factMarkup(items) {
  return items
    .map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`)
    .join("");
}

function renderRiskBreakdown(breakdown) {
  const components = breakdown.components || [];
  if (!components.length) {
    el.riskBreakdown.innerHTML = '<div class="empty-state compact">No score contributors</div>';
    return;
  }

  el.riskBreakdown.innerHTML = components
    .map((component) => {
      const percentage = Number(component.percentage || 0);
      const reasons = Array.isArray(component.reasons) ? component.reasons.slice(0, 5) : [];
      return `
        <article class="risk-component" style="--component-color: ${escapeHtml(component.color || "#6fcf97")}">
          <div class="risk-component-head">
            <span class="component-swatch" aria-hidden="true"></span>
            <strong>${escapeHtml(component.label || component.key || "Risk")}</strong>
            <b>${percentage.toFixed(1)}%</b>
          </div>
          <div class="component-bar" aria-hidden="true">
            <span style="width: ${Math.max(1, Math.min(percentage, 100))}%"></span>
          </div>
          <p>${escapeHtml(component.description || "")}</p>
          ${
            reasons.length
              ? `<small>${escapeHtml(reasons.join(" | "))}</small>`
              : ""
          }
        </article>
      `;
    })
    .join("");
}

function renderFindings(findings) {
  if (!findings.length) {
    el.findingsList.className = "empty-state";
    el.findingsList.textContent = "No findings";
    return;
  }
  el.findingsList.className = "";
  el.findingsList.innerHTML = findings
    .map(
      (finding) => `
        <article class="finding-item">
          <div class="finding-head">
            <strong>${escapeHtml(finding.title)}</strong>
            <span class="severity ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
          </div>
          <p>${escapeHtml(finding.description)}</p>
          <small>${escapeHtml(finding.analyzer)}</small>
        </article>
      `,
    )
    .join("");
}

function renderResponse(breakdown, recommendations) {
  const impacts = breakdown.potential_impacts || [];
  const recovery = breakdown.recovery_steps || [];
  if (!impacts.length && !recovery.length && !recommendations.length) {
    el.responseList.className = "empty-state";
    el.responseList.textContent = "No response guidance";
    return;
  }

  el.responseList.className = "response-grid";
  el.responseList.innerHTML = `
    <section>
      <h3>Potential Impact</h3>
      ${listMarkup(impacts)}
    </section>
    <section>
      <h3>Recovery</h3>
      ${listMarkup(recovery)}
    </section>
    <section>
      <h3>Recommendations</h3>
      ${listMarkup(recommendations)}
    </section>
  `;
}

function listMarkup(items) {
  if (!items.length) return '<p class="muted-line">None</p>';
  return `<ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

function renderIocs(iocs) {
  if (!iocs.length) {
    el.iocList.className = "empty-state";
    el.iocList.textContent = "No indicators";
    return;
  }
  el.iocList.className = "";
  el.iocList.innerHTML = iocs
    .map(
      (ioc) => `
        <div class="ioc-item">
          <div>
            <strong>${escapeHtml(ioc.value)}</strong>
            <small>${escapeHtml(ioc.source)}</small>
          </div>
          <span class="severity">${escapeHtml(ioc.ioc_type)}</span>
        </div>
      `,
    )
    .join("");
}

function renderMetadata(metadata) {
  const entries = Object.entries(metadata).filter(([, value]) => value !== null && value !== "");
  if (!entries.length) {
    el.metadataList.className = "empty-state";
    el.metadataList.textContent = "No metadata";
    return;
  }
  el.metadataList.className = "";
  el.metadataList.innerHTML = entries
    .map(
      ([key, value]) => `
        <div class="meta-item">
          <span>${escapeHtml(key)}</span>
          <strong>${escapeHtml(value)}</strong>
        </div>
      `,
    )
    .join("");
}

document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((tab) => tab.classList.remove("is-active"));
    document.querySelectorAll(".tab-panel").forEach((panel) => panel.classList.remove("is-active"));
    button.classList.add("is-active");
    document.querySelector(`#${button.dataset.tab}`).classList.add("is-active");
  });
});

el.fileInput.addEventListener("change", (event) => {
  setFile(event.target.files[0] || null);
});

["dragenter", "dragover"].forEach((name) => {
  el.dropzone.addEventListener(name, (event) => {
    event.preventDefault();
    el.dropzone.classList.add("is-dragging");
  });
});

["dragleave", "drop"].forEach((name) => {
  el.dropzone.addEventListener(name, (event) => {
    event.preventDefault();
    el.dropzone.classList.remove("is-dragging");
  });
});

el.dropzone.addEventListener("drop", (event) => {
  setFile(event.dataTransfer.files[0] || null);
});

el.analyzeBtn.addEventListener("click", analyze);
el.resetBtn.addEventListener("click", reset);

el.downloadPdfBtn.addEventListener("click", async () => {
  if (!state.file || !state.result) return;
  el.downloadPdfBtn.disabled = true;
  el.downloadPdfBtn.textContent = "Preparing";
  try {
    const params = new URLSearchParams();
    params.set("yara", el.yaraToggle.checked ? "1" : "0");
    const response = await fetch(`/api/report?${params.toString()}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-Filename": encodeURIComponent(state.file.name),
      },
      body: await state.file.arrayBuffer(),
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.error || "Report failed");
    }
    const blob = await response.blob();
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `${state.result.file_info?.file_name || "moda"}-report.pdf`;
    link.click();
    URL.revokeObjectURL(link.href);
  } catch (error) {
    toast(error.message);
  } finally {
    el.downloadPdfBtn.disabled = false;
    el.downloadPdfBtn.textContent = "PDF Report";
  }
});

el.copyJsonBtn.addEventListener("click", async () => {
  await navigator.clipboard.writeText(el.jsonOutput.textContent);
  toast("JSON copied");
});

el.downloadJsonBtn.addEventListener("click", () => {
  const blob = new Blob([el.jsonOutput.textContent], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `${state.result?.file_info?.file_name || "moda"}-analysis.json`;
  link.click();
  URL.revokeObjectURL(link.href);
});

drawRisk(0, "low");
checkHealth();
