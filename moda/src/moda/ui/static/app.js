const state = {
  file: null,
  result: null,
  lang: localStorage.getItem("moda_lang") || "en",
  health: "checking",
  isAnalyzing: false,
  isPreparingPdf: false,
  isChatting: false,
  chatConfigured: false,
  chatProvider: null,
  chatModel: null,
  chatMessages: [],
  accessToken: new URLSearchParams(window.location.search).get("token") || "",
};

const translations = {
  en: {
    brandSubtitle: "Document threat analysis",
    checkingEngine: "Checking engine",
    engineReady: "Engine ready",
    engineOffline: "Engine offline",
    intake: "Intake",
    reset: "Reset",
    dropDocument: "Drop document",
    acceptedTypes: "Office, RTF, or PDF",
    yaraScan: "YARA scan",
    analyze: "Analyze",
    analyzing: "Analyzing",
    selected: "Selected",
    none: "None",
    size: "Size",
    ready: "Ready",
    analysis: "Analysis",
    awaitingDocument: "Awaiting document",
    analysisComplete: "Analysis complete",
    riskFindings: "Risk Findings",
    oleStreams: "OLE Streams",
    iocs: "IOCs",
    yara: "YARA",
    pdfReport: "PDF Report",
    preparing: "Preparing",
    type: "Type",
    mime: "MIME",
    duration: "Duration",
    sha256: "SHA256",
    noScoreContributors: "No score contributors",
    findings: "Findings",
    response: "Response",
    metadata: "Metadata",
    json: "JSON",
    noAnalysisLoaded: "No analysis loaded",
    noResponseLoaded: "No response guidance loaded",
    noYaraLoaded: "No YARA matches loaded",
    noIndicatorsLoaded: "No indicators loaded",
    noMetadataLoaded: "No metadata loaded",
    copyJson: "Copy JSON",
    download: "Download",
    noFindings: "No findings",
    whyItMatters: "Why it matters",
    possibleImpact: "Possible impact",
    howToValidate: "How to validate",
    evidence: "Evidence",
    potentialImpact: "Potential Impact",
    recovery: "Recovery",
    recommendations: "Recommendations",
    noResponseGuidance: "No response guidance",
    noYaraMatches: "No YARA matches",
    yaraWarning: "YARA Compile/Scan Warning",
    yaraDefaultDescription: "YARA rule matched this file.",
    noTags: "no tags",
    strings: "strings",
    noIndicators: "No indicators",
    noMetadata: "No metadata",
    jsonCopied: "JSON copied",
    reportFailed: "Report failed",
    analysisFailed: "Analysis failed",
    reportAssistant: "Report assistant",
    askAboutAnalysis: "Ask about this analysis",
    apiKeyRequired: "API key required",
    chatbotReady: "ready",
    chatAwaitingAnalysis: "Analyze a document to ask evidence-based questions.",
    chatNeedsKey: "Configure an API key on the server to enable the report assistant.",
    chatReadyMessage: "I can explain this report's score, findings, evidence, IOCs, YARA matches, and analysis limitations.",
    chatPlaceholder: "Ask about findings, evidence, IOCs, or remediation…",
    ask: "Ask",
    thinking: "Reviewing evidence…",
    chatFailed: "The report assistant could not answer",
    chatPrivacy: "The structured report context—not the uploaded file—is sent to the configured provider.",
    questionWhy: "Why did this file receive this risk score?",
    questionPriority: "Which finding should I investigate first?",
    questionErrors: "Did any analysis errors limit this result?",
    complete: "complete",
    partial: "partial analysis",
    inconclusive: "inconclusive",
    risk: {
      low: "low",
      medium: "medium",
      high: "high",
      critical: "critical",
    },
    severity: {
      info: "info",
      low: "low",
      medium: "medium",
      high: "high",
      critical: "critical",
    },
  },
  tr: {
    brandSubtitle: "Doküman tehdit analizi",
    checkingEngine: "Motor kontrol ediliyor",
    engineReady: "Motor hazır",
    engineOffline: "Motor çevrimdışı",
    intake: "Dosya alımı",
    reset: "Sıfırla",
    dropDocument: "Dokümanı bırak",
    acceptedTypes: "Office, RTF veya PDF",
    yaraScan: "YARA taraması",
    analyze: "Analiz et",
    analyzing: "Analiz ediliyor",
    selected: "Seçilen",
    none: "Yok",
    size: "Boyut",
    ready: "Hazır",
    analysis: "Analiz",
    awaitingDocument: "Doküman bekleniyor",
    analysisComplete: "Analiz tamamlandı",
    riskFindings: "Risk bulguları",
    oleStreams: "OLE streamleri",
    iocs: "IOC'ler",
    yara: "YARA",
    pdfReport: "PDF raporu",
    preparing: "Hazırlanıyor",
    type: "Tür",
    mime: "MIME",
    duration: "Süre",
    sha256: "SHA256",
    noScoreContributors: "Skora katkı yok",
    findings: "Bulgular",
    response: "Müdahale",
    metadata: "Metadata",
    json: "JSON",
    noAnalysisLoaded: "Analiz yüklenmedi",
    noResponseLoaded: "Müdahale önerisi yüklenmedi",
    noYaraLoaded: "YARA eşleşmesi yüklenmedi",
    noIndicatorsLoaded: "Gösterge yüklenmedi",
    noMetadataLoaded: "Metadata yüklenmedi",
    copyJson: "JSON kopyala",
    download: "İndir",
    noFindings: "Bulgu yok",
    whyItMatters: "Neden önemli",
    possibleImpact: "Olası etki",
    howToValidate: "Nasıl doğrulanır",
    evidence: "Kanıt",
    potentialImpact: "Olası etki",
    recovery: "Toparlanma",
    recommendations: "Öneriler",
    noResponseGuidance: "Müdahale önerisi yok",
    noYaraMatches: "YARA eşleşmesi yok",
    yaraWarning: "YARA derleme/tarama uyarısı",
    yaraDefaultDescription: "Bu dosya bir YARA kuralıyla eşleşti.",
    noTags: "etiket yok",
    strings: "string",
    noIndicators: "Gösterge yok",
    noMetadata: "Metadata yok",
    jsonCopied: "JSON kopyalandı",
    reportFailed: "Rapor oluşturulamadı",
    analysisFailed: "Analiz başarısız",
    reportAssistant: "Rapor asistanı",
    askAboutAnalysis: "Bu analiz hakkında soru sor",
    apiKeyRequired: "API anahtarı gerekli",
    chatbotReady: "hazır",
    chatAwaitingAnalysis: "Kanıta dayalı sorular sormak için bir dokümanı analiz et.",
    chatNeedsKey: "Rapor asistanını etkinleştirmek için sunucuda API anahtarını yapılandır.",
    chatReadyMessage: "Bu raporun skorunu, bulgularını, kanıtlarını, IOC'lerini, YARA eşleşmelerini ve analiz sınırlamalarını açıklayabilirim.",
    chatPlaceholder: "Bulgu, kanıt, IOC veya iyileştirme hakkında sor…",
    ask: "Sor",
    thinking: "Kanıtlar inceleniyor…",
    chatFailed: "Rapor asistanı cevap veremedi",
    chatPrivacy: "Yapılandırılmış rapor bağlamı sağlayıcıya gönderilir; yüklenen dosyanın kendisi gönderilmez.",
    questionWhy: "Bu dosya neden bu risk skorunu aldı?",
    questionPriority: "Önce hangi bulguyu araştırmalıyım?",
    questionErrors: "Analiz hataları bu sonucu sınırlandırdı mı?",
    complete: "tamamlandı",
    partial: "kısmi analiz",
    inconclusive: "sonuçlandırılamadı",
    risk: {
      low: "düşük",
      medium: "orta",
      high: "yüksek",
      critical: "kritik",
    },
    severity: {
      info: "bilgi",
      low: "düşük",
      medium: "orta",
      high: "yüksek",
      critical: "kritik",
    },
  },
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
  streamCount: document.querySelector("#streamCount"),
  iocCount: document.querySelector("#iocCount"),
  yaraCount: document.querySelector("#yaraCount"),
  downloadPdfBtn: document.querySelector("#downloadPdfBtn"),
  factsGrid: document.querySelector("#factsGrid"),
  riskBreakdown: document.querySelector("#riskBreakdown"),
  findingsList: document.querySelector("#findingsList"),
  responseList: document.querySelector("#responseList"),
  yaraList: document.querySelector("#yaraList"),
  iocList: document.querySelector("#iocList"),
  metadataList: document.querySelector("#metadataList"),
  jsonOutput: document.querySelector("#jsonOutput"),
  copyJsonBtn: document.querySelector("#copyJsonBtn"),
  downloadJsonBtn: document.querySelector("#downloadJsonBtn"),
  chatEyebrow: document.querySelector("#chatEyebrow"),
  chatTitle: document.querySelector("#chatTitle"),
  chatStatus: document.querySelector("#chatStatus"),
  chatMessages: document.querySelector("#chatMessages"),
  chatSuggestions: document.querySelector("#chatSuggestions"),
  chatForm: document.querySelector("#chatForm"),
  chatInput: document.querySelector("#chatInput"),
  chatSendBtn: document.querySelector("#chatSendBtn"),
  chatPrivacy: document.querySelector("#chatPrivacy"),
  langButtons: document.querySelectorAll(".lang-btn"),
};

const riskColors = {
  low: "#42c98b",
  medium: "#f0b44d",
  high: "#f07848",
  critical: "#ef5b67",
};

function t(key) {
  const dictionary = translations[state.lang] || translations.en;
  return key.split(".").reduce((value, part) => value?.[part], dictionary) ?? key;
}

function buttonMarkup(label, glyph = "") {
  return `${glyph ? `<span aria-hidden="true">${glyph}</span>` : ""}${escapeHtml(label)}`;
}

function riskLabel(level) {
  return t(`risk.${level}`) || level;
}

function severityLabel(severity) {
  return t(`severity.${severity}`) || severity;
}

function renderHealth() {
  el.healthText.textContent = t(
    state.health === "ready"
      ? "engineReady"
      : state.health === "offline"
        ? "engineOffline"
        : "checkingEngine",
  );
}

function applyTranslations() {
  document.documentElement.lang = state.lang === "tr" ? "tr" : "en";
  document.querySelector(".brand-lockup p").textContent = t("brandSubtitle");
  document.querySelector(".panel-title span").textContent = t("intake");
  el.resetBtn.title = t("reset");
  el.resetBtn.setAttribute("aria-label", t("reset"));
  document.querySelector(".switch-row span").textContent = t("yaraScan");
  document.querySelector(".eyebrow").textContent = t("analysis");
  const metricLabels = document.querySelectorAll(".metric-row span");
  metricLabels[0].textContent = t("riskFindings");
  metricLabels[1].textContent = t("oleStreams");
  metricLabels[2].textContent = t("iocs");
  metricLabels[3].textContent = t("yara");
  el.copyJsonBtn.textContent = t("copyJson");
  el.downloadJsonBtn.textContent = t("download");
  el.chatEyebrow.textContent = t("reportAssistant");
  el.chatTitle.textContent = t("askAboutAnalysis");
  el.chatInput.placeholder = t("chatPlaceholder");
  el.chatPrivacy.textContent = t("chatPrivacy");
  const suggestionKeys = ["questionWhy", "questionPriority", "questionErrors"];
  el.chatSuggestions.querySelectorAll("button").forEach((button, index) => {
    button.textContent = t(suggestionKeys[index]);
  });
  document.querySelectorAll(".tab").forEach((button) => {
    const key = button.dataset.tab;
    button.textContent = key === "iocs" ? t("iocs") : t(key);
  });
  el.langButtons.forEach((button) => {
    const isActive = button.dataset.lang === state.lang;
    button.classList.toggle("is-active", isActive);
    button.setAttribute("aria-pressed", String(isActive));
  });
  renderHealth();
  setFile(state.file);
  renderResult(state.result);
  renderChat();
}

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

function apiHeaders(extra = {}) {
  return state.accessToken ? { ...extra, "X-MODA-Token": state.accessToken } : extra;
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
  ctx.strokeStyle = "rgba(185, 201, 224, 0.1)";
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
    ctx.strokeStyle = i % 5 === 0 ? "rgba(119, 160, 255, 0.42)" : "rgba(185, 201, 224, 0.12)";
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
    const payload = await response.json();
    state.health = "ready";
    state.chatConfigured = Boolean(payload.chatbot?.configured);
    state.chatProvider = payload.chatbot?.provider || null;
    state.chatModel = payload.chatbot?.model || null;
    el.healthDot.classList.add("ok");
    el.healthDot.classList.remove("offline");
  } catch {
    state.health = "offline";
    state.chatConfigured = false;
    el.healthDot.classList.remove("ok");
    el.healthDot.classList.add("offline");
  }
  renderHealth();
  renderChat();
}

function setFile(file) {
  state.file = file;
  el.dropzone.classList.toggle("has-file", Boolean(file));
  el.analyzeBtn.disabled = !file || state.isAnalyzing;
  el.analyzeBtn.setAttribute("aria-busy", String(state.isAnalyzing));
  el.analyzeBtn.innerHTML = buttonMarkup(state.isAnalyzing ? t("analyzing") : t("analyze"), "◆");
  el.dropTitle.textContent = file ? file.name : t("dropDocument");
  el.dropMeta.textContent = file ? formatBytes(file.size) : t("acceptedTypes");
  const rows = el.fileLedger.querySelectorAll("strong");
  const labels = el.fileLedger.querySelectorAll("span");
  labels[0].textContent = t("selected");
  labels[1].textContent = t("size");
  rows[0].textContent = file ? file.name : t("none");
  rows[1].textContent = file ? formatBytes(file.size) : "-";
}

function reset() {
  state.file = null;
  state.result = null;
  el.fileInput.value = "";
  setFile(null);
  resetChat();
  renderResult(null);
}

function resetChat() {
  state.chatMessages = [];
  state.isChatting = false;
  el.chatInput.value = "";
  renderChat();
}

async function analyze() {
  if (!state.file) return;
  state.isAnalyzing = true;
  el.analyzeBtn.disabled = true;
  el.analyzeBtn.setAttribute("aria-busy", "true");
  el.analyzeBtn.textContent = t("analyzing");

  try {
    const params = new URLSearchParams();
    params.set("yara", el.yaraToggle.checked ? "1" : "0");
    const response = await fetch(`/api/analyze?${params.toString()}`, {
      method: "POST",
      headers: apiHeaders({
        "Content-Type": "application/octet-stream",
        "X-Filename": encodeURIComponent(state.file.name),
      }),
      body: await state.file.arrayBuffer(),
    });
    const payload = await response.json();
    if (!response.ok || payload.error) {
      throw new Error(payload.error || t("analysisFailed"));
    }
    state.result = payload;
    resetChat();
    renderResult(payload);
  } catch (error) {
    toast(error.message);
  } finally {
    state.isAnalyzing = false;
    setFile(state.file);
  }
}

function renderResult(result) {
  if (!result) {
    drawRisk(0, "low");
    el.riskScore.textContent = "--";
    el.riskLabel.textContent = t("ready");
    el.resultTitle.textContent = t("awaitingDocument");
    el.findingCount.textContent = "0";
    el.streamCount.textContent = "-";
    el.iocCount.textContent = "0";
    el.yaraCount.textContent = "0";
    el.downloadPdfBtn.disabled = true;
    el.downloadPdfBtn.textContent = t("pdfReport");
    el.factsGrid.innerHTML = factMarkup([
      [t("type"), "-"],
      [t("mime"), "-"],
      [t("duration"), "-"],
      [t("sha256"), "-"],
    ]);
    el.riskBreakdown.innerHTML = `<div class="empty-state compact">${escapeHtml(t("noScoreContributors"))}</div>`;
    el.findingsList.className = "empty-state";
    el.findingsList.textContent = t("noAnalysisLoaded");
    el.responseList.className = "empty-state";
    el.responseList.textContent = t("noResponseLoaded");
    el.yaraList.className = "empty-state";
    el.yaraList.textContent = t("noYaraLoaded");
    el.iocList.className = "empty-state";
    el.iocList.textContent = t("noIndicatorsLoaded");
    el.metadataList.className = "empty-state";
    el.metadataList.textContent = t("noMetadataLoaded");
    el.jsonOutput.textContent = "{}";
    renderChat();
    return;
  }

  const risk = result.risk || {};
  const fileInfo = result.file_info || {};
  const score = Math.round(Number(risk.score || 0));
  const level = risk.level || "low";
  const components = risk.breakdown?.components || [];
  drawRisk(score, level, components);
  el.riskScore.textContent = String(score);
  const analysisStatus = risk.analysis_status || result.extra?.analysis_status || "complete";
  el.riskLabel.textContent = `${riskLabel(level)} • ${t(analysisStatus)}`;
  el.resultTitle.textContent = fileInfo.file_name || t("analysisComplete");
  const findings = result.findings || [];
  const riskFindingCount = findings.filter((finding) => finding.title !== "OLE Stream Inventory").length;
  el.findingCount.textContent = String(riskFindingCount);
  el.streamCount.textContent =
    result.extra?.ole_stream_count !== undefined ? String(result.extra.ole_stream_count) : "-";
  el.iocCount.textContent = String((result.iocs || []).length);
  el.yaraCount.textContent = String((result.yara_matches || []).length);
  el.downloadPdfBtn.disabled = false;
  el.downloadPdfBtn.textContent = state.isPreparingPdf ? t("preparing") : t("pdfReport");
  const facts = [
    [t("type"), fileInfo.file_type || "-"],
    [t("mime"), fileInfo.mime_type || "-"],
    [t("duration"), `${Number(result.analysis?.duration_seconds || 0).toFixed(3)}s`],
    [t("sha256"), result.hashes?.sha256 || "-"],
  ];
  if (result.extra?.ole_stream_count !== undefined) {
    facts.splice(2, 0, [t("oleStreams"), result.extra.ole_stream_count]);
  }
  el.factsGrid.innerHTML = factMarkup(facts);
  renderRiskBreakdown(risk.breakdown || {});
  renderFindings(findings);
  renderResponse(risk.breakdown || {}, result.recommendations || []);
  renderYaraMatches(result.yara_matches || [], result.errors || []);
  renderIocs(result.iocs || []);
  renderMetadata(result.metadata || {});
  el.jsonOutput.textContent = JSON.stringify(result, null, 2);
  renderChat();
}

function renderChat() {
  const hasAnalysis = Boolean(state.result?.extra?.analysis_id);
  const canChat = hasAnalysis && state.chatConfigured && !state.isChatting;
  el.chatInput.disabled = !canChat;
  el.chatSendBtn.disabled = !canChat;
  el.chatSendBtn.textContent = state.isChatting ? t("thinking") : t("ask");
  el.chatSuggestions.querySelectorAll("button").forEach((button) => {
    button.disabled = !canChat;
  });

  if (state.chatConfigured) {
    const provider = state.chatProvider || "LLM";
    const model = state.chatModel ? ` · ${state.chatModel}` : "";
    el.chatStatus.textContent = `${provider}${model} · ${t("chatbotReady")}`;
    el.chatStatus.classList.add("is-ready");
  } else {
    el.chatStatus.textContent = t("apiKeyRequired");
    el.chatStatus.classList.remove("is-ready");
  }

  el.chatMessages.replaceChildren();
  if (!hasAnalysis) {
    appendChatEmpty(t("chatAwaitingAnalysis"));
    return;
  }
  if (!state.chatConfigured) {
    appendChatEmpty(t("chatNeedsKey"));
    return;
  }
  if (!state.chatMessages.length) {
    appendChatEmpty(t("chatReadyMessage"));
    return;
  }
  state.chatMessages.forEach((message) => {
    const article = document.createElement("article");
    article.className = `chat-message ${message.role}`;
    const label = document.createElement("strong");
    label.textContent = message.role === "user" ? (state.lang === "tr" ? "Sen" : "You") : "MODA AI";
    const content = document.createElement("p");
    content.textContent = message.content;
    article.append(label, content);
    el.chatMessages.appendChild(article);
  });
  el.chatMessages.scrollTop = el.chatMessages.scrollHeight;
}

function appendChatEmpty(message) {
  const node = document.createElement("div");
  node.className = "chat-empty";
  node.textContent = message;
  el.chatMessages.appendChild(node);
}

async function askChat(question) {
  const cleanQuestion = String(question || "").trim();
  const analysisId = state.result?.extra?.analysis_id;
  if (!cleanQuestion || !analysisId || state.isChatting || !state.chatConfigured) return;

  const history = state.chatMessages.slice(-8).map(({ role, content }) => ({ role, content }));
  state.chatMessages.push({ role: "user", content: cleanQuestion });
  state.isChatting = true;
  el.chatInput.value = "";
  renderChat();

  try {
    const response = await fetch("/api/chat", {
      method: "POST",
      headers: apiHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        analysis_id: analysisId,
        question: cleanQuestion,
        language: state.lang,
        history,
      }),
    });
    const payload = await response.json();
    if (!response.ok || payload.error) {
      throw new Error(payload.error || t("chatFailed"));
    }
    state.chatMessages.push({ role: "assistant", content: payload.answer });
  } catch (error) {
    toast(error.message || t("chatFailed"));
  } finally {
    state.isChatting = false;
    renderChat();
    el.chatInput.focus();
  }
}

function factMarkup(items) {
  return items
    .map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`)
    .join("");
}

function renderRiskBreakdown(breakdown) {
  const components = breakdown.components || [];
  if (!components.length) {
    el.riskBreakdown.innerHTML = `<div class="empty-state compact">${escapeHtml(t("noScoreContributors"))}</div>`;
    return;
  }

  el.riskBreakdown.innerHTML = components
    .map((component) => {
      const percentage = Number(component.percentage || 0);
      const reasons = Array.isArray(component.reasons) ? component.reasons.slice(0, 5) : [];
      return `
        <article class="risk-component" style="--component-color: ${escapeHtml(component.color || "#42c98b")}">
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
    el.findingsList.textContent = t("noFindings");
    return;
  }
  el.findingsList.className = "";
  el.findingsList.innerHTML = findings
    .map(
      (finding) => {
        const guide = findingGuide(finding);
        return `
          <details class="finding-item">
            <summary>
              <div class="finding-head">
                <strong>${escapeHtml(finding.title)}</strong>
                <span class="severity ${escapeHtml(finding.severity)}">${escapeHtml(severityLabel(finding.severity))}</span>
              </div>
              <p>${escapeHtml(finding.description)}</p>
              <small>${escapeHtml(finding.analyzer)}</small>
            </summary>
            <div class="finding-detail-grid">
              ${findingDetailBlock(t("whyItMatters"), guide.why)}
              ${findingDetailBlock(t("possibleImpact"), guide.impact)}
              ${findingDetailBlock(t("howToValidate"), guide.validate)}
              ${findingEvidenceMarkup(finding.details || {})}
            </div>
          </details>
        `;
      },
    )
    .join("");
}

function findingDetailBlock(title, items) {
  const lines = Array.isArray(items) ? items : [items];
  return `
    <section>
      <h4>${escapeHtml(title)}</h4>
      <ul>${lines.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
    </section>
  `;
}

function findingEvidenceMarkup(details) {
  const entries = Object.entries(details).filter(([, value]) => value !== undefined && value !== null);
  if (!entries.length) return "";
  const streamEntries = Array.isArray(details.streams)
    ? details.streams.filter((item) => item && typeof item === "object")
    : [];
  const streamList = streamEntries.length
    ? `
      <div class="stream-list">
        ${streamEntries
          .slice(0, 16)
          .map(
            (stream) => `
              <div>
                <span>${escapeHtml(stream.index ?? "-")}</span>
                <code>${escapeHtml(stream.display_name || stream.name || "-")}</code>
                <b>${escapeHtml(stream.size ?? "-")} bytes</b>
              </div>
            `,
          )
          .join("")}
      </div>
    `
    : "";
  const rows = entries
    .filter(([key]) => key !== "streams")
    .map(
      ([key, value]) => `
        <div>
          <span>${escapeHtml(key)}</span>
          <code>${escapeHtml(formatEvidenceValue(value))}</code>
        </div>
      `,
    )
    .join("");
  return `
    <section class="evidence-block">
      <h4>${escapeHtml(t("evidence"))}</h4>
      ${streamList}
      ${rows ? `<div class="evidence-list">${rows}</div>` : ""}
    </section>
  `;
}

function formatEvidenceValue(value) {
  if (Array.isArray(value)) {
    if (value.every((item) => ["string", "number", "boolean"].includes(typeof item))) {
      return value.join(", ");
    }
    return JSON.stringify(value, null, 2);
  }
  if (value && typeof value === "object") {
    return JSON.stringify(value, null, 2);
  }
  return String(value);
}

function findingGuide(finding) {
  if (state.lang === "tr") {
    return findingGuideTr(finding);
  }
  const title = String(finding.title || "").toLowerCase();
  const details = finding.details || {};

  if (title.includes("ole stream inventory")) {
    const count = details.stream_count || "multiple";
    return {
      why: [
        `The OLE stream table is the file's internal map; Didier's oledump output is based on this same structure.`,
        `A mismatch here usually means a parser view, hidden control-character stream name, or stream/storage counting issue.`,
      ],
      impact: [
        `${count} streams were exposed for inspection; macro streams and WordDocument/PowerPoint streams are the highest-value places to review.`,
      ],
      validate: [
        "Compare index, size, and display_name with oledump.py output.",
        "Inspect Macros/VBA/dir and module streams when macro findings are present.",
      ],
    };
  }
  if (title.includes("vba macros present") || title.includes("macro project")) {
    return {
      why: "VBA projects can run code inside Office documents and are frequently used for initial access.",
      impact: [
        "User interaction can trigger script execution, process launch, or payload download.",
        "Macros can be benign in internal templates, so behavior and source must be reviewed.",
      ],
      validate: [
        "Check extracted macro code for AutoOpen, Document_Open, Workbook_Open, or Presentation_Open.",
        "Look for Shell, CreateObject, WScript.Shell, PowerShell, HTTP clients, or obfuscated strings.",
      ],
    };
  }
  if (title.includes("auto-execution")) {
    return {
      why: "Auto-execution names make code run when the document opens or when common Office events fire.",
      impact: "A user may only need to open or enable content for the malicious path to start.",
      validate: [
        "Confirm the trigger names in the finding details.",
        "Trace the called functions to see whether they launch processes, write files, or contact URLs.",
      ],
    };
  }
  if (title.includes("process execution") || title.includes("command text")) {
    return {
      why: "Office documents should rarely need to launch shell commands or living-off-the-land binaries.",
      impact: "This can lead to code execution, downloader activity, credential theft, or lateral movement.",
      validate: [
        "Review the exact command keyword and surrounding macro/string context.",
        "Treat PowerShell, mshta, rundll32, regsvr32, certutil, and cmd.exe as high-risk in documents.",
      ],
    };
  }
  if (title.includes("embedded")) {
    return {
      why: "Embedded payloads can hide scripts, nested documents, OLE objects, or executables inside the carrier file.",
      impact: "The document may drop or open a second-stage file after user interaction or exploit execution.",
      validate: [
        "Review the embedded type, offset/name, entropy, and file signature.",
        "Extract the embedded object in an isolated lab and analyze it separately.",
      ],
    };
  }
  if (title.includes("relationship") || title.includes("external link")) {
    return {
      why: "External relationships allow Office to retrieve templates, objects, or content from another location.",
      impact: "The document can change behavior after delivery or fetch a remote payload.",
      validate: [
        "Review target URLs, UNC paths, file links, and relationship type.",
        "Check proxy/DNS/mail telemetry for the extracted target.",
      ],
    };
  }
  if (title.includes("yara rule match")) {
    return {
      why: "A YARA hit means the file matched a known static pattern from the configured rule set.",
      impact: "The matched rule can indicate a known malware family, exploit pattern, or suspicious structure.",
      validate: [
        "Review the rule namespace, tags, and matched string count.",
        "Correlate the rule name with other findings before assigning final confidence.",
      ],
    };
  }
  if (title.includes("suspicious document author")) {
    return {
      why: "Generic author values are common in automated builders and sample-generation environments.",
      impact: "Metadata alone is weak evidence, but it can support stronger macro, relationship, or payload findings.",
      validate: [
        "Compare author and last-modified fields with the expected sender or organization.",
        "Do not classify as malicious from metadata alone.",
      ],
    };
  }
  if (title.includes("office exploit protocol") || title.includes("activex") || title.includes("dde")) {
    return {
      why: "These markers are associated with Office exploit chains or active content that can cross trust boundaries.",
      impact: "The file may trigger payload loading, protocol handler abuse, or legacy component exploitation.",
      validate: [
        "Inspect the exact protocol, classid, DDE text, or ActiveX marker.",
        "Open only in an isolated sandbox and correlate with process/network telemetry.",
      ],
    };
  }
  return {
    why: `This ${finding.severity || "info"} finding contributed to the document's static risk assessment.`,
    impact: "Impact depends on whether this signal combines with macros, remote content, embedded payloads, or exploit markers.",
    validate: [
      "Review the evidence fields and surrounding extracted text.",
      "Correlate with IOCs, YARA matches, sender context, and sandbox behavior.",
    ],
  };
}

function findingGuideTr(finding) {
  const title = String(finding.title || "").toLowerCase();
  const details = finding.details || {};

  if (title.includes("ole stream inventory")) {
    const count = details.stream_count || "birden fazla";
    return {
      why: [
        "OLE stream tablosu dosyanın iç haritasıdır; oledump çıktısı da aynı yapıya dayanır.",
        "Buradaki uyumsuzluk gizli stream adı, parser farkı veya stream/storage sayımıyla ilgili olabilir.",
      ],
      impact: [
        `${count} stream incelemeye açıldı; macro streamleri ve WordDocument/PowerPoint streamleri önceliklidir.`,
      ],
      validate: [
        "Index, boyut ve display_name alanlarını oledump.py çıktısıyla karşılaştır.",
        "Makro bulgusu varsa Macros/VBA/dir ve modül streamlerini incele.",
      ],
    };
  }
  if (title.includes("vba macros present") || title.includes("macro project")) {
    return {
      why: "VBA projeleri Office dokümanı içinde kod çalıştırabilir ve ilk erişim için sık kullanılır.",
      impact: [
        "Kullanıcı etkileşimi process başlatma, payload indirme veya script çalıştırmayı tetikleyebilir.",
        "Makrolar kurumsal şablonlarda meşru olabilir; davranış ve kaynak birlikte değerlendirilmelidir.",
      ],
      validate: [
        "AutoOpen, Document_Open, Workbook_Open veya Presentation_Open tetikleyicilerini kontrol et.",
        "Shell, CreateObject, WScript.Shell, PowerShell, HTTP istemcisi veya obfuscation izlerini ara.",
      ],
    };
  }
  if (title.includes("auto-execution")) {
    return {
      why: "Auto-execution isimleri doküman açıldığında veya Office olayları tetiklendiğinde kod çalıştırabilir.",
      impact: "Kötü amaçlı akışın başlaması için kullanıcının dosyayı açması veya içeriği etkinleştirmesi yeterli olabilir.",
      validate: ["Tetikleyici isimlerini bulgu detaylarında doğrula.", "Çağrılan fonksiyonların dosya, process veya ağ davranışına gidip gitmediğini izle."],
    };
  }
  if (title.includes("process execution") || title.includes("command text")) {
    return {
      why: "Office dokümanlarının shell komutu veya living-off-the-land araçları çağırması beklenen bir davranış değildir.",
      impact: "Kod çalıştırma, downloader aktivitesi, kimlik bilgisi hırsızlığı veya yatay hareket riski doğurabilir.",
      validate: ["Komut kelimesini ve çevresindeki macro/string bağlamını incele.", "PowerShell, mshta, rundll32, regsvr32, certutil ve cmd.exe geçişlerini yüksek riskli değerlendir."],
    };
  }
  if (title.includes("embedded")) {
    return {
      why: "Gömülü payloadlar taşıyıcı dosyanın içinde script, nested doküman, OLE nesnesi veya çalıştırılabilir saklayabilir.",
      impact: "Doküman kullanıcı etkileşimi veya exploit sonrası ikinci aşama dosya bırakabilir/açabilir.",
      validate: ["Gömülü tür, offset/ad, entropy ve dosya imzasını kontrol et.", "Nesneyi izole laboratuvarda çıkarıp ayrı analiz et."],
    };
  }
  if (title.includes("relationship") || title.includes("external link")) {
    return {
      why: "External relationship yapıları Office'in dışarıdan template, nesne veya içerik çekmesine izin verir.",
      impact: "Dosya teslim edildikten sonra davranış değiştirebilir veya uzak payload alabilir.",
      validate: ["URL, UNC path, file link ve ilişki türünü incele.", "Proxy, DNS ve mail telemetrisinde hedefi ara."],
    };
  }
  if (title.includes("yara rule match")) {
    return {
      why: "YARA eşleşmesi dosyanın yapılandırılmış kural setindeki bilinen bir statik paterne uyduğunu gösterir.",
      impact: "Kural adı bilinen aile, exploit paterni veya şüpheli yapı hakkında ipucu verebilir.",
      validate: ["Rule namespace, tag ve eşleşen string sayısını gözden geçir.", "Son güven kararı için kuralı diğer bulgularla korele et."],
    };
  }
  if (title.includes("suspicious document author")) {
    return {
      why: "Jenerik author değerleri otomatik builder veya örnek üretim ortamlarında sık görülür.",
      impact: "Metadata tek başına zayıf kanıttır; macro, ilişki veya payload bulgularını destekleyebilir.",
      validate: ["Author ve last-modified alanlarını beklenen gönderen/kurumla karşılaştır.", "Sadece metadata ile zararlı sınıflandırma yapma."],
    };
  }
  if (title.includes("office exploit protocol") || title.includes("activex") || title.includes("dde")) {
    return {
      why: "Bu markerlar Office exploit zincirleri veya güven sınırını aşabilen aktif içerikle ilişkilidir.",
      impact: "Dosya payload yükleme, protocol handler kötüye kullanımı veya eski bileşen istismarını tetikleyebilir.",
      validate: ["Protocol, classid, DDE metni veya ActiveX markerını netleştir.", "Sadece izole sandbox içinde aç ve process/ağ telemetrisiyle doğrula."],
    };
  }
  return {
    why: `Bu ${severityLabel(finding.severity || "info")} bulgu statik risk değerlendirmesine katkı verdi.`,
    impact: "Etki, sinyalin makro, uzak içerik, gömülü payload veya exploit markerlarıyla birleşip birleşmediğine bağlıdır.",
    validate: ["Kanıt alanlarını ve çevresindeki çıkarılmış metni incele.", "IOC, YARA eşleşmesi, gönderen bağlamı ve sandbox davranışıyla korele et."],
  };
}

function renderResponse(breakdown, recommendations) {
  const impacts = breakdown.potential_impacts || [];
  const recovery = breakdown.recovery_steps || [];
  if (!impacts.length && !recovery.length && !recommendations.length) {
    el.responseList.className = "empty-state";
    el.responseList.textContent = t("noResponseGuidance");
    return;
  }

  el.responseList.className = "response-grid";
  el.responseList.innerHTML = `
    <section>
      <h3>${escapeHtml(t("potentialImpact"))}</h3>
      ${listMarkup(impacts)}
    </section>
    <section>
      <h3>${escapeHtml(t("recovery"))}</h3>
      ${listMarkup(recovery)}
    </section>
    <section>
      <h3>${escapeHtml(t("recommendations"))}</h3>
      ${listMarkup(recommendations)}
    </section>
  `;
}

function listMarkup(items) {
  if (!items.length) return `<p class="muted-line">${escapeHtml(t("none"))}</p>`;
  return `<ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

function renderYaraMatches(matches, errors) {
  const yaraErrors = errors;
  if (!matches.length && !yaraErrors.length) {
    el.yaraList.className = "empty-state";
    el.yaraList.textContent = t("noYaraMatches");
    return;
  }

  el.yaraList.className = "";
  const matchMarkup = matches
    .map((match) => {
      const severity = match.meta?.severity || "medium";
      const tags = Array.isArray(match.tags) && match.tags.length ? match.tags.join(", ") : t("noTags");
      return `
        <article class="finding-item">
          <div class="finding-head">
            <strong>${escapeHtml(match.rule_name)}</strong>
            <span class="severity ${escapeHtml(severity)}">${escapeHtml(severityLabel(severity))}</span>
          </div>
          <p>${escapeHtml(match.meta?.description || t("yaraDefaultDescription"))}</p>
          <small>${escapeHtml(match.rule_namespace)} | ${escapeHtml(tags)} | ${escapeHtml(t("strings"))}: ${escapeHtml(match.strings_matched_count || 0)}</small>
        </article>
      `;
    })
    .join("");
  const errorMarkup = yaraErrors
    .map(
      (error) => `
        <article class="finding-item">
          <div class="finding-head">
            <strong>${escapeHtml(t("yaraWarning"))}</strong>
            <span class="severity medium">${escapeHtml(severityLabel("medium"))}</span>
          </div>
          <p>${escapeHtml(error)}</p>
          <small>YaraScanner</small>
        </article>
      `,
    )
    .join("");
  el.yaraList.innerHTML = matchMarkup + errorMarkup;
}

function renderIocs(iocs) {
  if (!iocs.length) {
    el.iocList.className = "empty-state";
    el.iocList.textContent = t("noIndicators");
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
    el.metadataList.textContent = t("noMetadata");
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

const tabs = [...document.querySelectorAll(".tab")];

function activateTab(button) {
  tabs.forEach((tab) => {
    const isActive = tab === button;
    tab.classList.toggle("is-active", isActive);
    tab.setAttribute("aria-selected", String(isActive));
    tab.tabIndex = isActive ? 0 : -1;
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    const isActive = panel.id === button.dataset.tab;
    panel.classList.toggle("is-active", isActive);
    panel.hidden = !isActive;
  });
}

tabs.forEach((button, index) => {
  button.addEventListener("click", () => {
    activateTab(button);
  });
  button.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    let nextIndex = index;
    if (event.key === "ArrowRight") nextIndex = (index + 1) % tabs.length;
    if (event.key === "ArrowLeft") nextIndex = (index - 1 + tabs.length) % tabs.length;
    if (event.key === "Home") nextIndex = 0;
    if (event.key === "End") nextIndex = tabs.length - 1;
    activateTab(tabs[nextIndex]);
    tabs[nextIndex].focus();
  });
});

activateTab(tabs.find((tab) => tab.classList.contains("is-active")) || tabs[0]);

el.langButtons.forEach((button) => {
  button.addEventListener("click", () => {
    state.lang = button.dataset.lang === "tr" ? "tr" : "en";
    localStorage.setItem("moda_lang", state.lang);
    applyTranslations();
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
  state.isPreparingPdf = true;
  el.downloadPdfBtn.disabled = true;
  el.downloadPdfBtn.textContent = t("preparing");
  try {
    const params = new URLSearchParams();
    params.set("lang", state.lang === "tr" ? "tr" : "en");
    const analysisId = state.result.extra?.analysis_id;
    if (analysisId) params.set("analysis_id", analysisId);
    const response = await fetch(`/api/report?${params.toString()}`, {
      method: "POST",
      headers: apiHeaders({
        "Content-Type": "application/octet-stream",
        "X-Filename": encodeURIComponent(state.file.name),
      }),
      body: analysisId ? null : await state.file.arrayBuffer(),
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.error || t("reportFailed"));
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
    state.isPreparingPdf = false;
    el.downloadPdfBtn.disabled = false;
    el.downloadPdfBtn.textContent = t("pdfReport");
  }
});

el.copyJsonBtn.addEventListener("click", async () => {
  await navigator.clipboard.writeText(el.jsonOutput.textContent);
  toast(t("jsonCopied"));
});

el.downloadJsonBtn.addEventListener("click", () => {
  const blob = new Blob([el.jsonOutput.textContent], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `${state.result?.file_info?.file_name || "moda"}-analysis.json`;
  link.click();
  URL.revokeObjectURL(link.href);
});

el.chatForm.addEventListener("submit", (event) => {
  event.preventDefault();
  askChat(el.chatInput.value);
});

el.chatInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    askChat(el.chatInput.value);
  }
});

el.chatSuggestions.querySelectorAll("button").forEach((button, index) => {
  const keys = ["questionWhy", "questionPriority", "questionErrors"];
  button.addEventListener("click", () => askChat(t(keys[index])));
});

applyTranslations();
checkHealth();
