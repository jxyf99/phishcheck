const API_URL = "https://phishcheck-qnp6.onrender.com/api/analyze-url";

const currentUrlEl = document.getElementById("currentUrl");
const scoreValueEl = document.getElementById("scoreValue");
const scoreMeterEl = document.getElementById("scoreMeter");
const statusPillEl = document.getElementById("statusPill");
const reasonsListEl = document.getElementById("reasonsList");
const errorMessageEl = document.getElementById("errorMessage");
const refreshButtonEl = document.getElementById("refreshButton");
const demoButtonEl = document.getElementById("demoButton");
const copyButtonEl = document.getElementById("copyButton");

const DEMO_RESULT = {
  url: "https://paypa1-login-security.top/verify-account",
  score: 72,
  level: "High risk",
  status: "Dangerous",
  findings: [
    {
      category: "Brand impersonation",
      severity: "high",
      message: "Uses number substitutions that resemble a trusted brand.",
      evidence: ["paypa1-login-security.top", "paypal"]
    },
    {
      category: "Credential path",
      severity: "medium",
      message: "Uses account, login, or verification wording in the link.",
      evidence: ["paypa1-login-security.top", "account", "login", "verify"]
    },
    {
      category: "Domain reputation",
      severity: "medium",
      message: "Uses a domain ending commonly abused in phishing campaigns.",
      evidence: ["paypa1-login-security.top"]
    }
  ],
  reasons: []
};

let lastResult = null;

refreshButtonEl.addEventListener("click", analyzeCurrentTab);
demoButtonEl.addEventListener("click", renderDemoScan);
copyButtonEl.addEventListener("click", copyReport);
document.addEventListener("DOMContentLoaded", analyzeCurrentTab);

async function analyzeCurrentTab() {
  setLoading();

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tab?.url || "";

    if (!isScannableUrl(url)) {
      showError("Open a normal website tab before running PhishCheck.");
      return;
    }

    currentUrlEl.textContent = url;

    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error(`Backend returned ${response.status}`);
    }

    const result = await response.json();
    renderResult(result);
  } catch (error) {
    showError("Could not reach the PhishCheck backend. Use Demo to preview a scan, or try Refresh again.");
  }
}

function isScannableUrl(url) {
  return Boolean(url) && /^https?:\/\//i.test(url);
}

function setLoading() {
  lastResult = null;
  errorMessageEl.hidden = true;
  copyButtonEl.disabled = true;
  refreshButtonEl.disabled = true;
  demoButtonEl.disabled = false;
  currentUrlEl.textContent = "Loading current tab...";
  scoreValueEl.textContent = "--";
  scoreMeterEl.style.width = "0%";
  statusPillEl.textContent = "Checking";
  statusPillEl.className = "status-pill loading";
  renderFindings([{ severity: "info", category: "Status", message: "Waiting for analysis.", evidence: [] }]);
}

function renderResult(result) {
  lastResult = result;
  errorMessageEl.hidden = true;
  refreshButtonEl.disabled = false;
  copyButtonEl.disabled = false;

  const score = clampScore(result.score);
  const status = result.status || "Safe";

  currentUrlEl.textContent = result.url || currentUrlEl.textContent;
  scoreValueEl.textContent = score;
  scoreMeterEl.style.width = `${score}%`;
  statusPillEl.textContent = status;
  statusPillEl.className = `status-pill ${status.toLowerCase()}`;
  renderFindings(result.findings || reasonsToFindings(result.reasons || []));
}

function renderFindings(findings) {
  reasonsListEl.innerHTML = "";

  if (!findings.length) {
    reasonsListEl.appendChild(findingItem({ severity: "info", category: "Status", message: "No findings returned by the backend.", evidence: [] }));
    return;
  }

  findings.forEach((finding) => {
    reasonsListEl.appendChild(findingItem(finding));
  });
}

function findingItem(finding) {
  const item = document.createElement("li");
  const severity = knownSeverity(finding.severity);

  const meta = document.createElement("div");
  meta.className = "finding-meta";

  const category = document.createElement("span");
  category.textContent = finding.category || "Finding";

  const badge = document.createElement("strong");
  badge.className = `severity-${severity}`;
  badge.textContent = severity;

  const message = document.createElement("p");
  message.textContent = finding.message || "No detail returned.";

  meta.append(category, badge);
  item.append(meta, message);

  if (finding.evidence?.length) {
    const evidence = document.createElement("div");
    evidence.className = "evidence-list";
    finding.evidence.forEach((value) => {
      const chip = document.createElement("span");
      chip.textContent = value;
      evidence.appendChild(chip);
    });
    item.appendChild(evidence);
  }

  return item;
}

function reasonsToFindings(reasons) {
  return reasons.map((reason) => ({
    severity: "info",
    category: "Finding",
    message: reason,
    evidence: []
  }));
}

function showError(message) {
  lastResult = null;
  errorMessageEl.textContent = message;
  errorMessageEl.hidden = false;
  refreshButtonEl.disabled = false;
  copyButtonEl.disabled = true;
  statusPillEl.textContent = "Offline";
  statusPillEl.className = "status-pill dangerous";
  scoreValueEl.textContent = "--";
  scoreMeterEl.style.width = "0%";
  renderFindings([
    {
      severity: "info",
      category: "Offline",
      message: "The extension needs the deployed PhishCheck API for live scans.",
      evidence: []
    }
  ]);
}

function renderDemoScan() {
  errorMessageEl.hidden = true;
  renderResult(DEMO_RESULT);
}

async function copyReport() {
  if (!lastResult) {
    showError("Run a scan before copying a report.");
    return;
  }

  const lines = [
    "PhishCheck report",
    `URL: ${lastResult.url || currentUrlEl.textContent}`,
    `Score: ${clampScore(lastResult.score)}/100`,
    `Status: ${lastResult.status || "Safe"}`,
    ""
  ];

  (lastResult.findings || reasonsToFindings(lastResult.reasons || [])).forEach((finding) => {
    lines.push(`- [${knownSeverity(finding.severity).toUpperCase()}] ${finding.category || "Finding"}: ${finding.message}`);
    if (finding.evidence?.length) {
      lines.push(`  Evidence: ${finding.evidence.join(", ")}`);
    }
  });

  try {
    await navigator.clipboard.writeText(lines.join("\n"));
    copyButtonEl.textContent = "Copied";
    setTimeout(() => {
      copyButtonEl.textContent = "Copy";
    }, 1200);
  } catch (error) {
    showError("Could not copy the report from this popup. Try running the scan again.");
  }
}

function clampScore(score) {
  return Math.max(0, Math.min(100, Number(score || 0)));
}

function knownSeverity(severity) {
  return ["high", "medium", "low", "info"].includes(severity) ? severity : "info";
}
