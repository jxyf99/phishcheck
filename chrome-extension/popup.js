const API_URL = "https://phishcheck-qnp6.onrender.com/api/analyze-url";

const currentUrlEl = document.getElementById("currentUrl");
const scoreValueEl = document.getElementById("scoreValue");
const scoreMeterEl = document.getElementById("scoreMeter");
const statusPillEl = document.getElementById("statusPill");
const reasonsListEl = document.getElementById("reasonsList");
const errorMessageEl = document.getElementById("errorMessage");
const refreshButtonEl = document.getElementById("refreshButton");

refreshButtonEl.addEventListener("click", analyzeCurrentTab);
document.addEventListener("DOMContentLoaded", analyzeCurrentTab);

async function analyzeCurrentTab() {
  setLoading();

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tab?.url || "";

    if (!url || url.startsWith("chrome://") || url.startsWith("edge://")) {
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
    showError("Could not reach the PhishCheck backend. Wait a moment and refresh this popup.");
  }
}

function setLoading() {
  errorMessageEl.hidden = true;
  currentUrlEl.textContent = "Loading current tab...";
  scoreValueEl.textContent = "--";
  scoreMeterEl.style.width = "0%";
  statusPillEl.textContent = "Checking";
  statusPillEl.className = "status-pill loading";
  renderReasons(["Waiting for analysis."]);
}

function renderResult(result) {
  const score = Number(result.score || 0);
  const status = result.status || "Safe";

  scoreValueEl.textContent = score;
  scoreMeterEl.style.width = `${score}%`;
  statusPillEl.textContent = status;
  statusPillEl.className = `status-pill ${status.toLowerCase()}`;
  renderReasons(result.reasons || []);
}

function renderReasons(reasons) {
  reasonsListEl.innerHTML = "";

  if (!reasons.length) {
    reasonsListEl.appendChild(reasonItem("No reasons returned by the backend."));
    return;
  }

  reasons.forEach((reason) => {
    reasonsListEl.appendChild(reasonItem(reason));
  });
}

function reasonItem(text) {
  const item = document.createElement("li");
  item.textContent = text;
  return item;
}

function showError(message) {
  errorMessageEl.textContent = message;
  errorMessageEl.hidden = false;
  statusPillEl.textContent = "Offline";
  statusPillEl.className = "status-pill dangerous";
  scoreValueEl.textContent = "--";
  scoreMeterEl.style.width = "0%";
  renderReasons(["The extension needs the deployed PhishCheck API to be reachable."]);
}
