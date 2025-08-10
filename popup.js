// popup.js
document.addEventListener("DOMContentLoaded", () => {
  refreshCurrentStatus();

  document.getElementById("check-url-btn").addEventListener("click", async () => {
    const url = document.getElementById("url-input").value.trim();
    if (!url) return;
    const resp = await sendMessage({ action: "getSafetyScore", url });
    showResultForInput(resp, url);
  });

  document.getElementById("add-malicious-btn").addEventListener("click", async () => {
    const url = document.getElementById("url-input").value.trim();
    if (!url) return;
    await sendMessage({ action: "addMaliciousDomain", url });
    document.getElementById("url-result").textContent = "Reported. Updated blocklist.";
    refreshCurrentStatus();
  });
});

function sendMessage(msg) {
  return new Promise(resolve => chrome.runtime.sendMessage(msg, resp => resolve(resp)));
}

async function refreshCurrentStatus() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tabs || !tabs[0] || !tabs[0].url) {
    document.getElementById("current-status").textContent = "No active page";
    return;
  }
  const url = tabs[0].url;
  const resp = await sendMessage({ action: "getSafetyScore", url });
  if (!resp || !resp.success) {
    document.getElementById("current-status").textContent = "Error";
    return;
  }
  const statusEl = document.getElementById("current-status");
  const scoreEl = document.getElementById("current-score");
  const vtNote = document.getElementById("vt-note");

  if (resp.isMalicious) {
    statusEl.textContent = "⚠️ Malicious";
    statusEl.style.color = "red";
  } else {
    statusEl.textContent = "✅ Safe";
    statusEl.style.color = "green";
  }

  scoreEl.textContent = `Score: ${resp.score}/100 | VT detections: ${resp.vtMalicious}`;
  vtNote.textContent = `Detection uses VirusTotal + PhishTank + pattern rules.`;
}

function showResultForInput(resp, url) {
  const result = document.getElementById("url-result");
  if (!resp || !resp.success) {
    result.textContent = "Error checking URL";
    return;
  }
  const verdict = resp.isMalicious ? "⚠️ Malicious" : "✅ Safe";
  result.textContent = `${verdict} | Score: ${resp.score}/100 | VT: ${resp.vtMalicious} | ${url}`;
}
