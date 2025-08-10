document.addEventListener("DOMContentLoaded", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const currentUrl = tabs[0].url;
    chrome.runtime.sendMessage({ action: "getSafetyScore", url: currentUrl }, (resp) => {
      if (resp && resp.success) {
        const statusEl = document.getElementById("current-status");
        const scoreEl = document.getElementById("current-score");

        if (resp.isMalicious) {
          statusEl.textContent = "⚠️ Malicious";
          statusEl.style.color = "red";
        } else {
          statusEl.textContent = "✅ Safe";
          statusEl.style.color = "green";
        }
        scoreEl.textContent = `Score: ${resp.score}/100 | VirusTotal: ${resp.vtMalicious} detections`;
      }
    });
  });
});
