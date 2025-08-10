const apiKey = "36843bd097895fefbe993fa762205aa1082c2677eb18b7879466d9e4463bf971"; // VirusTotal API key

class URLSafetyGuard {
  constructor() {
    this.maliciousPatterns = [
      /<script[^>]*>.*<\/script>/i, /javascript:/i, /vbscript:/i, /on\w+\s*=/i, /eval\s*\(/i, /<iframe[^>]*>/i,
      /\.tk$/i, /\.ml$/i, /\.ga$/i, /\.cf$/i, /\.gq$/i, /bit\.ly/i, /tinyurl\.com/i, /goo\.gl/i,
      /paypal.*\.(tk|ml|ga|cf|gq)/i, /bank.*\.(tk|ml|ga|cf|gq)/i
    ];
    this.knownMaliciousDomains = new Set([
      "malware.example.com", "phishing.example.com", "scam.example.com"
    ]);
    this.safetyScores = new Map();
    this.virusTotalResults = new Map();
    this.init();
  }

  init() {
    this.setupBlockingRules();
    chrome.runtime.onMessage.addListener(this.handleMessage.bind(this));
    this.loadData();
    this.setupVirusTotalListener();
    this.startHeartbeat();
  }

  startHeartbeat() {
    setInterval(() => console.log("SW heartbeat - still alive"), 25000);
  }

  async setupBlockingRules() {
    try {
      const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
      if (existingRules.length > 0) {
        await chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: existingRules.map(rule => rule.id)
        });
        console.log(`Removed ${existingRules.length} old rules`);
      }
      await new Promise(resolve => setTimeout(resolve, 100)); // ensure removal processed

      let nextId = Math.floor(Math.random() * 10000) + 1;
      const blockingRules = Array.from(this.knownMaliciousDomains).map(domain => ({
        id: nextId++,
        priority: 1,
        action: { type: "block" },
        condition: { urlFilter: `*://${domain}/*`, resourceTypes: ["main_frame", "sub_frame", "script", "xmlhttprequest"] }
      }));
      const patternRules = this.maliciousPatterns.map(pattern => ({
        id: nextId++,
        priority: 1,
        action: { type: "block" },
        condition: { urlFilter: pattern.source, resourceTypes: ["main_frame", "sub_frame", "script"] }
      }));

      await chrome.declarativeNetRequest.updateDynamicRules({ addRules: [...blockingRules, ...patternRules] });
      console.log(`Added ${blockingRules.length + patternRules.length} rules`);
    } catch (error) {
      console.error("Error setting up blocking rules:", error);
    }
  }

  hasMaliciousPatterns(url) {
    return this.maliciousPatterns.some(pattern => pattern.test(url));
  }

  async calculateSafetyScore(url) {
    try {
      const urlObj = new URL(url);
      let score = 100;
      if (urlObj.protocol !== "https:") score -= 30;
      if (this.hasMaliciousPatterns(url)) score -= 50;
      const suspiciousTLDs = [".tk", ".ml", ".ga", ".cf", ".gq"];
      if (suspiciousTLDs.some(tld => urlObj.hostname.endsWith(tld))) score -= 40;
      if (urlObj.protocol === "https:" && url.includes("http://")) score -= 20;
      if (this.knownMaliciousDomains.has(urlObj.hostname)) score = 0;
      if (this.virusTotalResults.has(url)) {
        const vtMalicious = this.virusTotalResults.get(url);
        if (vtMalicious > 0) score -= Math.min(100, vtMalicious * 20);
      }
      return Math.max(0, score);
    } catch (error) {
      console.error("Error calculating safety score:", error);
      return 0;
    }
  }

  async handleMessage(request, sender, sendResponse) {
    try {
      switch (request.action) {
        case "getSafetyScore":
          const score = await this.calculateSafetyScore(request.url);
          const vtMalicious = this.virusTotalResults.get(request.url) || 0;
          const isMalicious = vtMalicious > 0 || score < 50;
          sendResponse({ score, vtMalicious, isMalicious, success: true });
          break;
        case "addMaliciousDomain":
          const domain = new URL(request.url).hostname;
          this.knownMaliciousDomains.add(domain);
          await this.saveData();
          await this.setupBlockingRules();
          sendResponse({ success: true });
          break;
        case "getStats":
          sendResponse({ stats: { blockedDomains: this.knownMaliciousDomains.size, cachedScores: this.safetyScores.size }, success: true });
          break;
        case "clearCache":
          this.safetyScores.clear();
          this.virusTotalResults.clear();
          await this.saveData();
          sendResponse({ success: true });
          break;
        default:
          sendResponse({ success: false, error: "Unknown action" });
      }
    } catch (error) {
      console.error("Error handling message:", error);
      sendResponse({ success: false, error: error.message });
    }
    return true;
  }

  async loadData() {
    try {
      const result = await chrome.storage.local.get(["knownMaliciousDomains", "safetyScores", "virusTotalResults"]);
      if (result.knownMaliciousDomains) this.knownMaliciousDomains = new Set(result.knownMaliciousDomains);
      if (result.safetyScores) this.safetyScores = new Map(result.safetyScores);
      if (result.virusTotalResults) this.virusTotalResults = new Map(result.virusTotalResults);
      await this.setupBlockingRules();
    } catch (error) {
      console.error("Error loading data:", error);
    }
  }

  async saveData() {
    try {
      await chrome.storage.local.set({
        knownMaliciousDomains: Array.from(this.knownMaliciousDomains),
        safetyScores: Array.from(this.safetyScores.entries()),
        virusTotalResults: Array.from(this.virusTotalResults.entries())
      });
    } catch (error) {
      console.error("Error saving data:", error);
    }
  }

  setupVirusTotalListener() {
    chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
      if (changeInfo.url && this.isValidURL(changeInfo.url)) {
        const url = changeInfo.url;
        console.log("🔍 VirusTotal scanning:", url);
        try {
          const submitResponse = await fetch("https://www.virustotal.com/api/v3/urls", {
            method: "POST",
            headers: { "x-apikey": apiKey, "Content-Type": "application/x-www-form-urlencoded" },
            body: `url=${encodeURIComponent(url)}`
          });
          const submitData = await submitResponse.json();
          if (!submitData.data?.id) return;
          const scanId = submitData.data.id;

          await new Promise(resolve => setTimeout(resolve, 2000));

          const reportResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${scanId}`, {
            headers: { "x-apikey": apiKey }
          });
          const reportData = await reportResponse.json();
          const maliciousCount = reportData.data?.attributes?.stats?.malicious || 0;

          this.virusTotalResults.set(url, maliciousCount);
          await this.saveData();

          const score = await this.calculateSafetyScore(url);
          const isMalicious = maliciousCount > 0 || score < 50;

          if (isMalicious) {
            console.warn(`⚠️ Malicious site detected: ${url}`);
            const domain = new URL(url).hostname;
            this.knownMaliciousDomains.add(domain);
            await this.saveData();
            await this.setupBlockingRules();
            chrome.notifications.create({
              type: "basic", iconUrl: "icons/icon48.png",
              title: "⚠️ Malicious Site Detected!", message: `VirusTotal flagged ${maliciousCount} engines for: ${url}`
            });
          } else {
            console.log(`✅ Safe site: ${url}`);
            chrome.notifications.create({
              type: "basic", iconUrl: "icons/icon48.png",
              title: "✅ Safe Site", message: `${url} appears safe. Score: ${score}/100`
            });
          }
        } catch (err) {
          console.error("❌ VirusTotal API Error:", err);
        }
      }
    });
  }

  isValidURL(url) {
    try {
      const parsed = new URL(url);
      return parsed.protocol === "http:" || parsed.protocol === "https:";
    } catch { return false; }
  }
}

const urlSafetyGuard = new URLSafetyGuard();
