// background.js
// NOTE: Replace apiKey with your own VirusTotal API key if you want.
const apiKey = "36843bd097895fefbe993fa762205aa1082c2677eb18b7879466d9e4463bf971";

// PhishTank feed URL (online-valid JSON). This is a public feed that contains verified phishing entries.
// If PhishTank changes their feed URL or format, update this accordingly.
const PHISHTANK_FEED_URL = "https://data.phishtank.com/data/online-valid.json";

// How often to refresh PhishTank list (milliseconds). Default 12 hours.
const PHISHTANK_REFRESH_INTERVAL_MS = 12 * 60 * 60 * 1000;

class URLSafetyGuard {
  constructor() {
    this.maliciousPatterns = [
      /<script[^>]*>.*<\/script>/i,
      /javascript:/i,
      /vbscript:/i,
      /on\w+\s*=/i,
      /eval\s*\(/i,
      /<iframe[^>]*>/i,
      /\.tk$/i, /\.ml$/i, /\.ga$/i, /\.cf$/i, /\.gq$/i,
      /bit\.ly/i, /tinyurl\.com/i, /goo\.gl/i,
      /paypal.*\.(tk|ml|ga|cf|gq)/i, /bank.*\.(tk|ml|ga|cf|gq)/i
    ];

    // Seed known malicious list. PhishTank will add many domains after fetch.
    this.knownMaliciousDomains = new Set([
      "malware.example.com", "phishing.example.com", "scam.example.com"
    ]);

    // Caches
    this.safetyScores = new Map();     // url -> score
    this.virusTotalResults = new Map(); // url -> maliciousCount

    // initialize
    this.init();
  }

  init() {
    // try to load stored data and then setup rules
    this.loadData()
      .then(() => this.setupBlockingRules())
      .catch(err => console.error("Init loadData/setup error:", err));

    // listen for popup/content messages
    chrome.runtime.onMessage.addListener(this.handleMessage.bind(this));

    // start listeners and background tasks
    this.setupVirusTotalListener();      // tab updates -> VT scans
    this.fetchPhishTankList().catch(e => console.warn("PhishTank initial fetch failed:", e)); // fetch once at startup
    // schedule periodic PhishTank refresh
    setInterval(() => this.fetchPhishTankList().catch(e => console.warn("PhishTank refresh error:", e)), PHISHTANK_REFRESH_INTERVAL_MS);

    this.startHeartbeat();
  }

  startHeartbeat() {
    // Keep SW alive longer while debugging — remove or increase interval in production.
    setInterval(() => console.log("SW heartbeat - alive"), 25000);
  }

  // --- PhishTank integration ---
  async fetchPhishTankList() {
    try {
      console.log("Fetching PhishTank feed...");
      const resp = await fetch(PHISHTANK_FEED_URL, { cache: "no-store" });
      if (!resp.ok) {
        throw new Error(`PhishTank fetch failed: ${resp.status} ${resp.statusText}`);
      }
      const data = await resp.json();

      // Data is expected to be an array of objects with a 'url' field.
      let added = 0;
      for (const entry of data) {
        if (!entry || !entry.url) continue;
        try {
          const u = new URL(entry.url);
          const host = u.hostname;
          if (!this.knownMaliciousDomains.has(host)) {
            this.knownMaliciousDomains.add(host);
            added++;
          }
        } catch (e) {
          // skip malformed entries
        }
      }

      if (added > 0) {
        console.log(`PhishTank: added ${added} domains to knownMaliciousDomains`);
        await this.saveData();
        // Update blocking rules to include new domains
        await this.setupBlockingRules();
      } else {
        console.log("PhishTank: no new domains found");
      }
    } catch (err) {
      console.error("fetchPhishTankList error:", err);
      throw err;
    }
  }

  // --- Declarative Net Request rules (blocking) ---
  async setupBlockingRules() {
    try {
      const existing = await chrome.declarativeNetRequest.getDynamicRules();

      if (existing && existing.length > 0) {
        const idsToRemove = existing.map(r => r.id);
        try {
          await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: idsToRemove });
          console.log(`Removed ${idsToRemove.length} existing declarative rules`);
        } catch (remErr) {
          console.warn("Error removing existing rules (attempting to continue):", remErr);
        }
      }

      // small delay so Chrome processes the removals
      await new Promise(resolve => setTimeout(resolve, 150));

      // Create unique IDs using random base to avoid collisions
      let nextId = Math.floor(Math.random() * 100000) + 1000;

      const blockingRules = [];
      for (const domain of Array.from(this.knownMaliciousDomains)) {
        blockingRules.push({
          id: nextId++,
          priority: 1,
          action: { type: "block" },
          condition: {
            urlFilter: `*://${domain}/*`,
            resourceTypes: ["main_frame", "sub_frame", "script", "xmlhttprequest"]
          }
        });
      }

      const patternRules = [];
      for (const pattern of this.maliciousPatterns) {
        patternRules.push({
          id: nextId++,
          priority: 1,
          action: { type: "block" },
          condition: {
            // use the .source of regex; declarativeNetRequest requires a string filter
            urlFilter: pattern.source,
            resourceTypes: ["main_frame", "sub_frame", "script"]
          }
        });
      }

      const allRules = [...blockingRules, ...patternRules];

      if (allRules.length > 0) {
        await chrome.declarativeNetRequest.updateDynamicRules({ addRules: allRules });
        console.log(`Added ${allRules.length} declarative rules`);
      }
    } catch (err) {
      console.error("Error setting up blocking rules:", err);
    }
  }

  hasMaliciousPatterns(url) {
    try {
      return this.maliciousPatterns.some(p => p.test(url));
    } catch (e) {
      return false;
    }
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
        const vtMalicious = this.virusTotalResults.get(url) || 0;
        if (vtMalicious > 0) score -= Math.min(100, vtMalicious * 20);
      }

      return Math.max(0, score);
    } catch (err) {
      console.error("calculateSafetyScore error:", err);
      return 0;
    }
  }

  // respond to messages from popup / content
  async handleMessage(request, sender, sendResponse) {
    try {
      switch (request.action) {
        case "getSafetyScore": {
          const url = request.url;
          const score = await this.calculateSafetyScore(url);
          const vtMalicious = this.virusTotalResults.get(url) || 0;
          const domain = (() => { try { return new URL(url).hostname } catch { return ""; } })();

          const isMalicious = (
            vtMalicious > 0 ||
            this.knownMaliciousDomains.has(domain) ||
            this.hasMaliciousPatterns(url) ||
            score < 80
          );

          sendResponse({ success: true, score, vtMalicious, isMalicious });
          break;
        }

        case "addMaliciousDomain": {
          try {
            const domainToAdd = new URL(request.url).hostname;
            this.knownMaliciousDomains.add(domainToAdd);
            await this.saveData();
            await this.setupBlockingRules();
            sendResponse({ success: true });
          } catch (e) {
            sendResponse({ success: false, error: e.message });
          }
          break;
        }

        case "getStats": {
          sendResponse({
            success: true,
            stats: {
              blockedDomains: this.knownMaliciousDomains.size,
              cachedScores: this.safetyScores.size
            }
          });
          break;
        }

        case "clearCache": {
          this.safetyScores.clear();
          this.virusTotalResults.clear();
          await this.saveData();
          sendResponse({ success: true });
          break;
        }

        default:
          sendResponse({ success: false, error: "Unknown action" });
      }
    } catch (err) {
      console.error("handleMessage error:", err);
      sendResponse({ success: false, error: err.message });
    }
    return true; // will respond async
  }

  async loadData() {
    try {
      const result = await chrome.storage.local.get(["knownMaliciousDomains", "safetyScores", "virusTotalResults"]);
      if (result.knownMaliciousDomains) this.knownMaliciousDomains = new Set(result.knownMaliciousDomains);
      if (result.safetyScores) this.safetyScores = new Map(result.safetyScores);
      if (result.virusTotalResults) this.virusTotalResults = new Map(result.virusTotalResults);
      console.log("Loaded stored data:", {
        knownMaliciousCount: this.knownMaliciousDomains.size,
        safetyScores: this.safetyScores.size,
        vtResults: this.virusTotalResults.size
      });
    } catch (err) {
      console.error("loadData error:", err);
    }
  }

  async saveData() {
    try {
      await chrome.storage.local.set({
        knownMaliciousDomains: Array.from(this.knownMaliciousDomains),
        safetyScores: Array.from(this.safetyScores.entries()),
        virusTotalResults: Array.from(this.virusTotalResults.entries())
      });
    } catch (err) {
      console.error("saveData error:", err);
    }
  }

  // VirusTotal scanning on tab update
  setupVirusTotalListener() {
    chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
      if (!changeInfo.url) return;
      const url = changeInfo.url;

      if (!this.isValidURL(url)) {
        // skip chrome: internal pages etc
        return;
      }

      try {
        console.log("🔍 VirusTotal scanning:", url);

        // Submit URL for analysis
        const submitResp = await fetch("https://www.virustotal.com/api/v3/urls", {
          method: "POST",
          headers: {
            "x-apikey": apiKey,
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: `url=${encodeURIComponent(url)}`
        });

        const submitData = await submitResp.json();
        if (!submitData.data || !submitData.data.id) {
          console.warn("VirusTotal submit returned no analysis id for url:", url);
          return;
        }

        const analysisId = submitData.data.id;

        // Brief delay so analysis becomes available
        await new Promise(resolve => setTimeout(resolve, 2000));

        // Fetch analysis
        const reportResp = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
          headers: { "x-apikey": apiKey }
        });

        const reportData = await reportResp.json();
        const maliciousCount = (reportData.data && reportData.data.attributes && reportData.data.attributes.stats && reportData.data.attributes.stats.malicious) ? reportData.data.attributes.stats.malicious : 0;

        // cache vt result
        this.virusTotalResults.set(url, maliciousCount);
        await this.saveData();

        // compute score & verdict
        const score = await this.calculateSafetyScore(url);
        const domain = (() => { try { return new URL(url).hostname } catch { return ""; } })();
        const patternMatch = this.hasMaliciousPatterns(url);
        const inBadList = this.knownMaliciousDomains.has(domain);

        const isMalicious = (
          maliciousCount > 0 ||
          inBadList ||
          patternMatch ||
          score < 80
        );

        if (isMalicious) {
          console.warn(`⚠️ Malicious site detected: ${url} (vt:${maliciousCount} pattern:${patternMatch} inList:${inBadList} score:${score})`);
          if (!inBadList) {
            this.knownMaliciousDomains.add(domain);
            await this.saveData();
            // update rules after adding domain
            await this.setupBlockingRules();
          }
          // Notify user about malicious site
          chrome.notifications.create({
            type: "basic",
            iconUrl: "icons/icon48.png",
            title: "⚠️ Malicious Site Detected!",
            message: `${domain} flagged. VT detections: ${maliciousCount}.`
          });
        } else {
          // only log safe verdicts to reduce notification spam
          console.log(`✅ Safe site: ${url} (score:${score} vt:${maliciousCount})`);
        }
      } catch (err) {
        console.error("VirusTotal scan error:", err);
      }
    });
  }

  isValidURL(url) {
    try {
      const u = new URL(url);
      return (u.protocol === "http:" || u.protocol === "https:");
    } catch {
      return false;
    }
  }
}

const urlSafetyGuard = new URLSafetyGuard();
