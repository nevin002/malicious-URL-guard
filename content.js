// Content script for URL Safety Guard
class ContentSafetyGuard {
  constructor() {
    this.init();
  }
  
  init() {
    this.checkPageSafety();
    this.observeDOMChanges();
    this.blockMaliciousContent();
    this.addSafetyIndicator();
  }
  
  async checkPageSafety() {
    const currentUrl = window.location.href;
    try {
      const response = await chrome.runtime.sendMessage({
        action: 'getSafetyScore',
        url: currentUrl
      });
      
      if (response && response.score !== undefined) {
        this.displaySafetyScore(response.score, response.isMalicious, response.vtMalicious);
        
        if (response.isMalicious) {
          this.showWarningBanner(response.vtMalicious);
        }
      }
    } catch (error) {
      console.error('Error checking page safety:', error);
    }
  }
  
  displaySafetyScore(score, isMalicious, vtMalicious) {
    let scoreElement = document.getElementById('url-safety-score');
    if (!scoreElement) {
      scoreElement = document.createElement('div');
      scoreElement.id = 'url-safety-score';
      scoreElement.style.cssText = `
        position: fixed;
        top: 10px;
        right: 10px;
        background: ${isMalicious ? '#f44336' : '#4CAF50'};
        color: white;
        padding: 8px 12px;
        border-radius: 20px;
        font-family: Arial, sans-serif;
        font-size: 12px;
        font-weight: bold;
        z-index: 10000;
        box-shadow: 0 2px 10px rgba(0,0,0,0.3);
      `;
      document.body.appendChild(scoreElement);
    }
    scoreElement.textContent = `Safety: ${score}/100 | VT: ${vtMalicious} detections`;
    scoreElement.style.background = isMalicious ? '#f44336' : '#4CAF50';
  }
  
  showWarningBanner(vtMalicious) {
    const banner = document.createElement('div');
    banner.id = 'url-safety-warning';
    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      background: #f44336;
      color: white;
      text-align: center;
      padding: 10px;
      font-family: Arial, sans-serif;
      font-weight: bold;
      z-index: 10001;
      box-shadow: 0 2px 10px rgba(0,0,0,0.3);
    `;
    banner.innerHTML = `
      ⚠️ WARNING: This site is unsafe. VirusTotal flagged ${vtMalicious} engines.
      <button onclick="this.parentElement.remove()" style="margin-left: 10px; background: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer;">Dismiss</button>
    `;
    document.body.appendChild(banner);
  }
  
  observeDOMChanges() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            this.checkNodeSafety(node);
          }
        });
      });
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }
  
  checkNodeSafety(node) {
    if (node.tagName === 'SCRIPT') {
      if (this.isMaliciousScript(node.textContent || '')) {
        this.blockNode(node, 'Malicious script detected');
      }
    }
    if (node.tagName === 'IFRAME') {
      const src = node.getAttribute('src');
      if (src && this.isMaliciousURL(src)) {
        this.blockNode(node, 'Malicious iframe detected');
      }
    }
    if (node.hasAttribute) {
      for (let attr of node.attributes) {
        if (attr.name.startsWith('on') && this.isMaliciousEvent(attr.value)) {
          this.blockNode(node, 'Malicious event handler detected');
        }
      }
    }
  }
  
  isMaliciousScript(content) {
    const maliciousPatterns = [
      /eval\s*\(/i, /document\.write\s*\(/i, /innerHTML\s*=/i,
      /outerHTML\s*=/i, /setTimeout\s*\(/i, /setInterval\s*\(/i,
      /Function\s*\(/i, /new\s+Function/i
    ];
    return maliciousPatterns.some(p => p.test(content));
  }
  
  isMaliciousURL(url) {
    const maliciousPatterns = [
      /javascript:/i, /vbscript:/i, /data:text\/html/i, /data:application\/javascript/i
    ];
    return maliciousPatterns.some(p => p.test(url));
  }
  
  isMaliciousEvent(value) {
    const maliciousPatterns = [
      /javascript:/i, /vbscript:/i, /eval\s*\(/i, /document\.write/i
    ];
    return maliciousPatterns.some(p => p.test(value));
  }
  
  blockNode(node, reason) {
    const warning = document.createElement('div');
    warning.style.cssText = `
      background: #ffebee;
      border: 2px solid #f44336;
      color: #c62828;
      padding: 10px;
      margin: 10px 0;
      border-radius: 5px;
      font-family: Arial, sans-serif;
      font-size: 12px;
    `;
    warning.innerHTML = `<strong>🚫 Blocked by URL Safety Guard:</strong><br>${reason}`;
    if (node.parentNode) node.parentNode.replaceChild(warning, node);
  }
  
  blockMaliciousContent() {
    document.querySelectorAll('script').forEach(s => {
      if (this.isMaliciousScript(s.textContent || '')) {
        this.blockNode(s, 'Malicious script detected');
      }
    });
    document.querySelectorAll('iframe').forEach(f => {
      const src = f.getAttribute('src');
      if (src && this.isMaliciousURL(src)) {
        this.blockNode(f, 'Malicious iframe detected');
      }
    });
    document.querySelectorAll('*[onclick], *[onload], *[onerror], *[onmouseover]').forEach(el => {
      for (let attr of el.attributes) {
        if (attr.name.startsWith('on') && this.isMaliciousEvent(attr.value)) {
          el.removeAttribute(attr.name);
        }
      }
    });
  }
  
  addSafetyIndicator() {
    const indicator = document.createElement('div');
    indicator.id = 'url-safety-indicator';
    indicator.style.cssText = `
      position: fixed;
      bottom: 10px;
      right: 10px;
      background: rgba(0,0,0,0.7);
      color: white;
      padding: 5px 8px;
      border-radius: 15px;
      font-family: Arial, sans-serif;
      font-size: 10px;
      z-index: 9999;
      cursor: pointer;
    `;
    indicator.textContent = '🛡️';
    indicator.title = 'URL Safety Guard Active';
    indicator.addEventListener('click', () => {
      alert('URL Safety Guard is running.\nOpen the extension popup for details.');
    });
    document.body.appendChild(indicator);
  }
}

const contentSafetyGuard = new ContentSafetyGuard();
