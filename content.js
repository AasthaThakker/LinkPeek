(function() {
  // Brand domain mapping for login credential mimic detection
  const BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "facebook": "facebook.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "citibank": "citi.com",
    "binance": "binance.com",
    "instagram": "instagram.com",
    "linkedin": "linkedin.com",
    "apple": "apple.com",
    "netflix": "netflix.com"
  };

  let hoverTimeout = null;
  let tooltipContainer = null;
  let activeTooltipLink = null;

  // Local settings cache to prevent async storage race conditions in mouse events
  let tooltipEnabled = true;
  let tooltipStyle = "cyber";

  // Safe chrome runtime send message wrapper to prevent context invalidated crashes
  function safeSendMessage(message, callback) {
    try {
      if (chrome.runtime && chrome.runtime.id) {
        chrome.runtime.sendMessage(message, (response) => {
          const lastError = chrome.runtime.lastError;
          if (lastError) {
            console.warn("[Pre-Analyzer] Runtime message error:", lastError.message);
            return;
          }
          if (callback) callback(response);
        });
      } else {
        console.warn("[Pre-Analyzer] chrome.runtime or runtime.id is unavailable");
      }
    } catch (e) {
      console.error("[Pre-Analyzer] Exception in safeSendMessage:", e);
    }
  }

  // Initialize Settings Sync Safely
  try {
    if (chrome.storage && chrome.storage.local) {
      chrome.storage.local.get({ tooltipEnabled: true, tooltipStyle: "cyber" }, (items) => {
        const lastError = chrome.runtime.lastError;
        if (!lastError && items) {
          tooltipEnabled = items.tooltipEnabled !== undefined ? items.tooltipEnabled : true;
          tooltipStyle = items.tooltipStyle || "cyber";
        }
      });
    }
  } catch (e) {
    // Ignore
  }

  try {
    if (chrome.storage && chrome.storage.onChanged) {
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area === "local") {
          if (changes.tooltipEnabled !== undefined) {
            tooltipEnabled = changes.tooltipEnabled.newValue;
          }
          if (changes.tooltipStyle !== undefined) {
            tooltipStyle = changes.tooltipStyle.newValue;
          }
        }
      });
    }
  } catch (e) {
    // Ignore
  }

  // Run initializations
  initFakeLoginDetector();
  initHoverPreview();
  initPassiveBehaviorWatchers();

  /**
   * 1. FAKE LOGIN DETECTOR
   * Checks if page mimics a brand login but is hosted on an unofficial domain.
   */
  function initFakeLoginDetector() {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    if (passwordFields.length === 0) return;

    const pageTitle = (document.title || "").toLowerCase();
    const pageText = (document.body ? document.body.innerText.slice(0, 1000) : "").toLowerCase();
    const currentHost = window.location.hostname.toLowerCase();

    for (const [brand, officialDomain] of Object.entries(BRAND_DOMAINS)) {
      const titleMatches = pageTitle.includes(brand);
      const textMatches = pageText.includes(brand + " sign in") || 
                          pageText.includes("login to " + brand) || 
                          pageText.includes("log in to " + brand) ||
                          pageText.includes("sign in to your " + brand);

      if (titleMatches || textMatches) {
        const isOfficial = currentHost === officialDomain || currentHost.endsWith("." + officialDomain);
        const isLocalDev = currentHost === "localhost" || currentHost === "127.0.0.1";
        
        if (!isOfficial && !isLocalDev) {
          injectWarningBanner(brand, officialDomain, currentHost);
          reportAnomaly("fake_login", "Impersonated Login Interface", `This page mimics the branding of ${brand.toUpperCase()} but is hosted on ${currentHost} (official is ${officialDomain}).`);
          break;
        }
      }
    }
  }

  function injectWarningBanner(brand, officialDomain, actualHost) {
    const banner = document.createElement("div");
    banner.id = "cyber-prescan-warning-banner";
    
    banner.style.position = "fixed";
    banner.style.top = "0";
    banner.style.left = "0";
    banner.style.width = "100%";
    banner.style.backgroundColor = "#ef4444";
    banner.style.color = "#ffffff";
    banner.style.fontFamily = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
    banner.style.fontSize = "13px";
    banner.style.fontWeight = "bold";
    banner.style.textAlign = "center";
    banner.style.padding = "10px 40px 10px 10px";
    banner.style.zIndex = "2147483647";
    banner.style.boxShadow = "0 4px 10px rgba(0,0,0,0.3)";
    banner.style.display = "flex";
    banner.style.alignItems = "center";
    banner.style.justifyContent = "center";
    banner.style.boxSizing = "border-box";

    const msg = document.createElement("span");
    msg.innerHTML = `⚠️ SECURITY WARNING: This page resembles a <strong>${brand.toUpperCase()}</strong> login portal but is hosted on <strong>${actualHost}</strong> (not ${officialDomain}). Entering credentials here is extremely dangerous!`;
    banner.appendChild(msg);

    const closeBtn = document.createElement("button");
    closeBtn.innerText = "✖";
    closeBtn.style.position = "absolute";
    closeBtn.style.right = "15px";
    closeBtn.style.background = "none";
    closeBtn.style.border = "none";
    closeBtn.style.color = "#ffffff";
    closeBtn.style.fontSize = "14px";
    closeBtn.style.cursor = "pointer";
    closeBtn.style.padding = "5px";
    
    closeBtn.onclick = () => {
      banner.remove();
      document.body.style.marginTop = "0px";
    };
    banner.appendChild(closeBtn);

    document.body.style.marginTop = "40px";
    document.body.prepend(banner);
  }

  /**
   * 2. SMART HOVER PREVIEW
   * Hover over links to see passive risk preview via an isolated Shadow DOM.
   */
  function initHoverPreview() {
    document.addEventListener("pointerover", handleHoverStart, true);
    document.addEventListener("mouseover", handleHoverStart, true);
    document.addEventListener("pointerout", handleHoverEnd, true);
    document.addEventListener("mouseout", handleHoverEnd, true);
    window.addEventListener("scroll", handleScroll, { passive: true });
  }

  function handleScroll() {
    if (hoverTimeout) clearTimeout(hoverTimeout);
    if (activeTooltipLink) {
      activeTooltipLink = null;
    }
    hideTooltip();
  }

  function findClosestAnchor(event) {
    const path = typeof event.composedPath === "function" ? event.composedPath() : [];
    for (const node of path) {
      if (node && node.nodeType === Node.ELEMENT_NODE) {
        if (node.tagName === "A") {
          // Only return this anchor if it has a meaningful absolute href
          const nodeHref = node.getAttribute("href") || "";
          if (/^https?:\/\//i.test(nodeHref) || /^https?:\/\//i.test(node.href || "")) {
            return node;
          }
          // Skip anchors with relative/empty hrefs — keep walking up
        }
      }
      if (node === document || node === window) break;
    }

    if (event.target && event.target.nodeType === Node.ELEMENT_NODE) {
      const closest = event.target.closest("a");
      if (closest) {
        const nodeHref = closest.getAttribute("href") || "";
        if (/^https?:\/\//i.test(nodeHref) || /^https?:\/\//i.test(closest.href || "")) {
          return closest;
        }
      }
    }
    return null;
  }

  function handleHoverStart(e) {
  if (!tooltipEnabled) return;

  let link = null;

  const path = e.composedPath ? e.composedPath() : [];

  for (const el of path) {
    if (
      el instanceof HTMLAnchorElement &&
      el.href &&
      /^https?:\/\//i.test(el.href)
    ) {
      link = el;
      break;
    }
  }

  if (!link) return;

  // Prevent re-triggering on same link
  if (activeTooltipLink === link) return;

  const resolvedHref = link.href;
  const rawHref = link.getAttribute("href") || "";

  if (
    !resolvedHref ||
    resolvedHref.startsWith("#") ||
    resolvedHref.startsWith("javascript:")
  ) {
    return;
  }

  const isHttpOrMailto =
    /^https?:\/\//i.test(resolvedHref) ||
    resolvedHref.startsWith("mailto:");

  if (!isHttpOrMailto) {
    return;
  }

  const rawLower = rawHref.toLowerCase();

  const canonicalUrl =
    /^https?:\/\//i.test(rawLower)
      ? rawHref
      : resolvedHref;

  if (hoverTimeout) clearTimeout(hoverTimeout);

  activeTooltipLink = link;

  hoverTimeout = setTimeout(() => {
    if (activeTooltipLink === link) {
      createTooltipContainer();

      renderPendingTooltip(
        themeForCurrentHover(),
        canonicalUrl
      );

      positionTooltip(link);

      fetchAndShowTooltip(
        link,
        canonicalUrl,
        tooltipStyle,
        rawHref
      );
    }
  }, 120);
}

  function handleHoverEnd(e) {
    const link = activeTooltipLink;
    if (!link) return;
    if (e.relatedTarget instanceof Node && link.contains(e.relatedTarget)) return;

    if (hoverTimeout) clearTimeout(hoverTimeout);
    activeTooltipLink = null;
    hoverTimeout = setTimeout(() => {
      hideTooltip();
    }, 200);
  }

  function themeForCurrentHover() {
    return tooltipStyle || "cyber";
  }

  function renderPendingTooltip(theme, url) {
    const wrapper = tooltipContainer.shadowRoot.getElementById("tooltip-wrapper");
    if (!wrapper) return;

    let hostname = url;
    try {
      hostname = new URL(url).hostname || url;
    } catch (e) {}

    wrapper.className = `theme-${theme}`;
    wrapper.innerHTML = `
      <style>
        #tooltip-wrapper, #tooltip-wrapper * { pointer-events: none !important; box-sizing: border-box; }
        #tooltip-wrapper {
          width: 270px;
          font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          padding: 10px 12px;
          border-radius: 6px;
          box-shadow: 0 4px 15px rgba(0, 0, 0, 0.4);
          display: flex;
          flex-direction: column;
          gap: 6px;
          line-height: 1.35;
          background-color: #0b0f19;
          border: 1px solid #1e293b;
          border-left: 3px solid #06b6d4;
          color: #f3f4f6;
        }
        .intent-label { font-size: 10.5px; font-weight: 700; color: #e2e8f0; text-transform: uppercase; }
        .dest-url { font-size: 10px; font-family: monospace; color: #94a3b8; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .explanation-text { font-size: 11px; color: #cbd5e1; }
      </style>
      <div class="intent-label">Analyzing link</div>
      <div class="dest-url" title="${hostname}">${hostname}</div>
      <div class="explanation-text">Checking local risk signals...</div>
    `;
  }

  function fetchAndShowTooltip(linkElement, url, theme, rawHref) {
    const hasPassword = document.querySelector('input[type="password"]') !== null;
    const cardInputSelectors = [
      'input[name*="card"]', 'input[name*="cc"]', 'input[name*="cvv"]', 
      'input[id*="card"]', 'input[id*="cc"]', 'input[id*="cvv"]',
      'iframe[src*="stripe"]', 'iframe[src*="paypal"]', 'iframe[src*="braintree"]'
    ];
    const hasCard = cardInputSelectors.some(sel => document.querySelector(sel) !== null);

    // Snapshot the link at call time — don't rely on activeTooltipLink which can be nulled async
    const targetLink = linkElement;

    safeSendMessage({ 
      action: "getQuickScore", 
      url: url,
      linkText: linkElement.textContent || "",
      hasPasswordFields: hasPassword,
      hasCardInputs: hasCard
    }, (response) => {
      if (!response) {

  renderErrorTooltip(
    "Analysis unavailable",
    "No response received from background service."
  );

  return;
}

if (!response.success) {

  renderErrorTooltip(
    "Analysis failed",
    response.error || "Unknown analysis error."
  );

  return;
}

    function renderErrorTooltip(title, message) {

  if (!tooltipContainer) return;

  tooltipContainer.innerHTML = `
    <div class="intel-tooltip">
      <div class="tooltip-header">
        <div class="tooltip-title">
          ${title}
        </div>
      </div>

      <div class="tooltip-body">
        ${message}
      </div>
    </div>
  `;
}
      if (targetLink !== activeTooltipLink) return;
      // Only render if tooltip is still visible (user hasn't moved away)
      createTooltipContainer();
      if (!tooltipContainer || tooltipContainer.style.display === "none") return;
      renderTooltipContent(response, theme, url, rawHref);
      positionTooltip(targetLink);
    });
  }

  function createTooltipContainer() {
    if (tooltipContainer) return;

    // Check if the element already exists in the document (from previous script instances)
    const existing = document.getElementById("cyber-pre-analyzer-tooltip-root");
    if (existing) {
      console.log("[Pre-Analyzer] Reusing existing tooltip root in DOM.");
      tooltipContainer = existing;
      return;
    }

    console.log("[Pre-Analyzer] Creating new tooltip root container.");
    tooltipContainer = document.createElement("div");
    tooltipContainer.id = "cyber-pre-analyzer-tooltip-root";
    
    // Apply reset to insulate from host page styles
    tooltipContainer.style.all = "initial";
    tooltipContainer.style.position = "fixed"; 
    tooltipContainer.style.zIndex = "2147483646";
    tooltipContainer.style.setProperty("pointer-events", "none", "important");
    tooltipContainer.style.display = "none";
    
    const shadow = tooltipContainer.attachShadow({ mode: "open" });
    
    const wrapper = document.createElement("div");
    wrapper.id = "tooltip-wrapper";
    shadow.appendChild(wrapper);

    // Append to body if available, falling back to documentElement
    const parent = document.body || document.documentElement;
    if (parent) {
      parent.appendChild(tooltipContainer);
    }
  }

  function hideTooltip() {
    if (tooltipContainer) {
      tooltipContainer.style.display = "none";
    }
  }

  function positionTooltip(linkElement) {
    if (!tooltipContainer) return;

    // Show but keep invisible to measure
    tooltipContainer.style.visibility = "hidden";
    tooltipContainer.style.display = "block";
    tooltipContainer.style.setProperty("pointer-events", "none", "important");

    const wrapper = tooltipContainer.shadowRoot.getElementById("tooltip-wrapper");
    if (!wrapper) {
      console.warn("[Pre-Analyzer] Wrapper not found inside shadow root.");
      return;
    }
    const tooltipRect = wrapper.getBoundingClientRect();
    const tooltipHeight = tooltipRect.height || 140;

    const linkRect = linkElement.getBoundingClientRect();

    // Place tooltip centered, 12px below the element
    let top = linkRect.bottom + 12;
    let left = linkRect.left + (linkRect.width / 2) - 135; // Centered on a 270px width card

    // Keep within horizontal window bounds
    if (left < 10) left = 10;
    if (left + 270 > window.innerWidth - 10) {
      left = window.innerWidth - 280;
    }

    // Keep within vertical window bounds
    if (top + tooltipHeight > window.innerHeight) {
      // Position above the link
      top = linkRect.top - tooltipHeight - 12;
    }

    if (top < 10) top = 10;

    tooltipContainer.style.top = top + "px";
    tooltipContainer.style.left = left + "px";
    tooltipContainer.style.visibility = "visible";
    console.log("[Pre-Analyzer] Positioned tooltip card at top:", top, "left:", left);
  }

  function renderTooltipContent(data, theme, url, rawHref) {
    const wrapper = tooltipContainer.shadowRoot.getElementById("tooltip-wrapper");
    
    let riskColor = "#10b981";
    if (data.risk === "HIGH") riskColor = "#ef4444";
    else if (data.risk === "MEDIUM") riskColor = "#f59e0b";

    const styleBlock = `
      <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        
        #tooltip-wrapper, #tooltip-wrapper * {
          pointer-events: none !important;
          box-sizing: border-box;
        }

        #tooltip-wrapper {
          width: 270px;
          font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          padding: 10px 12px;
          border-radius: 6px;
          box-shadow: 0 4px 15px rgba(0, 0, 0, 0.4);
          transition: all 0.1s ease;
          display: flex;
          flex-direction: column;
          gap: 6px;
          line-height: 1.35;
          --accent-color: ${riskColor};
        }

        /* Styles */
        .theme-cyber {
          background-color: #0b0f19;
          border: 1px solid #1e293b;
          border-left: 3px solid var(--accent-color);
          color: #f3f4f6;
        }

        .theme-slate {
          background-color: #0f172a;
          border: 1px solid #1e293b;
          border-left: 3px solid var(--accent-color);
          color: #f1f5f9;
        }

        .intent-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          width: 100%;
        }

        .intent-label {
          font-size: 10.5px;
          font-weight: 700;
          color: #e2e8f0;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }

        .intent-confidence {
          font-size: 8.5px;
          font-weight: 600;
          color: ${data.intentConfidence === 'Strong' ? '#10b981' : '#f59e0b'};
          text-transform: uppercase;
        }

        .caution-row {
          font-size: 11px;
          font-weight: 600;
          color: var(--accent-color);
        }

        .dest-url {
          font-size: 10px;
          font-family: monospace;
          color: #94a3b8;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
          background: rgba(255, 255, 255, 0.03);
          padding: 2px 4px;
          border-radius: 3px;
        }

        .explanation-text {
          font-size: 11px;
          color: #cbd5e1;
        }

        .chips-container {
          display: flex;
          flex-wrap: wrap;
          gap: 4px;
          margin-top: 2px;
        }

        .chip {
          font-size: 9px;
          font-weight: 700;
          padding: 1px 4px;
          border-radius: 3px;
          text-transform: uppercase;
          letter-spacing: 0.3px;
        }

        .chip.chip-safe {
          background: rgba(16, 185, 129, 0.1);
          color: #10b981;
          border: 1px solid rgba(16, 185, 129, 0.2);
        }

        .chip.chip-email {
          background: rgba(6, 182, 212, 0.1);
          color: #06b6d4;
          border: 1px solid rgba(6, 182, 212, 0.2);
        }

        .chip.chip-warning {
          background: rgba(245, 158, 11, 0.1);
          color: #f59e0b;
          border: 1px solid rgba(245, 158, 11, 0.2);
        }

        .chip.chip-danger {
          background: rgba(239, 68, 68, 0.1);
          color: #ef4444;
          border: 1px solid rgba(239, 68, 68, 0.2);
        }

        .disclaimer-footer {
          font-size: 8px;
          text-align: center;
          color: #64748b;
          font-style: italic;
          border-top: 1px dashed rgba(255, 255, 255, 0.08);
          padding-top: 4px;
          margin-top: 2px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
      </style>
    `;

    const chips = [];
    const isEmail = url.toLowerCase().startsWith("mailto:") || /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(url.trim());
    let isHttps = false;
    if (isEmail) {
      chips.push('<span class="chip chip-email">EMAIL</span>');
    } else {
      // Use rawHref protocol if it's absolute, otherwise fall back to resolved url
      // url is now canonicalUrl — already has the correct protocol from rawHref
      isHttps = url.toLowerCase().startsWith("https://");
      if (isHttps) {
        chips.push('<span class="chip chip-safe">HTTPS</span>');
      } else {
        chips.push('<span class="chip chip-danger">HTTP</span>');
      }
    }

    if (data.findings && data.findings.length > 0) {
      data.findings.forEach(f => {
        const lower = typeof f === "string" ? f.toLowerCase() : `${f.title || ""} ${f.desc || ""}`.toLowerCase();
        if (lower.includes("typosquatting")) {
          chips.push('<span class="chip chip-danger">Typo Spoof</span>');
        } else if (lower.includes("impersonation")) {
          chips.push('<span class="chip chip-danger">Brand Spoof</span>');
        } else if (lower.includes("homoglyph")) {
          chips.push('<span class="chip chip-danger">Homoglyph</span>');
        } else if (lower.includes("tld")) {
          chips.push('<span class="chip chip-warning">Abused TLD</span>');
        } else if (lower.includes("entropy")) {
          chips.push('<span class="chip chip-warning">High Entropy</span>');
        } else if (lower.includes("redirection") || lower.includes("redirect parameter")) {
          chips.push('<span class="chip chip-warning">Redirect Param</span>');
        } else if (lower.includes("shortened")) {
          chips.push('<span class="chip chip-warning">Shortener</span>');
        } else if (lower.includes("executable")) {
          chips.push('<span class="chip chip-danger">Executable</span>');
        } else if (lower.includes("archive")) {
          chips.push('<span class="chip chip-warning">Archive</span>');
        } else if (lower.includes("banking") || lower.includes("bank")) {
          chips.push('<span class="chip chip-danger">Bank Spoof</span>');
        }
      });
    }

    if (chips.length === 1 && (isHttps || isEmail)) {
      chips.push('<span class="chip chip-safe">Clean Profile</span>');
    }

    wrapper.className = `theme-${theme}`;
    wrapper.innerHTML = `
      ${styleBlock}
      <div class="intent-header">
        <span class="intent-label">${data.intent}</span>
        <span class="intent-confidence">[${data.intentConfidence || 'Weak'}]</span>
      </div>
      <div class="caution-row">${data.cautionLevel}</div>
      ${(() => {
        let displayHost = url;

        try {
          displayHost = new URL(url).host;
        } catch (e) {}

        return `
          <div class="dest-url" title="${displayHost}">
            ${displayHost}
          </div>
        `;
      })()}
      <div class="explanation-text">${data.explanation}</div>
      <div class="chips-container">
        ${chips.join("")}
      </div>
      <div class="disclaimer-footer">Passive structural scan only</div>
    `;
  }

  /**
   * 3. PASSIVE BROWSER INTELLIGENCE WATCHERS
   * Tracks tabjacking, clipboard modifications, fake alerts, redirects and downloads.
   */
  function initPassiveBehaviorWatchers() {
    let userClicked = false;
    document.addEventListener("click", () => {
      userClicked = true;
      setTimeout(() => { userClicked = false; }, 50);
    }, { capture: true, passive: true });

    // --- A. Tabjacking Detector ---
    let initialTitle = document.title;
    const titleObserver = new MutationObserver(() => {
      if (document.visibilityState === 'hidden' && document.title !== initialTitle) {
        reportAnomaly("tabjacking", "Hidden Tab Hijacking (Tabjacking)", `The page altered its title from "${initialTitle}" to "${document.title}" while running in a hidden background tab, which is a common tactic to lure users back or mimic other tabs.`);
        initialTitle = document.title;
      }
    });
    
    // Fallback if title element doesn't exist yet on load
    const startObserver = () => {
      const titleEl = document.querySelector('title');
      if (titleEl) {
        titleObserver.observe(titleEl, { subtree: true, characterData: true, childList: true });
      } else {
        setTimeout(startObserver, 1000);
      }
    };
    startObserver();

    // --- B. Tab-under Redirection Detector ---
    window.addEventListener("beforeunload", () => {
      if (document.visibilityState === 'hidden') {
        reportAnomaly("tabunder", "Hidden Tab Redirection (Tab-under)", "The page initiated a network redirection while the tab was running in the background, typical of sneaky ad campaigns or unauthorized redirects.");
      }
    });

    // --- C. Suspicious Download Interceptor ---
    document.addEventListener("click", (e) => {
      const anchor = e.target.closest("a");
      if (!anchor) return;
      const href = anchor.href || "";
      
      // Detect double extensions (e.g. invoice.pdf.exe)
      const doubleExtMatch = href.match(/\.([a-z0-9]{2,5})\.([a-z0-9]{2,5})($|\?)/i);
      if (doubleExtMatch) {
        const secondExt = doubleExtMatch[2].toLowerCase();
        const dangerousExtensions = ["exe", "msi", "scr", "bat", "cmd", "vbs", "ps1", "lnk", "zip", "cab"];
        if (dangerousExtensions.includes(secondExt)) {
          reportAnomaly("suspicious_download", "Masked Dangerous Download", `Attempted to download a file with a masked double extension: "${href.split('/').pop() || href}". The outer extension is .${secondExt} which is an executable file format.`);
          return;
        }
      }

      // Detect raw executable files
      try {
        const urlObj = new URL(href);
        const path = urlObj.pathname.toLowerCase();
        const dangerousExtensions = [".exe", ".msi", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".lnk"];
        const matchedExt = dangerousExtensions.find(ext => path.endsWith(ext));
        if (matchedExt) {
          reportAnomaly("dangerous_download", "Executable File Download Target", `The user clicked a link targeting a raw executable binary file (${matchedExt}): "${href.split('/').pop() || href}".`);
        }
      } catch (err) {}
    }, { capture: true });

    // --- D. Clipboard Action Monitor ---
    document.addEventListener("copy", (e) => {
      const selectedText = window.getSelection().toString();
      if (e.clipboardData) {
        const originalSetData = e.clipboardData.setData;
        e.clipboardData.setData = function(format, value) {
          if (format === "text/plain" && value && value !== selectedText) {
            reportAnomaly("clipboard_hijack", "Forced Clipboard Modification", "The website intercepted your copy action and altered the copied text content dynamically, which is frequently used to hijack cryptocurrency wallet addresses or command line blocks.");
          }
          return originalSetData.apply(this, arguments);
        };
      }
    });

    // Capture direct programmatic clipboard write attempts
    if (navigator.clipboard && navigator.clipboard.writeText) {
      const originalWriteText = navigator.clipboard.writeText;
      navigator.clipboard.writeText = function(text) {
        if (!userClicked) {
          reportAnomaly("clipboard_write", "Direct Clipboard Write Action", "The page attempted to write text to your system clipboard programmatically without an explicit user copy command.");
        }
        return originalWriteText.apply(this, arguments);
      };
    }

    // --- E. Fake Update & Urgent Prompts Scanner ---
    function scanForFakeUpdates() {
      const text = (document.body ? document.body.innerText : "").toLowerCase();
      const fakeUpdateKeywords = [
        "update your browser to view",
        "chrome update required",
        "critical virus alert",
        "windows security warning",
        "update flash player",
        "install extension to proceed",
        "account suspended",
        "verify immediately to avoid closure"
      ];
      const found = fakeUpdateKeywords.find(kw => text.includes(kw));
      if (found) {
        reportAnomaly("fake_update", "Urgent Social Engineering Prompts", `Detected visual elements mimicking official alerts or browser update prompts ("${found}"). This is a common social engineering tactic to deliver malware.`);
      }
    }
    // Run after DOM settles
    setTimeout(scanForFakeUpdates, 1500);

    // --- F. Excessive Popups Spawning ---
    let popupCount = 0;
    const originalOpen = window.open;
    window.open = function() {
      popupCount++;
      if (popupCount > 2) {
        reportAnomaly("excessive_popups", "Excessive Popup Spawning", "The website is launching multiple background tabs or popup windows, which matches clickjacking and redirect-spam behavior.");
      }
      return originalOpen.apply(this, arguments);
    };

    // --- G. Automated Redirect Refreshes ---
    const metaRefresh = document.querySelector('meta[http-equiv="refresh"]');
    if (metaRefresh) {
      reportAnomaly("meta_refresh", "Automated Meta Redirect", "The page uses a metadata refresh tag to force your browser to redirect to another URL automatically.");
    }

    window.addEventListener("beforeunload", () => {
      if (!userClicked && performance.now() < 5000) {
        reportAnomaly("rapid_redirect", "Unsolicited Rapid Redirection", "The page redirected you to another destination within seconds of loading without any user clicks or interactions.");
      }
    });

    // --- H. Dynamic Input Injection Monitor ---
    const formObserver = new MutationObserver((mutations) => {
      let formAdded = false;
      for (const mutation of mutations) {
        if (mutation.addedNodes.length) {
          for (const node of mutation.addedNodes) {
            if (node.nodeType === Node.ELEMENT_NODE) {
              if (
                node.querySelector('input[type="password"]') || 
                node.querySelector('iframe[src*="stripe"]') ||
                node.querySelector('iframe[src*="paypal"]') ||
                (node.tagName === 'INPUT' && node.type === 'password')
              ) {
                formAdded = true;
                break;
              }
            }
          }
        }
        if (formAdded) break;
      }
      if (formAdded) {
        reportAnomaly("dynamic_form", "Delayed Input Form Injection", "An input credentials field or card transaction frame was dynamically injected into the page body after loading. This is common in spoofing interfaces designed to evade headless security crawlers.");
      }
    });
    if (document.body) {
      formObserver.observe(document.body, { childList: true, subtree: true });
    }

    // --- I. Forced Fullscreen Scam Monitor ---
    if (Element.prototype.requestFullscreen) {
      const originalRequest = Element.prototype.requestFullscreen;
      Element.prototype.requestFullscreen = function() {
        if (!userClicked) {
          reportAnomaly("forced_fullscreen", "Unauthorized Fullscreen Locking", "The page attempted to activate fullscreen mode automatically without any prior user interaction. Fake support scams use this behavior to mimic official desktop applications and lock user navigation.");
        }
        return originalRequest.apply(this, arguments);
      };
    }
  }

  function reportAnomaly(type, title, desc) {
    safeSendMessage({
      action: "reportBehavioralAnomaly",
      anomaly: {
        type: type,
        title: title,
        desc: desc,
        timestamp: Date.now()
      }
    });
  }
})();
