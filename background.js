// Import our utility functions for use in passive tab scoring
importScripts("utils.js");

// In-memory behavioral logs
const tabBehaviorLogs = {};
const tabOrigins = {};

// Initialize context menu on install
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "analyzeLink",
    title: "Analyze Link with Pre-Analyzer",
    contexts: ["link"]
  });
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId === "analyzeLink") {
    chrome.windows.create({
      url: `popup.html?url=${encodeURIComponent(info.linkUrl)}`,
      type: "popup",
      width: 420,
      height: 600
    });
  }
});

// Listen for tab activation and page load events to update passive warning badges
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (tab && tab.url && /^https?:\/\//i.test(tab.url)) {
    try {
      const u = new URL(tab.url);
      const host = u.hostname;
      // If the origin changed, reset passive behavioral anomalies
      if (tabOrigins[tabId] && tabOrigins[tabId] !== host) {
        tabBehaviorLogs[tabId] = [];
      }
      tabOrigins[tabId] = host;
    } catch (e) {
      tabBehaviorLogs[tabId] = [];
    }
    updateTabBadge(tab.url);
  }
});

chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (tab && tab.url && /^https?:\/\//i.test(tab.url)) {
      updateTabBadge(tab.url);
    }
  });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabBehaviorLogs[tabId];
  delete tabOrigins[tabId];
});

// Local cache disabled in background.js

/**
 * Main Message Router
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "reportBehavioralAnomaly") {
    if (!sender.tab) {
      sendResponse({ success: false, error: "No sender tab" });
      return;
    }
    const tabId = sender.tab.id;
    if (!tabBehaviorLogs[tabId]) {
      tabBehaviorLogs[tabId] = [];
    }
    // Avoid duplicates of the same type/title on this tab
    const exists = tabBehaviorLogs[tabId].some(a => a.type === request.anomaly.type && a.title === request.anomaly.title);
    if (!exists) {
      tabBehaviorLogs[tabId].push(request.anomaly);
    }
    sendResponse({ success: true });
    return;
  }

  if (request.action === "getTabBehaviors") {
    const tabId = request.tabId;
    sendResponse({ success: true, behaviors: tabBehaviorLogs[tabId] || [] });
    return;
  }

  if (request.action === "traceRedirects") {
    traceRedirectChain(request.url)
      .then(result => {
        sendResponse({ success: true, ...result, cached: false });
      })
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true; // async
  }

  if (request.action === "getLiveDnsInfo") {
    resolveAllDnsRecords(request.domain)
      .then(dnsRecords => {
        const ip = dnsRecords.a.length > 0 ? dnsRecords.a[0] : null;
        const fetchGeo = ip ? getGeoIpInfo(ip) : Promise.resolve(null);
        return fetchGeo.then(geo => {
          const resData = {
            ip: ip || "Unresolved",
            geo: geo,
            dnsRecords: dnsRecords,
            cached: false
          };
          sendResponse({ success: true, ...resData });
        });
      })
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (request.action === "getDomainAge") {
    Promise.all([
      getDomainAgeRdap(request.domain).catch(err => {
        console.warn("RDAP age fetch error:", err.message);
        return null;
      }),
      getCertTransparencyAge(request.domain).catch(err => {
        console.warn("CT age fetch error:", err.message);
        return null;
      })
    ]).then(([rdapData, certData]) => {
      const combined = {
        ageDays: rdapData ? rdapData.ageDays : null,
        lifecycleDays: rdapData ? rdapData.lifecycleDays : null,
        registrar: rdapData ? rdapData.registrar : "Unknown Registrar",
        createdDate: rdapData ? rdapData.createdDate : null,
        expirationDate: rdapData ? rdapData.expirationDate : null,
        cert: certData,
        notFound: (!rdapData && !certData)
      };
      sendResponse({ success: true, data: combined, cached: false });
    }).catch(err => {
      sendResponse({ success: false, error: err.message });
    });
    return true;
  }

  if (request.action === "fetchReputation") {
    const promises = [];
    const vtKey = (request.vtKey || "").trim();
    const abuseKey = (request.abuseKey || "").trim();
    
    if (vtKey) {
      promises.push(checkVirusTotal(request.url, vtKey).then(vt => ({ vt })));
    } else {
      promises.push(Promise.resolve({ vt: null }));
    }
    
    if (abuseKey && request.ip) {
      promises.push(checkAbuseIpDb(request.ip, abuseKey).then(abuse => ({ abuse })));
    } else {
      promises.push(Promise.resolve({ abuse: null }));
    }

    Promise.all(promises)
      .then(results => {
        const vtResult = results.find(r => 'vt' in r)?.vt || null;
        const abuseResult = results.find(r => 'abuse' in r)?.abuse || null;
        
        const resData = { vt: vtResult, abuse: abuseResult, cached: false };
        sendResponse({ success: true, ...resData });
      })
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (request.action === "getQuickScore") {

  (async () => {

    try {

      const targetUrl = request.url || "";

      let parsedUrl;

      try {
        parsedUrl = new URL(targetUrl);
      } catch (err) {
        sendResponse({
          success: false,
          error: "Invalid URL"
        });
        return;
      }

      const hostname = parsedUrl.hostname || "";

      // Detect raw IPs
      const isRawIP =
        /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);

      // Skip unsupported domain logic for raw IPs
      let safeHostname = hostname;

      if (isRawIP) {
        safeHostname = hostname;
      }

      const evaluation = evaluateLocalHeuristics(
        targetUrl,
        request.linkText || "",
        request.hasPasswordFields || false,
        request.hasCardInputs || false
      );

      if (!evaluation || typeof evaluation !== "object") {
        sendResponse({
          success: false,
          error: "Heuristic engine failed"
        });
        return;
      }

      // Always normalize response structure
      sendResponse({
        success: true,
        ...evaluation,
        hostname: safeHostname,
        isRawIP
      });

    } catch (e) {

      console.error(
        "[Pre-Analyzer] getQuickScore failure:",
        e
      );

      sendResponse({
        success: false,
        error: e.message || "Unknown analysis error"
      });
    }

  })();

  return true;
}

  if (request.action === "getExplainItems") {
    try {
      const items = getScoreExplainItems(
        request.url,
        request.isEmail,
        request.findings,
        request.activeDnsResult,
        request.activeAgeResult,
        request.activeTabBehaviors,
        request.activeReputationData
      );
      sendResponse({ success: true, items: items });
    } catch (e) {
      sendResponse({ success: false, error: e.message });
    }
    return true;
  }
});

/**
 * Traces the redirect hops of a URL sequentially using redirect: "manual".
 */
async function traceRedirectChain(startUrl) {
  let currentUrl = startUrl;
  const chain = [currentUrl];
  let redirectCount = 0;
  const maxRedirects = 10;
  let status = "completed";

  while (redirectCount < maxRedirects) {
    try {
      new URL(currentUrl);
    } catch (e) {
      break; 
    }

    try {
      let response = await fetch(currentUrl, {
        method: "HEAD",
        redirect: "manual"
      });

      if (response.status === 405 || response.status === 403) {
        response = await fetch(currentUrl, {
          method: "GET",
          redirect: "manual"
        });
      }

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        if (location) {
          const nextUrl = new URL(location, currentUrl).href;
          if (chain.includes(nextUrl)) {
            chain.push(nextUrl);
            status = "circular";
            break;
          }
          currentUrl = nextUrl;
          chain.push(currentUrl);
          redirectCount++;
        } else {
          break;
        }
      } else {
        break;
      }
    } catch (err) {
      status = "network_limit";
      break;
    }
  }

  if (redirectCount >= maxRedirects) {
    status = "max_limit";
  }

  return {
    chain: chain,
    finalUrl: currentUrl,
    hops: redirectCount,
    status: status
  };
}

/**
 * Resolves a hostname to an IP address using Cloudflare DNS-over-HTTPS
 */
async function queryDohRecord(domain, type) {
  try {
    const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`, {
      headers: { Accept: "application/dns-json" }
    });
    if (!response.ok) return [];
    const data = await response.json();
    return data.Answer || [];
  } catch (e) {
    return [];
  }
}

async function resolveAllDnsRecords(domain) {
  const cleanDomain = domain.split(':')[0];
  try {
    const [aAns, nsAns, mxAns, txtAns] = await Promise.all([
      queryDohRecord(cleanDomain, "A"),
      queryDohRecord(cleanDomain, "NS"),
      queryDohRecord(cleanDomain, "MX"),
      queryDohRecord(cleanDomain, "TXT")
    ]);
    
    const aRecords = aAns.filter(ans => ans.type === 1).map(ans => ans.data);
    const nsRecords = nsAns.filter(ans => ans.type === 2).map(ans => ans.data);
    const mxRecords = mxAns.filter(ans => ans.type === 15).map(ans => ans.data);
    const txtRecords = txtAns.filter(ans => ans.type === 16).map(ans => ans.data);
    
    const hasSpf = txtRecords.some(rec => {
      const cleanRec = rec.replace(/"/g, "").trim().toLowerCase();
      return cleanRec.startsWith("v=spf1") || cleanRec.includes("spf1");
    });

    const spfRecord = txtRecords.find(rec => {
      const cleanRec = rec.replace(/"/g, "").trim().toLowerCase();
      return cleanRec.startsWith("v=spf1") || cleanRec.includes("spf1");
    });
    
    return {
      a: aRecords,
      ns: nsRecords,
      mx: mxRecords,
      txt: txtRecords,
      hasSpf: hasSpf,
      spf: spfRecord ? spfRecord.replace(/"/g, "").trim() : null
    };
  } catch (e) {
    return {
      a: [],
      ns: [],
      mx: [],
      txt: [],
      hasSpf: false
    };
  }
}

/**
 * Fetches country, ISP, and ASN for a resolved IP
 */
async function getGeoIpInfo(ip) {
  if (!ip) return null;
  try {
    const response = await fetch(`https://ipapi.co/${ip}/json/`);
    if (!response.ok) return null;
    const data = await response.json();
    if (data && !data.error) {
      return {
        asn: data.asn || "Unknown",
        org: data.org || "Unknown",
        country: data.country_name || "Unknown",
        countryCode: data.country || "",
        city: data.city || "Unknown"
      };
    }
  } catch (e) {
    // GeoIP fail
  }
  return null;
}

/**
 * Fetches registration events and registrar info using RDAP
 */
async function getDomainAgeRdap(domain) {
  try {
    const parts = domain.toLowerCase().split('.');
    if (parts.length < 2) return null;
    
    const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
    if (!response.ok) return null;
    const data = await response.json();
    
    let createdDate = null;
    let expirationDate = null;
    let registrar = "Unknown";

    if (data.events) {
      const regEvent = data.events.find(ev => 
        ev.eventAction === "registration" || 
        ev.eventAction === "creation"
      ) || data.events.find(ev => ev.eventAction.includes("creat"));
      
      if (regEvent) {
        createdDate = regEvent.eventDate;
      }

      const expEvent = data.events.find(ev => 
        ev.eventAction === "expiration" || 
        ev.eventAction === "registration expiration"
      ) || data.events.find(ev => ev.eventAction.includes("expir"));
      
      if (expEvent) {
        expirationDate = expEvent.eventDate;
      }
    }

    if (data.entities) {
      const registrarEntity = data.entities.find(ent => 
        ent.roles && ent.roles.includes("registrar")
      );
      if (registrarEntity) {
        if (registrarEntity.vcardArray && registrarEntity.vcardArray[1]) {
          const fnItem = registrarEntity.vcardArray[1].find(item => item[0] === "fn");
          if (fnItem) registrar = fnItem[3];
        } else {
          registrar = registrarEntity.handle || "Unknown";
        }
      }
    }

    if (createdDate) {
      const createdTime = new Date(createdDate).getTime();
      const diffMs = Date.now() - createdTime;
      const ageDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
      
      let lifecycleDays = null;
      if (expirationDate) {
        const expTime = new Date(expirationDate).getTime();
        if (expTime > createdTime) {
          lifecycleDays = Math.floor((expTime - createdTime) / (1000 * 60 * 60 * 24));
        }
      }
      
      return {
        createdDate: createdDate,
        expirationDate: expirationDate,
        lifecycleDays: lifecycleDays,
        ageDays: ageDays,
        registrar: registrar
      };
    }
  } catch (e) {
    // RDAP lookup failed
  }
  return null;
}

function normalizeVirusTotalUrl(rawUrl) {
  const trimmed = (rawUrl || "").trim();
  if (!/^https?:\/\//i.test(trimmed)) {
    return null;
  }

  try {
    return new URL(trimmed).href;
  } catch (e) {
    return null;
  }
}

function encodeVirusTotalUrlId(url) {
  const utf8Bytes = new TextEncoder().encode(url);
  let binary = "";
  for (let i = 0; i < utf8Bytes.byteLength; i++) {
    binary += String.fromCharCode(utf8Bytes[i]);
  }
  return btoa(binary)
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function formatVirusTotalStats(stats, sourceStatus = "success") {
  const safeStats = stats || {};
  return {
    status: sourceStatus,
    malicious: safeStats.malicious || 0,
    suspicious: safeStats.suspicious || 0,
    harmless: safeStats.harmless || 0,
    undetected: safeStats.undetected || 0,
    total: (safeStats.malicious || 0) + (safeStats.suspicious || 0) + (safeStats.harmless || 0) + (safeStats.undetected || 0)
  };
}

async function getVirusTotalAnalysis(analysisId, apiKey) {
  if (!analysisId) return null;

  const maxAttempts = 6;      // poll up to 6 times
  const pollInterval = 5000;  // 5 seconds between each attempt

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    // Wait before each poll (including the first, giving VT time to start)
    await new Promise(resolve => setTimeout(resolve, pollInterval));

    const response = await fetch(`https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(analysisId)}`, {
      headers: { "x-apikey": apiKey }
    });

    if (!response.ok) return null;

    const data = await response.json();
    const attributes = data && data.data && data.data.attributes;
    if (!attributes || !attributes.stats) return null;

    if (attributes.status === "completed") {
      return formatVirusTotalStats(attributes.stats, "success");
    }
    // Not completed yet — loop and try again
  }

  // Exhausted all attempts — return whatever stats we have as partial
  return { status: "submitted_for_scan", malicious: 0, suspicious: 0, harmless: 0, undetected: 0, total: 0 };
}

/**
 * Queries VirusTotal URL report via V3 API
 */
async function checkVirusTotal(url, apiKey) {
  if (!apiKey) return null;

  const normalizedUrl = normalizeVirusTotalUrl(url);
  if (!normalizedUrl) {
    return { status: "unsupported" };
  }

  try {
    const urlId = encodeVirusTotalUrlId(normalizedUrl);
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { "x-apikey": apiKey }
    });
    
    if (response.status === 401 || response.status === 403) {
      console.warn("[Pre-Analyzer] VirusTotal API key authentication error:", response.status);
      return { status: "error", error: "VirusTotal API key rejected" };
    }

    if (response.status === 429) {
      console.warn("[Pre-Analyzer] VirusTotal API rate limit reached.");
      return { status: "error", error: "VirusTotal rate limit reached" };
    }
    
    if (response.status === 404) {
      console.log("[Pre-Analyzer] URL not found on VirusTotal, submitting for scan:", normalizedUrl);
      const postResponse = await fetch("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: {
          "x-apikey": apiKey,
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({ url: normalizedUrl })
      });

      if (!postResponse.ok) {
        console.warn("[Pre-Analyzer] VirusTotal URL submission failed:", postResponse.status);
        return { status: "not_found" };
      }

      const postData = await postResponse.json();
      const analysisId = postData && postData.data && postData.data.id;
      const analysis = await getVirusTotalAnalysis(analysisId, apiKey);
      return analysis || { status: "submitted_for_scan", malicious: 0, suspicious: 0, harmless: 0, undetected: 0, total: 0 };
    }

    if (response.ok) {
      const data = await response.json();
      const attributes = data && data.data && data.data.attributes;
      if (attributes && attributes.last_analysis_stats) {
        return formatVirusTotalStats(attributes.last_analysis_stats);
      }
    }

    console.warn("[Pre-Analyzer] Unexpected VirusTotal response:", response.status);
    return { status: "error", error: `Unexpected VirusTotal response: ${response.status}` };
  } catch (e) {
    console.error("[Pre-Analyzer] Exception in checkVirusTotal:", e);
    return { status: "error", error: e.message };
  }
}
/**
 * Queries IP abuse profile on AbuseIPDB
 */
async function checkAbuseIpDb(ip, apiKey) {
  if (!apiKey || !ip) return null;
  try {
    const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
      headers: {
        Key: apiKey,
        Accept: "application/json"
      }
    });
    if (response.status === 401 || response.status === 403) {
      console.warn("[Pre-Analyzer] AbuseIPDB API key authentication error:", response.status);
      return { status: "error" };
    }
    if (response.ok) {
      const data = await response.json();
      if (data.data) {
        return {
          status: "success",
          abuseScore: data.data.abuseConfidenceScore,
          totalReports: data.data.totalReports,
          lastReportedAt: data.data.lastReportedAt
        };
      }
    }
  } catch (e) {
    // AbuseIPDB query failed
  }
  return null;
}

/**
 * Runs passive scoring of a URL and updates the browser action badge
 */
function updateTabBadge(url) {
  try {
    const evaluation = evaluateLocalHeuristics(url, "", false, false);
    if (!evaluation || !evaluation.success) return;

    let badgeText = "OK";
    let badgeColor = "#10b981";
    
    if (evaluation.score >= 55) {
      badgeText = "SUS";
      badgeColor = "#ef4444";
    } else if (evaluation.score >= 25) {
      badgeText = "WRN";
      badgeColor = "#f59e0b";
    }
    
    chrome.action.setBadgeText({ text: badgeText });
    chrome.action.setBadgeBackgroundColor({ color: badgeColor });
  } catch (e) {
    // silent fail
  }
}

/**
 * Queries public crt.sh to retrieve Certificate Transparency issuance age
 */
async function getCertTransparencyAge(domain) {
  try {
    const cleanDomain = domain.split(':')[0];
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000); // 3 seconds timeout
    const response = await fetch(`https://crt.sh/?q=${encodeURIComponent(cleanDomain)}&output=json`, {
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (!response.ok) return null;
    const data = await response.json();
    if (!Array.isArray(data) || data.length === 0) return null;
    
    // Find the latest "not_before" date
    let latestTime = 0;
    let latestDateStr = null;
    data.forEach(item => {
      if (item.not_before) {
        const time = new Date(item.not_before).getTime();
        if (time > latestTime) {
          latestTime = time;
          latestDateStr = item.not_before;
        }
      }
    });
    
    if (latestTime > 0) {
      const ageDays = Math.floor((Date.now() - latestTime) / (1000 * 60 * 60 * 24));
      return {
        issuedDate: latestDateStr,
        issuedDaysAgo: ageDays
      };
    }
  } catch (e) {
    // ignore
  }
  return null;
}
