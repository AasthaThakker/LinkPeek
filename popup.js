document.addEventListener("DOMContentLoaded", () => {
  // Elements
  const urlInput = document.getElementById("urlInput");
  const clearBtn = document.getElementById("clearBtn");
  const analyzeBtn = document.getElementById("analyzeBtn");
  const statusPulse = document.getElementById("statusPulse");
  
  const scannerScreen = document.getElementById("scannerScreen");
  const scannerSubtext = document.getElementById("scannerSubtext");
  
  const resultsCard = document.getElementById("resultsCard");
  const riskGauge = document.getElementById("riskGauge");
  const gaugeScore = document.getElementById("gaugeScore");
  const riskBadge = document.getElementById("riskBadge");
  const confidenceBadge = document.getElementById("confidenceBadge");
  const urlBreakdown = document.getElementById("urlBreakdown");
  
  // Threat Story Elements
  const storyIntent = document.getElementById("storyIntent");
  const storyScenario = document.getElementById("storyScenario");

  // Explainability & Transparency Elements
  const layeredScoringTable = document.getElementById("layeredScoringTable");
  const scoreExplainabilityTable = document.getElementById("scoreExplainabilityTable");
  const explainabilityList = document.getElementById("explainabilityList");
  const observedFactsList = document.getElementById("observedFactsList");
  const inferredInterpretationsList = document.getElementById("inferredInterpretationsList");
  const structuralAnomaliesList = document.getElementById("structuralAnomaliesList");
  const behavioralAnomaliesList = document.getElementById("behavioralAnomaliesList");
  const reputationCorroborationList = document.getElementById("reputationCorroborationList");
  const activeThreatsList = document.getElementById("activeThreatsList");

  const scoreLayerStructural = document.getElementById("scoreLayerStructural");
  const scoreLayerBehavioral = document.getElementById("scoreLayerBehavioral");
  const scoreLayerReputation = document.getElementById("scoreLayerReputation");
  const scoreLayerRuntime = document.getElementById("scoreLayerRuntime");
  const overallConcernValue = document.getElementById("overallConcernValue");
  const finalContextualScore = document.getElementById("finalContextualScore");
  
  const repApiBar = document.getElementById("repApiBar");
  const fetchRepBtn = document.getElementById("fetchRepBtn");
  const liveRepBox = document.getElementById("liveRepBox");
  const vtScore = document.getElementById("vtScore");
  
  const cacheBadge = document.getElementById("cacheBadge");
  
  const evidenceDetails = document.getElementById("evidenceDetails");
  const redirectCount = document.getElementById("redirectCount");
  const chainList = document.getElementById("chainList");
  
  const timelineFlow = document.getElementById("timelineFlow");
  const dnsIp = document.getElementById("dnsIp");
  const dnsOrg = document.getElementById("dnsOrg");
  const dnsRegistrar = document.getElementById("dnsRegistrar");
  const dnsCountry = document.getElementById("dnsCountry");
  
  const metricEntropy = document.getElementById("metricEntropy");
  const metricProtocol = document.getElementById("metricProtocol");
  
  const errorCard = document.getElementById("errorCard");
  const errorMsg = document.getElementById("errorMsg");
  
  // Settings elements
  const activeScanToggle = document.getElementById("activeScanToggle");
  const tooltipToggle = document.getElementById("tooltipToggle");
  const saveSettingsBtn = document.getElementById("saveSettingsBtn");
  const vtApiKeyInput = document.getElementById("vtApiKey");
  
  // State
  let currentTargetUrl = "";
  let resolvedIpAddress = "";
  let baseThreatScore = 0;
  let activeReputationData = null;
  let activeDnsResult = null;
  let activeAgeResult = null;
  let cacheHitDetected = false;
  let activeTabBehaviors = [];
  let lastFindings = [];
  let currentIsEmail = false;

  // Load Saved Configurations
  chrome.storage.local.get({
    activeScanEnabled: true,
    tooltipEnabled: true,
    tooltipStyle: "cyber",
    vtApiKey: "",
  }, (items) => {
    activeScanToggle.checked = items.activeScanEnabled;
    tooltipToggle.checked = items.tooltipEnabled;
    vtApiKeyInput.value = items.vtApiKey;
    
    const themeRadio = document.querySelector(`input[name="tooltipTheme"][value="${items.tooltipStyle}"]`);
    if (themeRadio) themeRadio.checked = true;

    // Check if we were launched with a URL parameter (e.g. from context menu)
    const urlParams = new URLSearchParams(window.location.search);
    const urlParam = urlParams.get("url");
    if (urlParam) {
      urlInput.value = urlParam;
      clearBtn.style.display = "block";
      runAnalysis(urlParam);
    } else {
      // Default to analyzing the active tab
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs && tabs[0] && tabs[0].url && /^https?:\/\//i.test(tabs[0].url)) {
          urlInput.value = tabs[0].url;
          clearBtn.style.display = "block";
          runAnalysis(tabs[0].url);
        }
      });
    }
  });

  // Save Configurations
  saveSettingsBtn.addEventListener("click", () => {
    const activeScanEnabled = activeScanToggle.checked;
    const tooltipEnabled = tooltipToggle.checked;
    const tooltipStyle = document.querySelector('input[name="tooltipTheme"]:checked').value;
    const vtApiKey = vtApiKeyInput.value.trim();

    let valid = true;
    vtApiKeyInput.style.borderColor = "";

    if (vtApiKey && !/^[a-zA-Z0-9]{64}$/.test(vtApiKey)) {
      vtApiKeyInput.style.borderColor = "#ef4444";
      valid = false;
    }

    if (!valid) {
      const originalText = saveSettingsBtn.innerText;
      saveSettingsBtn.innerText = "INVALID KEY FORMAT!";
      saveSettingsBtn.style.background = "#ef4444";
      saveSettingsBtn.style.borderColor = "#ef4444";
      setTimeout(() => {
        saveSettingsBtn.innerText = originalText;
        saveSettingsBtn.style.background = "";
        saveSettingsBtn.style.borderColor = "";
      }, 2000);
      return;
    }

    chrome.storage.local.set({
      activeScanEnabled,
      tooltipEnabled,
      tooltipStyle,
      vtApiKey,
    }, () => {
      // Temporarily highlight save button
      const originalText = saveSettingsBtn.innerText;
      saveSettingsBtn.innerText = "CONFIGURATION SECURED!";
      saveSettingsBtn.style.background = "#10b981";
      saveSettingsBtn.style.borderColor = "#10b981";
      setTimeout(() => {
        saveSettingsBtn.innerText = originalText;
        saveSettingsBtn.style.background = "";
        saveSettingsBtn.style.borderColor = "";
      }, 1500);
    });
  });

  // Clear Scan Cache button
  const clearCacheBtn = document.getElementById("clearCacheBtn");
  if (clearCacheBtn) {
    clearCacheBtn.addEventListener("click", () => {
      chrome.storage.local.get({ vtApiKey: "" }, (items) => {
        const vtKey = items.vtApiKey;
        const activeScan = activeScanToggle.checked;
        const tooltip = tooltipToggle.checked;
        const themeRadio = document.querySelector('input[name="tooltipTheme"]:checked');
        const theme = themeRadio ? themeRadio.value : "cyber";
        
        chrome.storage.local.clear(() => {
          chrome.storage.local.set({
            vtApiKey: vtKey,
            activeScanEnabled: activeScan,
            tooltipEnabled: tooltip,
            tooltipStyle: theme
          }, () => {
            clearCacheBtn.innerText = "CACHE CLEARED!";
            setTimeout(() => { clearCacheBtn.innerText = "Clear Scan Cache"; }, 2000);
          });
        });
      });
    });

    clearCacheBtn.addEventListener("mouseover", () => {
      clearCacheBtn.style.borderColor = "#ef4444";
      clearCacheBtn.style.color = "#ef4444";
    });
    clearCacheBtn.addEventListener("mouseout", () => {
      clearCacheBtn.style.borderColor = "var(--border-color)";
      clearCacheBtn.style.color = "var(--text-secondary)";
    });
  }

  // Clear button logic
  urlInput.addEventListener("input", () => {
    clearBtn.style.display = urlInput.value ? "block" : "none";
  });

  clearBtn.addEventListener("click", () => {
    urlInput.value = "";
    clearBtn.style.display = "none";
    urlInput.focus();
  });

  // Click handler for analyze button
  analyzeBtn.addEventListener("click", () => {
    const url = urlInput.value.trim();
    if (url) {
      runAnalysis(url);
    }
  });

  // Enter key press support
  urlInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const url = urlInput.value.trim();
      if (url) {
        runAnalysis(url);
      }
    }
  });

  // On-demand reputation lookup button listener
  fetchRepBtn.addEventListener("click", () => {
    if (!currentTargetUrl) return;
    
    fetchRepBtn.disabled = true;
    fetchRepBtn.querySelector("span").innerText = "Querying Threat Reputations...";

    chrome.storage.local.get({ vtApiKey: ""}, (keys) => {
      chrome.runtime.sendMessage({
        action: "fetchReputation",
        url: currentTargetUrl,
        ip: resolvedIpAddress,
        vtKey: keys.vtApiKey.trim(),
      }, (response) => {
        fetchRepBtn.disabled = false;
        fetchRepBtn.querySelector("span").innerText = "On-Demand reputation Check (VT)";

        if (response && response.success) {
          activeReputationData = response;
          if (response.cached) {
            cacheHitDetected = true;
          }
          renderReputationDetails(response);
          recalculateFinalScore(lastFindings);
        } else {
          alert("Failed to reach reputation API endpoints. Check configuration keys.");
        }
      });
    });
  });

  /**
   * Main orchestrator for URL scanning
   */
  async function runAnalysis(urlStr) {
    // 1. Reset Dashboard
    errorCard.style.display = "none";
    resultsCard.style.display = "none";
    liveRepBox.style.display = "none";
    activeReputationData = null;
    activeDnsResult = null;
    activeAgeResult = null;
    resolvedIpAddress = "";
    cacheHitDetected = false;
    activeTabBehaviors = [];

    // 2. Validate URL Format & Prepend Protocol if needed
    let formattedUrl = urlStr.trim();
    const isEmail = isEmailOrMailto(formattedUrl);
    if (isEmail) {
      if (!formattedUrl.toLowerCase().startsWith("mailto:")) {
        formattedUrl = "mailto:" + formattedUrl;
      }
    } else {
      if (!/^https?:\/\//i.test(formattedUrl)) {
        formattedUrl = "https://" + formattedUrl;
      }
    }

    let urlObj;
    try {
      urlObj = new URL(formattedUrl);
      currentTargetUrl = isEmail ? formattedUrl : urlObj.href;
    } catch (e) {
      showError("Invalid URL syntax. Ensure the hostname is formatted properly (e.g. google.com).");
      return;
    }

    currentIsEmail = isEmail;

    // Show/hide MX/SPF containers based on email target
    const mxContainer = document.getElementById("dnsMxContainer");
    const spfContainer = document.getElementById("dnsSpfContainer");
    if (mxContainer && spfContainer) {
      if (currentIsEmail) {
        mxContainer.style.display = "flex";
        spfContainer.style.display = "flex";
      } else {
        mxContainer.style.display = "none";
        spfContainer.style.display = "none";
      }
    }

    // 3. Show Scanning UI and set loading subtext
    scannerScreen.style.display = "block";
    scannerSubtext.innerText = "Analyzing domain characteristics...";

    // 4. Load setting configurations to decide active tracing
    chrome.storage.local.get({ activeScanEnabled: true, vtApiKey: "" }, async (settings) => {
      try {
        const hostname = currentIsEmail ? extractDomainFromEmailOrMailto(formattedUrl) : urlObj.hostname;
        const protocol = currentIsEmail ? "mailto:" : urlObj.protocol;

        // Query background behavioral anomalies if url matches active tab
        await new Promise((resolve) => {
          chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs && tabs[0] && tabs[0].url === currentTargetUrl) {
              chrome.runtime.sendMessage({ action: "getTabBehaviors", tabId: tabs[0].id }, (response) => {
                if (response && response.success) {
                  activeTabBehaviors = response.behaviors || [];
                }
                resolve();
              });
            } else {
              resolve();
            }
          });
        });

        // Perform local heuristics scan
        const evaluation = evaluateLocalHeuristics(urlObj.href, "", false, false);
        const findings = evaluation.findings || [];
        lastFindings = findings;
        
        // Render URL parts
        renderUrlBreakdown(urlObj);

        // Fetch API configurations to check visibility of the Fetch button
        chrome.storage.local.get({ vtApiKey: "" }, (freshKeys) => {
          if (freshKeys.vtApiKey.trim()) {
            repApiBar.style.display = "flex";
          } else {
            repApiBar.style.display = "none";
          }
        });
        // Active Redirect Chain tracing
        let redirectResult = null;
        if (settings.activeScanEnabled && !currentIsEmail) {
          scannerSubtext.innerText = "Tracing active network redirect paths...";
          redirectResult = await traceRedirectsAsync(currentTargetUrl);
          if (redirectResult && redirectResult.cached) {
            cacheHitDetected = true;
          }
        }

        // DNS-over-HTTPS & GeoIP Resolution
        scannerSubtext.innerText = "Querying live DNS registers & ASNs...";
        const dnsResult = await fetchDnsInfoAsync(hostname);
        if (dnsResult && dnsResult.cached) {
          cacheHitDetected = true;
        }

        // RDAP Age Resolver
        scannerSubtext.innerText = "Retrieving RDAP domain registration timeline...";
        const ageResult = await fetchDomainAgeAsync(hostname);
        if (ageResult && ageResult.cached) {
          cacheHitDetected = true;
        }

        activeDnsResult = dnsResult;
        activeAgeResult = ageResult;

        // 5. Hide Loader, Display Dashboards
        scannerScreen.style.display = "none";
        resultsCard.style.display = "block";
        
        // Render Redirect Chain Graphic
        renderRedirectChain(currentTargetUrl, redirectResult);
        
        // Render Trust Timeline Graphic
        renderTrustTimeline(protocol, dnsResult, ageResult);

        // Fill out DNS details grid
        if (dnsResult && dnsResult.success) {
          resolvedIpAddress = dnsResult.ip;
          dnsIp.innerText = dnsResult.ip;
          dnsOrg.innerText = dnsResult.geo ? dnsResult.geo.org : "Unknown ISP";
          dnsCountry.innerText = dnsResult.geo ? `${dnsResult.geo.city}, ${dnsResult.geo.country}` : "Unknown Location";
          
          if (dnsResult.dnsRecords) {
            const recs = dnsResult.dnsRecords;
            const mxEl = document.getElementById("dnsMx");
            if (recs.mx && recs.mx.length > 0) {
              const mxList = recs.mx.map(mx => mx.replace(/\.$/, "")).join(", ");
              mxEl.innerText = mxList;
              mxEl.style.color = "#10b981";
            } else {
              mxEl.innerText = "Missing";
              mxEl.style.color = "#ef4444";
            }
            
            const nsEl = document.getElementById("dnsNs");
            nsEl.innerText = (recs.ns && recs.ns.length > 0) ? "Present" : "Missing";
            nsEl.style.color = (recs.ns && recs.ns.length > 0) ? "#10b981" : "#ef4444";

            const spfEl = document.getElementById("dnsSpf");
            if (recs.hasSpf) {
              spfEl.innerText = recs.spf || "Configured";
              spfEl.style.color = "#10b981";
            } else {
              spfEl.innerText = "Missing";
              spfEl.style.color = "#ef4444";
            }
          } else {
            document.getElementById("dnsMx").innerText = "Missing";
            document.getElementById("dnsMx").style.color = "#ef4444";
            document.getElementById("dnsNs").innerText = "Missing";
            document.getElementById("dnsNs").style.color = "#ef4444";
            document.getElementById("dnsSpf").innerText = "Missing";
            document.getElementById("dnsSpf").style.color = "#ef4444";
          }
        } else {
          dnsIp.innerText = "Unresolved";
          dnsOrg.innerText = "N/A";
          dnsCountry.innerText = "N/A";
          document.getElementById("dnsMx").innerText = "Missing";
          document.getElementById("dnsMx").style.color = "#ef4444";
          document.getElementById("dnsNs").innerText = "Missing";
          document.getElementById("dnsNs").style.color = "#ef4444";
          document.getElementById("dnsSpf").innerText = "Missing";
          document.getElementById("dnsSpf").style.color = "#ef4444";
        }

        if (ageResult && ageResult.success && ageResult.data) {
          dnsRegistrar.innerText = ageResult.data.registrar || "Unknown Registrar";
          const lifecycle = ageResult.data.lifecycleDays;
          document.getElementById("dnsLifecycle").innerText = lifecycle !== null ? `${lifecycle} days` : "Unknown";
          document.getElementById("whoisCreated").innerText = ageResult.data.createdDate
            ? new Date(ageResult.data.createdDate).toLocaleDateString() : "Unknown";
          document.getElementById("whoisExpires").innerText = ageResult.data.expirationDate
            ? new Date(ageResult.data.expirationDate).toLocaleDateString() : "Unknown";
          document.getElementById("whoisAge").innerText = ageResult.data.ageDays !== null
            ? `${ageResult.data.ageDays} days` : "Unknown";
        } else {
          dnsRegistrar.innerText = "Unknown Registrar";
          document.getElementById("dnsLifecycle").innerText = "Unknown";
          document.getElementById("whoisCreated").innerText = "Unknown";
          document.getElementById("whoisExpires").innerText = "Unknown";
          document.getElementById("whoisAge").innerText = "Unknown";
        }
        // Raw metrics cards
        const registered = getRegisteredDomain(hostname);
        const label = registered ? registered.split('.')[0] : "";
        metricEntropy.innerText = label ? calculateEntropy(label).toFixed(2) : "0.00";
        if (currentIsEmail) {
          metricProtocol.innerText = "EMAIL";
          metricProtocol.className = "metric-value email";
        } else {
          metricProtocol.innerText = protocol.toUpperCase().replace(":", "");
          if (protocol === "https:") {
            metricProtocol.className = "metric-value secure";
          } else {
            metricProtocol.className = "metric-value insecure";
          }
        }

        // Render base score logic
        baseThreatScore = evaluation.score;
        
        // Calculate, render narrative cards, and update layers panel
        recalculateFinalScore(findings);

      } catch (err) {
        scannerScreen.style.display = "none";
        showError("Scanning interruption: " + err.message);
      }
    });
  }

  /**
   * Evaluates local heuristics using utils.js checks
   * Categorizes items into "danger" or "suspicious" indicators.
   */
  function runLocalHeuristics(urlObj) {
    const evaluation = evaluateLocalHeuristics(urlObj.href, "", false, false);
    return evaluation.findings || [];
  }

  /**
   * Computes the base threat score from findings array
   */
  function calculateBaseScore(findings) {
    let score = 0;
    findings.forEach(f => {
      if (f.category === "danger") score += 35;
      else if (f.category === "suspicious") score += 15;
    });
    return score;
  }

  /**
   * Dynamic recalculation combining heuristics, trust weights (negative scoring), and live reputations
   */
  function recalculateFinalScore(findings = []) {
    const urlObj = new URL(currentTargetUrl);
    const hostname = currentIsEmail ? extractDomainFromEmailOrMailto(currentTargetUrl) : urlObj.hostname;
    const regDomain = getRegisteredDomain(hostname);
    const label = regDomain ? regDomain.split('.')[0] : "";

    let explainItems = [];

    // Protocol check
    if (!currentIsEmail) {
      if (urlObj.protocol === "http:") {
        explainItems.push({
          name: "HTTP protocol",
          score: 15,
          observed: "Insecure HTTP connection protocol detected",
          inferred: "Risk of credential sniffing and man-in-the-middle data interception",
          category: "structural"
        });
      } else if (urlObj.protocol === "https:") {
        explainItems.push({
          name: "HTTPS secure protocol",
          score: -10,
          observed: "Valid secure HTTPS connection active",
          inferred: "Data in transit is encrypted using standard SSL/TLS",
          category: "structural"
        });
      }
    }

    // IP Domain check
    if (checkIpAddressDomain(urlObj.hostname)) {
      explainItems.push({
        name: "Raw IP URL",
        score: 25,
        observed: "URL hostname resolves to a raw numeric IP address",
        inferred: "Potential unmanaged or temporary hosting bypassing typical DNS filters",
        category: "structural"
      });
    }

    // Suspicious Port
    if (checkSuspiciousPort(currentTargetUrl)) {
      explainItems.push({
        name: "Non-standard port",
        score: 20,
        observed: "URL requests network connection through a non-standard port",
        inferred: "Suggests non-standard administrative backend endpoints",
        category: "structural"
      });
    }

    // DNS A record resolution check
    if (activeDnsResult && activeDnsResult.success) {
      if (!activeDnsResult.dnsRecords || !activeDnsResult.dnsRecords.a || activeDnsResult.dnsRecords.a.length === 0) {
        explainItems.push({
          name: "No direct IPv4 resolution observed during passive lookup",
          score: 10,
          observed: "No active IPv4 A records found for this domain name",
          inferred: "DNS infrastructure exhibits structural anomaly",
          category: "structural"
        });
      }
    }

    // MX / SPF records (only for email)
    if (currentIsEmail && activeDnsResult && activeDnsResult.success && activeDnsResult.dnsRecords) {
      if (!activeDnsResult.dnsRecords.mx || activeDnsResult.dnsRecords.mx.length === 0) {
        explainItems.push({
          name: "Missing MX records",
          score: 15,
          observed: "No active MX records resolved for correspondence domain",
          inferred: "Domain cannot receive incoming emails, highly suspicious for correspondence domains",
          category: "structural"
        });
      }
      if (!activeDnsResult.dnsRecords.hasSpf) {
        explainItems.push({
          name: "No SPF record configured",
          score: 10,
          observed: "Lacks Sender Policy Framework authentication records",
          inferred: "Lacks spoofing protections, allowing unauthorized email senders",
          category: "structural"
        });
      }
    }

    // WHOIS Domain age
    if (activeAgeResult && activeAgeResult.success && activeAgeResult.data) {
      const ageDays = activeAgeResult.data.ageDays;
      const lifecycleDays = activeAgeResult.data.lifecycleDays;
      const registrar = activeAgeResult.data.registrar;

      if (ageDays !== null) {
        if (ageDays < 30) {
          explainItems.push({
            name: "Brand-new domain registration",
            score: 15,
            observed: `Domain registered only ${ageDays} days ago`,
            inferred: "High risk of freshly deployed phishing or scam infrastructure",
            category: "structural"
          });
        } else if (ageDays < 90) {
          explainItems.push({
            name: "Recent domain registration",
            score: 5,
            observed: `Domain registered only ${ageDays} days ago`,
            inferred: "Relatively young domain carrying elevated structural risk",
            category: "structural"
          });
        } else if (ageDays > 3650) {
          explainItems.push({
            name: "Established domain (>10 years)",
            score: -30,
            observed: `Domain has long active registration history of ${Math.floor(ageDays/365)} years`,
            inferred: "Established infrastructure reduces threat likelihood",
            category: "structural"
          });
        } else if (ageDays > 365) {
          explainItems.push({
            name: "Established domain (>1 year)",
            score: -15,
            observed: `Domain has active registration history of ${Math.floor(ageDays/365)} years`,
            inferred: "Established infrastructure reduces threat likelihood",
            category: "structural"
          });
        }
      }

      if (lifecycleDays !== null && lifecycleDays < 365) {
        explainItems.push({
          name: "Short registration lifecycle",
          score: 5,
          observed: `Domain registered for only ${lifecycleDays} days`,
          inferred: "Typical pattern of temporary single-purpose/disposable sites",
          category: "structural"
        });
      }

      if (registrar && (registrar.toLowerCase().includes("godaddy") || registrar.toLowerCase().includes("namecheap"))) {
        explainItems.push({
          name: "Suspicious registrar",
          score: 2,
          observed: `Hosted via low-cost registrar (${registrar})`,
          inferred: "Low entry cost registrar frequently abused for spam campaigns",
          category: "structural"
        });
      }
    } else if (!activeAgeResult || !activeAgeResult.success || (activeAgeResult.data && activeAgeResult.data.notFound)) {
      explainItems.push({
        name: "Unverifiable registry age",
        score: 5,
        observed: "No RDAP domain age records could be resolved",
        inferred: "Lack of historical registry timeline increases infrastructure uncertainty",
        category: "structural"
      });
    }

    // Heuristics findings from evaluateLocalHeuristics
    if (findings && findings.length > 0) {
      findings.forEach(f => {
        const title = f.title;
        if (title.includes("Entropy") && !explainItems.some(i => i.name === "High entropy domain label")) {
          explainItems.push({
            name: "High entropy domain label",
            score: 5,
            observed: "Domain name exhibits high structural character entropy",
            inferred: "Domain name pattern matches randomized Domain Generation Algorithms (DGA)",
            category: "structural"
          });
        } else if (title.includes("Domain Label Length") && !explainItems.some(i => i.name === "Excessive domain label length")) {
          explainItems.push({
            name: "Excessive domain label length",
            score: 5,
            observed: "Contains domain segment exceeding 25 characters",
            inferred: "Possible usage of long subdomains for URL hiding",
            category: "structural"
          });
        } else if (title.includes("Top-Level Domain") && !explainItems.some(i => i.name === "High-risk TLD")) {
          explainItems.push({
            name: "High-risk TLD",
            score: 10,
            observed: "Domain uses a top-level registry with high abuse rates",
            inferred: "Cheap TLDs are frequently abused for automated spam campaigns",
            category: "structural"
          });
        } else if (title.includes("Spoofing Impersonation") && !explainItems.some(i => i.name === "Brand impersonation")) {
          explainItems.push({
            name: "Brand impersonation",
            score: 35,
            observed: "Impersonation signature matching popular brand domain label",
            inferred: "Intentional mimicry to deceive users into credential entry",
            category: "active"
          });
        } else if (title.includes("Typosquatting") && !explainItems.some(i => i.name === "Typosquatted brand spelling")) {
          explainItems.push({
            name: "Typosquatted brand spelling",
            score: 30,
            observed: "Typosquatted spelling detected close to registered brand name",
            inferred: "Targeted brand imposter mask layout",
            category: "active"
          });
        } else if (title.includes("Homograph") && !explainItems.some(i => i.name === "Homograph domain spoofing")) {
          explainItems.push({
            name: "Homograph domain spoofing",
            score: 35,
            observed: "Mixed unicode character sets found in domain label",
            inferred: "Homograph attack designed to spoof authentic brand text",
            category: "active"
          });
        } else if (title.includes("Executable Payload") && !explainItems.some(i => i.name === "Executable payload target")) {
          explainItems.push({
            name: "Executable payload target",
            score: 40,
            observed: "References executable file distribution paths",
            inferred: "High risk of delivery of unauthorized client-side executables",
            category: "active"
          });
        } else if (title.includes("Archive Payload") && !explainItems.some(i => i.name === "Archive payload target")) {
          explainItems.push({
            name: "Archive payload target",
            score: 20,
            observed: "References compressed archive file target",
            inferred: "Potential delivery of obfuscated script macros",
            category: "active"
          });
        } else if (title.includes("Banking") && !explainItems.some(i => i.name === "Banking security risk")) {
          explainItems.push({
            name: "Banking security risk",
            score: 30,
            observed: "Banking keyword detected on insecure/untrusted domain",
            inferred: "Elevated risk of spoofed financial credentials portal",
            category: "active"
          });
        } else if (title.includes("Popular Brand Squatting") && !explainItems.some(i => i.name === "Popular brand squatting")) {
          explainItems.push({
            name: "Popular brand squatting",
            score: 30,
            observed: "Contains popular brand name inside domain label",
            inferred: "Brand mimicry to bypass security reputation filters",
            category: "active"
          });
        } else if (title.includes("Redirect Parameter") && !explainItems.some(i => i.name === "Redirect parameter detected")) {
          explainItems.push({
            name: "Redirect parameter detected",
            score: 5,
            observed: "The URL query contains a redirection parameter",
            inferred: "Masks third-party destination routing and open redirect threats",
            category: "structural"
          });
        } else if (title.includes("Shortened") && !explainItems.some(i => i.name === "Shortened link origin")) {
          explainItems.push({
            name: "Shortened link origin",
            score: 10,
            observed: "Link originates from a URL shortener service",
            inferred: "Masks the final destination, preventing direct structure inspection",
            category: "structural"
          });
        }
      });
    }

    // Official brand matches
    let isOfficialBrand = false;
    for (const brand of MONITORED_BRANDS) {
      if (regDomain === brand.domain) {
        isOfficialBrand = true;
        break;
      }
    }
    if (isOfficialBrand) {
      explainItems.push({
        name: "Official brand domain match",
        score: -40,
        observed: "Verified exact match with official brand domain name",
        inferred: "Authentic company infrastructure",
        category: "structural"
      });
    }

    // Top-tier trusted CDN/Host match
    if (activeDnsResult && activeDnsResult.success && activeDnsResult.geo && activeDnsResult.geo.org) {
      const orgLower = activeDnsResult.geo.org.toLowerCase();
      const trustedISPs = ["google", "microsoft", "amazon", "cloudflare", "fastly", "akamai", "github", "apple"];
      if (trustedISPs.some(isp => orgLower.includes(isp))) {
        explainItems.push({
          name: "Trusted hosting network",
          score: -20,
          observed: `Hosted on certified high-reputation CDN or hosting network (${activeDnsResult.geo.org})`,
          inferred: "Hosted on enterprise-level cloud infrastructure",
          category: "structural"
        });
      }
    }

    // Active tab behaviors
    if (activeTabBehaviors && activeTabBehaviors.length > 0) {
      activeTabBehaviors.forEach(b => {
        if (b.type === "tabjacking") {
          explainItems.push({
            name: "Hidden tab hijacking",
            score: 15,
            observed: "Page modified its location while in an inactive background tab",
            inferred: "Potential credential-harvesting phishing template injection",
            category: "behavioral"
          });
        } else if (b.type === "tabunder") {
          explainItems.push({
            name: "Hidden tab redirection",
            score: 15,
            observed: "Opened background popups while navigating",
            inferred: "Unsolicited background routing",
            category: "behavioral"
          });
        } else if (b.type === "suspicious_download" || b.type === "download_anomaly") {
          explainItems.push({
            name: "Suspicious file download",
            score: 25,
            observed: "Automatic download of executable file extension detected",
            inferred: "Attempted drive-by download or script injection payload",
            category: "behavioral"
          });
        } else if (b.type === "dangerous_download") {
          explainItems.push({
            name: "Dangerous file download",
            score: 40,
            observed: "Automatic download of executable file format detected",
            inferred: "Attempted drive-by download or script injection payload",
            category: "behavioral"
          });
        } else if (b.type === "clipboard_hijack") {
          explainItems.push({
            name: "Clipboard hijacking",
            score: 30,
            observed: "Page attempted to access or rewrite clipboard without permission",
            inferred: "Vulnerability to clipboard tampering or wallet spoofing",
            category: "behavioral"
          });
        } else if (b.type === "clipboard_write") {
          explainItems.push({
            name: "Clipboard write access",
            score: 10,
            observed: "Page attempted to write text to clipboard programmatically",
            inferred: "Potential clipboard manipulation without consent",
            category: "behavioral"
          });
        } else if (b.type === "fake_update" || b.type === "fake_system_alert") {
          explainItems.push({
            name: "Urgent social engineering prompts",
            score: 20,
            observed: "Injected OS style alert boxes in page content",
            inferred: "Social engineering urgency manipulation",
            category: "behavioral"
          });
        } else if (b.type === "meta_refresh" || b.type === "rapid_redirect") {
          explainItems.push({
            name: "Automated redirect trigger",
            score: 15,
            observed: "Unsolicited redirect action executed shortly after loading",
            inferred: "Potential clickjacking or redirection loop",
            category: "behavioral"
          });
        } else if (b.type === "excessive_popups") {
          explainItems.push({
            name: "Excessive popups",
            score: 15,
            observed: "Website launched multiple background tabs or popups",
            inferred: "Unsolicited advertising clickjacking attempts",
            category: "behavioral"
          });
        } else if (b.type === "dynamic_form") {
          explainItems.push({
            name: "Dynamic credentials form",
            score: 20,
            observed: "Password or transaction input field dynamically injected after page load",
            inferred: "Spoofing interface designed to evade headless security crawlers",
            category: "behavioral"
          });
        } else if (b.type === "forced_fullscreen") {
          explainItems.push({
            name: "Forced fullscreen lock",
            score: 20,
            observed: "Page requested fullscreen mode automatically without user input",
            inferred: "Typical scam template behaviour to lock navigation controls",
            category: "behavioral"
          });
        }
      });
    }

    // Reputation data
    if (activeReputationData) {
      let hasReputationIndicator = false;
      if (activeReputationData.vt && activeReputationData.vt.malicious > 0) {
        explainItems.push({
          name: `VirusTotal detections (${activeReputationData.vt.malicious})`,
          score: activeReputationData.vt.malicious * 10,
          observed: `Flagged as malicious by ${activeReputationData.vt.malicious} engine(s) on VirusTotal`,
          inferred: "External threat reports confirm active suspicious activity",
          category: "reputation"
        });
        hasReputationIndicator = true;
      }
      if (activeReputationData.abuse && activeReputationData.abuse.abuseScore > 10) {
        explainItems.push({
          name: `AbuseIPDB report flag (${activeReputationData.abuse.abuseScore}%)`,
          score: Math.floor(activeReputationData.abuse.abuseScore / 2),
          observed: `IP hosting infrastructure has a ${activeReputationData.abuse.abuseScore}% abuse report rate`,
          inferred: "IP has high volumes of abuse traffic reports (spam, DDoS, ports)",
          category: "reputation"
        });
        hasReputationIndicator = true;
      }

      if (!hasReputationIndicator) {
        explainItems.push({
          name: "No reputation corroboration",
          score: 0,
          observed: "No active reputation detections found on VT or AbuseIPDB",
          inferred: "Infrastructure remains neutral (no external threats verified)",
          category: "reputation"
        });
      }
    } else {
      explainItems.push({
        name: "No reputation corroboration",
        score: 0,
        observed: "No active reputation detections found on VT or AbuseIPDB",
        inferred: "Infrastructure remains neutral (no external threats verified)",
        category: "reputation"
      });
    }

    // Calculate sum of explainability list
    let finalScore = 0;
    explainItems.forEach(item => {
      finalScore += item.score;
    });
    finalScore = Math.max(0, Math.min(finalScore, 100));

    // 1. Show Cache Badge if response was pulled from local storage
    if (cacheHitDetected) {
      cacheBadge.style.display = "inline-flex";
    } else {
      cacheBadge.style.display = "none";
    }

    // Apply color styles to pulse indicator
    statusPulse.className = "pulse-indicator";
    if (finalScore >= 55) {
      statusPulse.classList.add("glow-red");
    } else if (finalScore >= 25) {
      statusPulse.classList.add("glow-orange");
    } else {
      statusPulse.classList.add("glow-green");
    }

    // Render gauge circle and value text
    setGaugeValue(finalScore);
    gaugeScore.innerText = finalScore;

    // Render Risk Badge state
    riskBadge.className = "risk-badge";
    if (finalScore >= 55) {
      riskBadge.innerText = "CRITICAL INDICATORS FLAGGED";
      riskBadge.classList.add("risk-high");
    } else if (finalScore >= 25) {
      riskBadge.innerText = "SUSPICIOUS INDICATORS DETECTED";
      riskBadge.classList.add("risk-medium");
    } else {
      riskBadge.innerText = "NO IMMEDIATE STRUCTURAL THREATS";
      riskBadge.classList.add("risk-low");
    }

    const confidence = activeReputationData ? "High" : "Medium";
    confidenceBadge.innerText = `Confidence: ${confidence}`;

    // Update Explainability Table
    explainabilityList.innerHTML = "";
    explainItems.forEach(item => {
      const tr = document.createElement("tr");
      const sign = item.score > 0 ? "+" : "";
      let impactClass = "impact-neutral";
      if (item.score > 0) impactClass = "impact-positive";
      else if (item.score < 0) impactClass = "impact-negative";

      tr.innerHTML = `
        <td>${item.name}</td>
        <td class="impact-badge ${impactClass}" style="text-align: right;">${sign}${item.score}</td>
      `;
      explainabilityList.appendChild(tr);
    });
    finalContextualScore.innerText = finalScore;

    // Compute Layered Scoring Profile
    let structuralSum = 0;
    explainItems.filter(item => item.category === "structural").forEach(item => structuralSum += item.score);
    structuralSum = Math.max(0, Math.min(structuralSum, 100));

    let behavioralSum = 0;
    explainItems.filter(item => item.category === "behavioral").forEach(item => behavioralSum += item.score);
    behavioralSum = Math.max(0, Math.min(behavioralSum, 100));

    let reputationSumStr = "--";
    if (activeReputationData) {
      let reputationSum = 0;
      explainItems.filter(item => item.category === "reputation").forEach(item => reputationSum += item.score);
      reputationSum = Math.max(0, Math.min(reputationSum, 100));
      reputationSumStr = `${reputationSum}`;
    }

    let runtimeObsStr = "Passive scan only";
    if (currentIsEmail) {
      runtimeObsStr = "N/A (Delegated to mail protocol)";
    } else if (activeScanToggle.checked) {
      let hops = redirectCount.innerText;
      if (hops === "0" || hops === "") hops = "0";
      runtimeObsStr = `Active redirect tracing performed (${hops} hops)`;
    }

    scoreLayerStructural.innerText = `${structuralSum}`;
    scoreLayerBehavioral.innerText = `${behavioralSum}`;
    scoreLayerReputation.innerText = reputationSumStr;
    scoreLayerRuntime.innerText = runtimeObsStr;

    // Set overall concern badge
    overallConcernValue.className = "concern-badge";
    if (finalScore >= 75) {
      overallConcernValue.innerText = "Critical";
      overallConcernValue.classList.add("concern-critical");
    } else if (finalScore >= 55) {
      overallConcernValue.innerText = "Elevated";
      overallConcernValue.classList.add("concern-elevated");
    } else if (finalScore >= 25) {
      overallConcernValue.innerText = "Moderate";
      overallConcernValue.classList.add("concern-moderate");
    } else {
      overallConcernValue.innerText = "Low";
      overallConcernValue.classList.add("concern-low");
    }

    // Populate Observed vs Inferred
    observedFactsList.innerHTML = "";
    inferredInterpretationsList.innerHTML = "";
    if (explainItems.length === 0) {
      const factLi = document.createElement("li");
      factLi.innerText = "No anomalous infrastructure observed.";
      observedFactsList.appendChild(factLi);

      const infLi = document.createElement("li");
      infLi.innerText = "No immediate security threat inferred.";
      inferredInterpretationsList.appendChild(infLi);
    } else {
      explainItems.forEach(item => {
        const factLi = document.createElement("li");
        factLi.innerText = item.observed;
        observedFactsList.appendChild(factLi);

        const infLi = document.createElement("li");
        infLi.innerText = item.inferred;
        if (item.score > 0) {
          infLi.className = item.score >= 25 ? "danger-inf" : "";
        } else if (item.score < 0) {
          infLi.className = "clean-inf";
        }
        inferredInterpretationsList.appendChild(infLi);
      });
    }

    // Populate Evidence Classification lists
    structuralAnomaliesList.innerHTML = "";
    behavioralAnomaliesList.innerHTML = "";
    reputationCorroborationList.innerHTML = "";
    activeThreatsList.innerHTML = "";

    explainItems.forEach(item => {
      const li = document.createElement("li");
      if (item.score < 0) {
        li.className = "clean";
      } else if (item.score >= 15) {
        li.className = "danger";
      }

      let displayName = item.name;
      if (displayName === "No direct IPv4 resolution observed during passive lookup") {
        li.className = ""; // neutral warning
      }

      li.innerHTML = `<strong>${displayName}</strong>: ${item.observed}`;

      if (item.category === "structural") {
        structuralAnomaliesList.appendChild(li);
      } else if (item.category === "behavioral") {
        behavioralAnomaliesList.appendChild(li);
      } else if (item.category === "reputation") {
        reputationCorroborationList.appendChild(li);
      } else if (item.category === "active") {
        activeThreatsList.appendChild(li);
      }
    });

    if (structuralAnomaliesList.children.length === 0) {
      const li = document.createElement("li");
      li.className = "clean";
      li.innerHTML = "No structural anomalies detected.";
      structuralAnomaliesList.appendChild(li);
    }
    if (behavioralAnomaliesList.children.length === 0) {
      const li = document.createElement("li");
      li.className = "clean";
      li.innerHTML = "No behavioral anomalies detected.";
      behavioralAnomaliesList.appendChild(li);
    }
    if (reputationCorroborationList.children.length === 0) {
      const li = document.createElement("li");
      li.className = "clean";
      li.innerHTML = "No reputation threats reported.";
      reputationCorroborationList.appendChild(li);
    }
    if (activeThreatsList.children.length === 0) {
      const li = document.createElement("li");
      li.className = "clean";
      li.innerHTML = "No active threat signatures identified.";
      activeThreatsList.appendChild(li);
    }

    // Generate and render Threat Story Cards
    renderThreatStory(findings, finalScore);

    // Update 8-Layer Audit Indicators
    update8LayerAudit(findings, finalScore);
  }

  /**
   * Renders the narrative Threat Story sections based on results
   */
  function renderThreatStory(findings, finalScore) {
    const urlObj = new URL(currentTargetUrl);
    const hostname = currentIsEmail ? extractDomainFromEmailOrMailto(currentTargetUrl) : urlObj.hostname;
    const regDomain = getRegisteredDomain(hostname);

    // --- Card 1: What is this page? (Intent evaluation) ---
    let intentText = "";
    const brandSpoof = checkBrandImpersonation(hostname);
    const squatData = checkTyposquatting(hostname);
    const keywords = getSuspiciousKeywords(currentTargetUrl);

    if (brandSpoof) {
      intentText = `This email domain appears to mimic the official brand <strong>${brandSpoof.name.toUpperCase()}</strong>, but resides on the registered domain <em>${regDomain}</em>. It appears configured to impersonate branding.`;
    } else if (squatData) {
      intentText = `This email domain uses a typosquatted domain designed to resemble <strong>${squatData.brand.toUpperCase()}</strong>. Its intent is highly likely brand impersonation.`;
    } else if (keywords.includes("login") || keywords.includes("signin") || keywords.includes("verify") || keywords.includes("account")) {
      intentText = "This email domain displays characteristics of a user portal or account verification portal, attempting to gather credentials.";
    } else if (keywords.includes("banking") || keywords.includes("paypal") || keywords.includes("support")) {
      intentText = "This email domain appears to target financial accounts, customer billing, or customer service portals.";
    } else {
      intentText = currentIsEmail 
        ? `Email correspondence target pointing to the domain <em>${regDomain}</em>.`
        : `An active webpage running on domain <em>${regDomain}</em>.`;
    }

    // Append active browser behavior anomalies if any
    if (activeTabBehaviors.length > 0) {
      intentText += " System has intercepted active interactive modifications on this page.";
    }
    storyIntent.innerHTML = intentText;

    // --- Threat Outcomes & Explanation Box Styling ---
    let outcomeText = "";
    const explanationBox = document.getElementById("primaryExplanationBox");
    if (explanationBox) {
      explanationBox.className = "explanation-box";
      if (finalScore >= 55) {
        explanationBox.classList.add("high");
        outcomeText = "<strong>Warning:</strong> Multiple high-risk structural indicators detected. Behavioral execution analysis unavailable. <strong>Recommendation:</strong> Avoid entering credentials or downloading files unless the source is trusted.";
      } else if (finalScore >= 25) {
        explanationBox.classList.add("medium");
        outcomeText = "<strong>Caution:</strong> This page exhibits patterns commonly associated with suspicious infrastructure. <strong>Recommendation:</strong> Exercise caution before interacting with this page.";
      } else {
        explanationBox.classList.add("low");
        outcomeText = "<strong>Standard:</strong> The page aligns with standard trusted infrastructure, secure protocols, and mature domain age. Safe to visit under normal caution.";
      }
    }
    storyScenario.innerHTML = outcomeText;
  }
  /**
   * Updates the 8 Threat Layer Audit dashboard list UI
   */
  function update8LayerAudit(findings, finalScore) {
    const urlObj = new URL(currentTargetUrl);
    const hostname = currentIsEmail ? extractDomainFromEmailOrMailto(currentTargetUrl) : urlObj.hostname;
    
    // Helper to set row status
    const setLayer = (id, status, descText) => {
      const row = document.getElementById(`layer-${id}`);
      const icon = row.querySelector(".layer-status-icon");
      const desc = document.getElementById(`layerDesc-${id}`);
      
      icon.className = `layer-status-icon status-${status}`;
      desc.innerText = descText;
    };

    // Layer 1: URL Structure
    const hasHttp = urlObj.protocol === "http:";
    const regDom = getRegisteredDomain(hostname);
    const label = regDom.split('.')[0];
    const highEntropy = calculateEntropy(label) > 3.8 && label.length > 5;
    const hasParams = /(\?|&)(email|usr|user|username|signin|login|pwd|pass|password)=/i.test(urlObj.search);
    if (hasHttp) {
      setLayer("url", "danger", "Insecure connection (HTTP protocol detected)");
    } else if (highEntropy || hasParams) {
      setLayer("url", "warning", "Anomalous attributes: high entropy domain or credential parameters");
    } else {
      setLayer("url", "clean", "Normal structure (Secure HTTPS & clean URL elements)");
    }

    // Layer 2: Domain Intelligence
    if (activeAgeResult && activeAgeResult.success && activeAgeResult.data && activeAgeResult.data.ageDays !== null) {
      const age = activeAgeResult.data.ageDays;
      if (age < 30) {
        setLayer("domain", "danger", `Newly registered domain (${age} days ago)`);
      } else if (age < 180) {
        setLayer("domain", "warning", `Recent domain registration (${age} days ago)`);
      } else {
        setLayer("domain", "clean", `Mature domain registered over ${Math.floor(age/365)} years ago`);
      }
    } else if (activeAgeResult && activeAgeResult.data && activeAgeResult.data.notFound) {
      setLayer("domain", "warning", "Timeline unverified (No RDAP record found)");
    } else if (activeAgeResult && !activeAgeResult.success) {
      setLayer("domain", "warning", "Timeline unverified (Registry did not respond)");
    } else {
      setLayer("domain", "skipped", "Timeline scan scheduled (Pending RDAP query)");
    }

    // Layer 3: DOM Inspection
    const domAlerts = activeTabBehaviors.filter(b => b.type === "fake_system_alert");
    if (domAlerts.length > 0) {
      setLayer("dom", "danger", "Fake warning alert template detected in document content");
    } else if (activeTabBehaviors.length > 0) {
      setLayer("dom", "warning", "Suspicious iframe or dynamic DOM script observed");
    } else {
      setLayer("dom", "clean", "Standard DOM structure (No template abnormalities found)");
    }

    // Layer 4: JS Behavior
    const jsBehaviors = activeTabBehaviors.filter(b => b.type === "clipboard_hijack" || b.type === "download_anomaly");
    if (jsBehaviors.length > 0) {
      setLayer("js", "danger", "Intercepted dangerous input capture or file triggers");
    } else {
      setLayer("js", "clean", "No malicious interactive scripting behavior detected");
    }

    // Layer 5: Psychology Analysis
    const keywords = getSuspiciousKeywords(currentTargetUrl);
    if (keywords.length > 0) {
      setLayer("psychology", "warning", `Urgency/brand keyword match: ${keywords.slice(0, 3).join(", ")}`);
    } else {
      setLayer("psychology", "clean", "No urgency keywords or emotional styling targets found");
    }

    // Layer 6: Browser Behavior
    const tabjacks = activeTabBehaviors.filter(b => b.type === "tabjacking");
    if (tabjacks.length > 0) {
      setLayer("browser", "danger", "Tab hijack event (silent reload to new origin) intercepted");
    } else {
      setLayer("browser", "clean", "No active navigation context manipulation detected");
    }

    // Layer 7: Visual Analysis
    const brandSpoof = checkBrandImpersonation(hostname);
    const squatData = checkTyposquatting(hostname);
    const homoglyphs = detectScriptMixture(hostname);
    if (brandSpoof || squatData || homoglyphs) {
      setLayer("visual", "danger", brandSpoof ? `Brand impersonation signature: ${brandSpoof.name}` : (squatData ? "Typosquatted brand spelling detected" : "Homoglyph spoofing characters mixed"));
    } else {
      setLayer("visual", "clean", "No visual brand mimicry or homoglyph character mixing found");
    }

    // Layer 8: Correlation Engine
    if (finalScore >= 55) {
      setLayer("correlation", "danger", `Critical risk match (correlated score: ${finalScore}/100)`);
    } else if (finalScore >= 25) {
      setLayer("correlation", "warning", `Elevated suspicion (correlated score: ${finalScore}/100)`);
    } else {
      setLayer("correlation", "clean", `Clean correlation (correlated score: ${finalScore}/100)`);
    }
  }

  /**
   * Helper to set CSS dash offset on SVG circle gauge
   */
  function setGaugeValue(percent) {
    const circle = document.getElementById("riskGauge");
    const radius = circle.r.baseVal.value;
    const circumference = radius * 2 * Math.PI;
    
    // Set circle stroke offset
    const offset = circumference - (percent / 100) * circumference;
    circle.style.strokeDashoffset = offset;

    // Update gauge stroke color according to severity
    if (percent >= 55) {
      circle.style.stroke = "#ef4444"; // red
    } else if (percent >= 25) {
      circle.style.stroke = "#d97706"; // amber
    } else {
      circle.style.stroke = "#10b981"; // green
    }
  }

  /**
   * Renders the domain parts with color highlights
   */
  function renderUrlBreakdown(urlObj) {
    if (currentIsEmail) {
      let emailAddress = urlObj.pathname;
      if (!emailAddress && currentTargetUrl.toLowerCase().startsWith("mailto:")) {
        emailAddress = currentTargetUrl.substring(7).split('?')[0];
      }
      const searchParams = urlObj.search || "";
      
      const parts = emailAddress.split('@');
      const localPart = parts[0] || "";
      const emailDomain = parts[1] || "";
      
      const regDomain = getRegisteredDomain(emailDomain);
      const domainParts = regDomain ? regDomain.split('.') : [];
      const tld = domainParts.length > 0 ? domainParts.pop() : "";
      const mainLabel = domainParts.join('.');
      
      let subdomains = "";
      if (regDomain && emailDomain.endsWith("." + regDomain)) {
        subdomains = emailDomain.slice(0, -(regDomain.length + 1));
      }
      
      const brandSpoof = checkBrandImpersonation(emailDomain);
      const squatData = checkTyposquatting(emailDomain);
      
      let html = `<span class="breakdown-protocol email">mailto:</span>`;
      if (localPart) {
        html += `<span class="breakdown-path">${localPart}@</span>`;
      }
      if (subdomains) {
        html += `<span class="breakdown-subdomain">${subdomains}.</span>`;
      }
      
      let mainLabelHtml = "";
      if (mainLabel) {
        for (let i = 0; i < mainLabel.length; i++) {
          const char = mainLabel[i];
          const code = char.charCodeAt(0);
          const isCyrillic = /[\u0400-\u04FF]/.test(char);
          const isGreek = /[\u0370-\u03FF]/.test(char);
          
          if (code > 127 || isCyrillic || isGreek) {
            const latinEquivalent = HOMOGLYPH_MAP[char] || "unknown";
            mainLabelHtml += `<span class="url-char-warning" title="Homoglyph character mimic detected: '${char}' (Unicode U+${code.toString(16).toUpperCase()}) targets standard character '${latinEquivalent}'">${char}</span>`;
          } else {
            mainLabelHtml += char;
          }
        }
      }
      
      let labelClass = "breakdown-domain";
      if (brandSpoof) {
        labelClass += " flagged";
      } else if (squatData) {
        labelClass += " flagged-typo";
      }
      
      html += `<span class="${labelClass}">${mainLabelHtml}</span>`;
      if (tld) {
        const isBadTld = checkSuspiciousTLD(emailDomain);
        html += `<span class="breakdown-tld ${isBadTld ? 'suspicious' : ''}">.${tld}</span>`;
      }
      
      if (searchParams) {
        html += `<span class="breakdown-path">${searchParams}</span>`;
      }
      
      urlBreakdown.innerHTML = html;
      return;
    }

    const hostname = urlObj.hostname;
    const protocol = urlObj.protocol;
    const path = urlObj.pathname + urlObj.search;

    const isSecure = protocol === "https:";
    const regDomain = getRegisteredDomain(hostname);
    
    // Split domain label and TLD
    const domainParts = regDomain.split('.');
    const tld = domainParts.pop();
    const mainLabel = domainParts.join('.');
    
    // Extract subdomains
    let subdomains = "";
    if (hostname.endsWith("." + regDomain)) {
      subdomains = hostname.slice(0, -(regDomain.length + 1));
    }

    const brandSpoof = checkBrandImpersonation(hostname);
    const squatData = checkTyposquatting(hostname);

    let html = `<span class="breakdown-protocol ${isSecure ? 'secure' : 'insecure'}">${protocol}//</span>`;
    
    if (subdomains) {
      html += `<span class="breakdown-subdomain">${subdomains}.</span>`;
    }

    // Process characters inside mainLabel to highlight homoglyphs
    let mainLabelHtml = "";
    for (let i = 0; i < mainLabel.length; i++) {
      const char = mainLabel[i];
      const code = char.charCodeAt(0);
      const isCyrillic = /[\u0400-\u04FF]/.test(char);
      const isGreek = /[\u0370-\u03FF]/.test(char);
      
      if (code > 127 || isCyrillic || isGreek) {
        const latinEquivalent = HOMOGLYPH_MAP[char] || "unknown";
        mainLabelHtml += `<span class="url-char-warning" title="Homoglyph character mimic detected: '${char}' (Unicode U+${code.toString(16).toUpperCase()}) targets standard character '${latinEquivalent}'">${char}</span>`;
      } else {
        mainLabelHtml += char;
      }
    }

    let labelClass = "breakdown-domain";
    if (brandSpoof) {
      labelClass += " flagged";
    } else if (squatData) {
      labelClass += " flagged-typo";
    }

    html += `<span class="${labelClass}">${mainLabelHtml}</span>`;
    
    const isBadTld = checkSuspiciousTLD(hostname);
    html += `<span class="breakdown-tld ${isBadTld ? 'suspicious' : ''}">.${tld}</span>`;
    
    if (path && path !== "/") {
      html += `<span class="breakdown-path">${path}</span>`;
    }

    urlBreakdown.innerHTML = html;
  }

  /**
   * Renders the vertical flowchart for redirects
   */
  function renderRedirectChain(startUrl, redirectResult) {
    chainList.innerHTML = "";
    
    if (currentIsEmail) {
      redirectCount.innerText = "0";
      const emailDomain = extractDomainFromEmailOrMailto(startUrl);
      const node = document.createElement("div");
      node.className = "chain-node";
      node.innerHTML = `
        <div class="node-dot low"></div>
        <div class="node-info">
          <div class="node-domain">${emailDomain}</div>
          <div class="node-details">Direct Email Destination • Mail protocol</div>
        </div>
      `;
      chainList.appendChild(node);
      return;
    }

    if (!redirectResult || !redirectResult.success || redirectResult.hops === 0) {
      // Single hop layout
      redirectCount.innerText = "0";
      const host = new URL(startUrl).hostname;
      
      const node = document.createElement("div");
      node.className = "chain-node";
      
      const nodeRisk = getQuickRiskClass(host);
      node.innerHTML = `
        <div class="node-dot ${nodeRisk}"></div>
        <div class="node-info">
          <div class="node-domain">${host}</div>
          <div class="node-details">Direct Destination • Secure connection</div>
        </div>
      `;
      chainList.appendChild(node);
      return;
    }

    // Process redirect hops
    const chain = redirectResult.chain;
    redirectCount.innerText = redirectResult.hops;
    evidenceDetails.open = true; // Auto expand if redirects are found

    chain.forEach((url, index) => {
      const urlObj = new URL(url);
      const isFinal = index === chain.length - 1;
      const isFirst = index === 0;
      
      const node = document.createElement("div");
      node.className = "chain-node";

      const nodeRisk = getQuickRiskClass(urlObj.hostname);
      
      if (nodeRisk === "high") {
        node.classList.add("danger-hop");
      } else if (nodeRisk === "medium") {
        node.classList.add("suspicious-hop");
      }

      let detailText = "";
      if (isFirst) detailText = "Original query link";
      else if (isFinal) detailText = `Final Destination (Hop ${index})`;
      else detailText = `Redirect Hop ${index}`;

      if (urlObj.protocol === "http:") {
        detailText += " • Insecure (HTTP)";
      }

      node.innerHTML = `
        <div class="node-dot ${nodeRisk}"></div>
        <div class="node-info">
          <div class="node-domain">${urlObj.hostname}</div>
          <div class="node-details">${detailText}</div>
        </div>
      `;
      chainList.appendChild(node);
    });
  }

  // Returns quick low/medium/high indicator for redirect nodes
  function getQuickRiskClass(hostname) {
    if (checkBrandImpersonation(hostname) || checkTyposquatting(hostname) || detectScriptMixture(hostname)) {
      return "high";
    }
    if (checkSuspiciousTLD(hostname) || calculateEntropy(hostname.split('.')[0]) > 3.8) {
      return "medium";
    }
    return "low";
  }

  /**
   * Constructs the vertical Trust Timeline graphic
   */
  function renderTrustTimeline(protocol, dnsResult, ageResult) {
    timelineFlow.innerHTML = "";

    // Step 1: Domain registration details
    const stepAge = document.createElement("div");
    stepAge.className = "timeline-step";

    if (ageResult && ageResult.success && ageResult.data && ageResult.data.ageDays !== null) {
      const ageDays = ageResult.data.ageDays;
      if (ageDays < 30) {
        stepAge.classList.add("danger");
        stepAge.innerHTML = `
          <div class="timeline-label">Registered</div>
          <div class="timeline-value">Fresh Domain (${ageDays} days ago) <span style="color:var(--severity-red); font-weight:bold;">⚠️ HIGH RISK</span></div>
        `;
      } else if (ageDays < 180) {
        stepAge.classList.add("suspicious");
        stepAge.innerHTML = `
          <div class="timeline-label">Registered</div>
          <div class="timeline-value">Recent Domain (${ageDays} days ago)</div>
        `;
      } else {
        stepAge.classList.add("completed");
        stepAge.innerHTML = `
          <div class="timeline-label">Registered</div>
          <div class="timeline-value">Established (${Math.floor(ageDays/365)} years, ${ageDays%365} days ago)</div>
        `;
      }
    } else {
      stepAge.classList.add("suspicious");
      const noRdapReason = (ageResult && ageResult.data && ageResult.data.notFound)
        ? "No RDAP record found for this domain"
        : "No RDAP record found";
      stepAge.innerHTML = `
        <div class="timeline-label">Registered</div>
        <div class="timeline-value" style="color:var(--text-muted);">Unknown Age (${noRdapReason})</div>
      `;
    }
    timelineFlow.appendChild(stepAge);

    // Step 2: SSL/HTTPS status
    const stepSsl = document.createElement("div");
    stepSsl.className = "timeline-step";
    if (currentIsEmail) {
      stepSsl.classList.add("completed");
      stepSsl.innerHTML = `
        <div class="timeline-label">Mail Client</div>
        <div class="timeline-value">N/A (Delegated to default mail protocol)</div>
      `;
    } else if (protocol === "https:") {
      let certInfo = "";
      if (ageResult && ageResult.success && ageResult.data && ageResult.data.cert) {
        const cert = ageResult.data.cert;
        certInfo = ` (Active CT logs indicate cert issued ${cert.issuedDaysAgo} days ago)`;
        if (cert.issuedDaysAgo < 14) {
          stepSsl.classList.add("suspicious");
          stepSsl.innerHTML = `
            <div class="timeline-label">SSL Cert</div>
            <div class="timeline-value">HTTPS Active — <span style="color:var(--severity-orange); font-weight:bold;">Fresh Certificate</span>${certInfo}</div>
          `;
        } else {
          stepSsl.classList.add("completed");
          stepSsl.innerHTML = `
            <div class="timeline-label">SSL Cert</div>
            <div class="timeline-value">Valid active HTTPS configuration${certInfo}</div>
          `;
        }
      } else {
        stepSsl.classList.add("completed");
        stepSsl.innerHTML = `
          <div class="timeline-label">SSL Cert</div>
          <div class="timeline-value">Valid active HTTPS configuration</div>
        `;
      }
    } else {
      stepSsl.classList.add("danger");
      stepSsl.innerHTML = `
        <div class="timeline-label">SSL Cert</div>
        <div class="timeline-value" style="color:var(--severity-red); font-weight:bold;">None (Insecure HTTP connection)</div>
      `;
    }
    timelineFlow.appendChild(stepSsl);

    // Step 3: DNS IP resolution status
    const stepDns = document.createElement("div");
    stepDns.className = "timeline-step";
    if (dnsResult && dnsResult.success && dnsResult.ip !== "Unresolved") {
      stepDns.classList.add("completed");
      stepDns.innerHTML = `
        <div class="timeline-label">DNS Record</div>
        <div class="timeline-value">Resolved A-Record to ${dnsResult.ip}</div>
      `;
    } else {
      stepDns.classList.add("danger");
      stepDns.innerHTML = `
        <div class="timeline-label">DNS Record</div>
        <div class="timeline-value" style="color:var(--severity-red);">DNS resolution failed (No A-Record found)</div>
      `;
    }
    timelineFlow.appendChild(stepDns);
  }

  /**
   * Binds reputation data to grid boxes
   */
  function renderReputationDetails(data) {
    liveRepBox.style.display = "block";

    // 1. Render VirusTotal details
    if (data.vt) {
      if (data.vt.status === "submitted_for_scan") {
        vtScore.innerText = "Scanning...";
        vtScore.className = "rep-badge-val warning";
      } else if (data.vt.status === "not_found") {
        vtScore.innerText = "No report";
        vtScore.className = "rep-badge-val warning";
      } else if (data.vt.status === "error") {
        vtScore.innerText = "API error";
        vtScore.className = "rep-badge-val danger";
      } else if (data.vt.status === "unsupported") {
        vtScore.innerText = "N/A";
        vtScore.className = "rep-badge-val";
      } else {
        const mal = data.vt.malicious || 0;
        const total = data.vt.total || 0;
        vtScore.innerText = `${mal}/${total}`;
        
        if (mal > 0) {
          vtScore.className = "rep-badge-val danger";
        } else {
          vtScore.className = "rep-badge-val safe";
        }
      }
    } else {
      vtScore.innerText = "Skipped";
      vtScore.className = "rep-badge-val";
    }
  }

  // --- Async Promise Messaging wrappers ---

  function traceRedirectsAsync(url) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ action: "traceRedirects", url: url }, (response) => {
        resolve(response);
      });
    });
  }

  function fetchDnsInfoAsync(domain) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ action: "getLiveDnsInfo", domain: domain }, (response) => {
        resolve(response);
      });
    });
  }

  function fetchDomainAgeAsync(domain) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ action: "getDomainAge", domain: domain }, (response) => {
        resolve(response);
      });
    });
  }

  function showError(msg) {
    errorMsg.innerText = msg;
    errorCard.style.display = "flex";
  }
});