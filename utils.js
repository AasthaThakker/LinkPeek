/**
 * Calculates the Shannon Entropy of a string.
 * High entropy indicates a random-looking string (potential DGA or generated domain).
 */
function calculateEntropy(str) {
  if (!str) return 0;
  const map = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    map[char] = (map[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;
  for (const char in map) {
    const p = map[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Calculates the Levenshtein distance between two strings.
 */
function levenshtein(a, b) {
  const matrix = [];
  
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }
  
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }
  
  return matrix[b.length][a.length];
}

/**
 * A standard, self-contained Punycode (RFC 3492) Bootstring decoder.
 * Converts 'xn--...' domain segments to standard Unicode.
 */
function decodePunycode(domain) {
  if (!domain) return "";
  const parts = domain.toLowerCase().split('.');
  
  const decodedParts = parts.map(part => {
    if (!part.startsWith('xn--')) return part;
    
    // Bootstring parameters
    const BASE = 36;
    const TMIN = 1;
    const TMAX = 26;
    const SKEW = 38;
    const DAMP = 700;
    const INITIAL_BIAS = 72;
    const INITIAL_N = 128;
    const DELIMITER = '-';

    let n = INITIAL_N;
    let i = 0;
    let bias = INITIAL_BIAS;
    let output = [];

    // Strip xn-- prefix
    const input = part.slice(4);
    
    // Find basic code points delimiter
    const basicLength = input.lastIndexOf(DELIMITER);
    let inputIndex = 0;
    
    if (basicLength >= 0) {
      for (let j = 0; j < basicLength; ++j) {
        const code = input.charCodeAt(j);
        if (code >= 0x80) return part; // Fail: basic characters must be ASCII
        output.push(code);
      }
      inputIndex = basicLength + 1;
    }

    const inputLength = input.length;
    while (inputIndex < inputLength) {
      const oldi = i;
      let w = 1;
      
      for (let k = BASE; ; k += BASE) {
        if (inputIndex >= inputLength) return part; // Fail: unexpected end of stream
        const code = input.charCodeAt(inputIndex++);
        
        let digit;
        if (code >= 48 && code <= 57) digit = code - 22; // '0'-'9' -> 26-35
        else if (code >= 97 && code <= 122) digit = code - 97; // 'a'-'z' -> 0-25
        else return part; // Fail: invalid character
        
        i += digit * w;
        
        const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
        if (digit < t) break;
        w *= (BASE - t);
      }

      const outLen = output.length + 1;
      // Adapt bias
      let delta = i - oldi;
      delta = oldi === 0 ? Math.floor(delta / DAMP) : delta >> 1;
      delta += Math.floor(delta / outLen);
      let k = 0;
      while (delta > Math.floor(((BASE - TMIN) * TMAX) / 2)) {
        delta = Math.floor(delta / (BASE - TMIN));
        k += BASE;
      }
      bias = k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));

      n += Math.floor(i / outLen);
      i %= outLen;
      output.splice(i++, 0, n);
    }
    
    return String.fromCharCode.apply(null, output);
  });
  
  return decodedParts.join('.');
}

/**
 * Extracts the registered domain (e.g. "example.com" or "example.co.uk") from a hostname.
 * Prevents false positives by isolating effective root domains before brand checks.
 */
function getRegisteredDomain(hostname) {
  if (!hostname) return "";
  const parts = hostname.toLowerCase().split('.');
  if (parts.length <= 2) return hostname;
  
  // Common double-part suffixes (e.g. co.uk, com.au, net.in)
  const ccTlds = [
    "co", "com", "net", "org", "gov", "edu", "ac", "mil", "nom", "in", 
    "us", "uk", "br", "ru", "cn", "jp", "fr", "de", "it", "es", "ca", "au",
    "org", "net", "gov"
  ];
  const len = parts.length;
  const secondToLast = parts[len - 2];
  const last = parts[len - 1];
  
  if (ccTlds.includes(secondToLast) && last.length === 2) {
    return parts.slice(-3).join('.');
  }
  
  return parts.slice(-2).join('.');
}

// Global list of brands monitored for impersonation and typosquatting
const MONITORED_BRANDS = [
  { name: "google", domain: "google.com" },
  { name: "paypal", domain: "paypal.com" },
  { name: "facebook", domain: "facebook.com" },
  { name: "amazon", domain: "amazon.com" },
  { name: "microsoft", domain: "microsoft.com" },
  { name: "netflix", domain: "netflix.com" },
  { name: "apple", domain: "apple.com" },
  { name: "github", domain: "github.com" },
  { name: "chase", domain: "chase.com" },
  { name: "bankofamerica", domain: "bankofamerica.com" },
  { name: "binance", domain: "binance.com" },
  { name: "instagram", domain: "instagram.com" },
  { name: "twitter", domain: "twitter.com" },
  { name: "youtube", domain: "youtube.com" },
  { name: "linkedin", domain: "linkedin.com" },
  { name: "yahoo", domain: "yahoo.com" },
  { name: "wellsfargo", domain: "wellsfargo.com" },
  { name: "citibank", domain: "citi.com" }
];

// Homoglyph mappings: translate lookalike symbols, Cyrillic, and Greek characters into Latin counterparts
const HOMOGLYPH_MAP = {
  // Cyrillic small letters
  '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c', 
  '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0455': 's', '\u0458': 'j', 
  '\u043c': 'm', '\u043d': 'h', '\u043a': 'k', '\u0432': 'b', '\u043f': 'n', 
  '\u0442': 't', '\u0437': '3', '\u0434': 'g', '\u043b': 'l', '\u0457': 'i',
  // Cyrillic capital letters
  '\u0410': 'a', '\u0415': 'e', '\u041e': 'o', '\u0420': 'p', '\u0421': 'c', 
  '\u0423': 'y', '\u0425': 'x', '\u0406': 'i', '\u0408': 'j', '\u041c': 'm', 
  '\u041d': 'h', '\u041a': 'k', '\u0412': 'b', '\u041f': 'n', '\u0422': 't',
  // Greek small letters
  '\u03b1': 'a', '\u03b2': 'b', '\u03b5': 'e', '\u03b9': 'i', '\u03ba': 'k', 
  '\u03bf': 'o', '\u03c1': 'p', '\u03c4': 't', '\u03c5': 'y', '\u03c7': 'x', 
  '\u03b7': 'n', '\u03bc': 'm', '\u03c9': 'w',
  // Lookalikes, numbers and combined symbols
  '1': 'l', '0': 'o', 'I': 'l', 'l': 'i', 'v': 'u', 'w': 'vv', 
  '\u2010': '-', '\u2011': '-', '\u2013': '-'
};

/**
 * Translates homoglyphs, script mixtures, and standard lookalikes (rn -> m)
 * to standard clean Latin equivalent.
 */
function cleanHomoglyphs(str) {
  if (!str) return "";
  let cleaned = str.toLowerCase();
  
  // Replace combinations that mimic characters
  cleaned = cleaned.replace(/rn/g, 'm');
  cleaned = cleaned.replace(/vv/g, 'w');
  cleaned = cleaned.replace(/cl/g, 'd');
  cleaned = cleaned.replace(/10/g, 'lo');
  
  let result = "";
  for (let i = 0; i < cleaned.length; i++) {
    const char = cleaned[i];
    result += HOMOGLYPH_MAP[char] || char;
  }
  
  return result;
}

/**
 * Checks if a string contains non-standard mixed script styles (like Cyrillic/Greek mixed with Latin).
 */
function detectScriptMixture(str) {
  if (!str) return false;
  const hasLatin = /[a-z]/i.test(str);
  const hasCyrillic = /[\u0400-\u04FF]/.test(str);
  const hasGreek = /[\u0370-\u03FF]/.test(str);
  
  // If it mixes Latin with Cyrillic or Greek, it's highly suspicious
  return (hasLatin && hasCyrillic) || (hasLatin && hasGreek) || (hasCyrillic && hasGreek);
}

/**
 * Checks if the hostname is attempting to impersonate a brand
 * (e.g. "paypal-security-login.xyz" or "login-chasebank.net").
 * Automatically strips homoglyphs first.
 */
function checkBrandImpersonation(hostname) {
  const decodedHost = decodePunycode(hostname);
  const cleanHost = cleanHomoglyphs(decodedHost);
  const registeredDomain = getRegisteredDomain(decodedHost);
  const cleanRegistered = cleanHomoglyphs(registeredDomain);
  
  if (!registeredDomain) return null;

  for (const brand of MONITORED_BRANDS) {
    const brandLabel = brand.domain.split('.')[0];
    const registeredLabel = registeredDomain.split('.')[0];
    const cleanRegisteredLabel = cleanHomoglyphs(registeredLabel);

    // If the registered domain's main label is exactly the brand label, it is the brand's legitimate local domain (e.g. google.co.uk, amazon.de)
    if (cleanRegisteredLabel === brandLabel) {
      continue;
    }

    // If cleaned hostname contains the brand name, but the cleaned registered domain is not the brand's official domain
    if (cleanHost.includes(brand.name) && cleanRegistered !== brand.domain) {
      // Check if it's a subdomain of the official brand
      const officialSuffix = "." + brand.domain;
      if (cleanHost === brand.domain || cleanHost.endsWith(officialSuffix)) {
        continue; // Legitimate subdomain
      }
      return brand; // Impersonation!
    }
  }
  return null;
}

/**
 * Checks if the domain name is a typosquatting version of a popular brand.
 * Analyzes ONLY the registered root domain label, eliminating false positives on subdomains.
 */
function checkTyposquatting(hostname) {
  const decodedHost = decodePunycode(hostname);
  const registeredDomain = getRegisteredDomain(decodedHost);
  if (!registeredDomain) return null;

  const label = registeredDomain.split('.')[0];
  const cleanLabel = cleanHomoglyphs(label);

  for (const brand of MONITORED_BRANDS) {
    const brandLabel = brand.domain.split('.')[0];
    
    // If the registered domain's label matches the brand label exactly, it is NOT typosquatting (could be country-code TLD)
    if (label === brandLabel) continue;

    // Homoglyph match: clean label is the brand but original differs
    if (cleanLabel === brandLabel && label !== brandLabel) {
      return { brand: brand.name, official: brand.domain, distance: 0, reason: "homoglyph" };
    }

    // Levenshtein edit distance check
    const alphaLabel = cleanLabel.replace(/[^a-z0-9]/g, "");
    const alphaBrandLabel = brandLabel.replace(/[^a-z0-9]/g, "");

    const dist = levenshtein(alphaLabel, alphaBrandLabel);
    if (dist > 0 && dist <= 2 && alphaLabel.length >= 3) {
      return { brand: brand.name, official: brand.domain, distance: dist, reason: "typosquatting" };
    }
  }
  return null;
}

/**
 * Scans URL path/domain for suspicious keywords.
 */
function getSuspiciousKeywords(url) {
  const keywords = [
    "login", "verify", "secure", "update", "wallet", "password", 
    "crypto", "signin", "billing", "account", "support", "claim", 
    "refund", "verification", "auth", "recover", "portal"
  ];
  const urlLower = url.toLowerCase();
  return keywords.filter(keyword => urlLower.includes(keyword));
}

// Top-Level Domains that are frequently abused or cheap to register
const HIGH_RISK_TLDS = [
  "xyz", "top", "click", "club", "info", "work", "zip", "gq", "cf", 
  "tk", "ml", "cc", "online", "site", "space", "website", "tech", 
  "download", "bid", "stream", "men", "date", "win", "icu", "cam", 
  "fit", "gdn", "ru", "su"
];

/**
 * Checks if the TLD of the URL is considered high-risk.
 */
function checkSuspiciousTLD(hostname) {
  if (!hostname) return null;
  const parts = hostname.toLowerCase().split('.');
  const tld = parts[parts.length - 1];
  if (HIGH_RISK_TLDS.includes(tld)) {
    return tld;
  }
  return null;
}

/**
 * Special bank security rule
 */
function checkBankHeuristic(hostname, protocol) {
  const domainLower = hostname.toLowerCase();
  
  if (domainLower.includes("bank")) {
    const registeredDomain = getRegisteredDomain(hostname);
    const parts = registeredDomain.split('.');
    const tld = parts[parts.length - 1];
    
    if (HIGH_RISK_TLDS.includes(tld)) {
      return { reason: `Contains 'bank' but uses an untrusted TLD (.${tld})`, severity: "high" };
    }
    
    if (protocol === "http:") {
      return { reason: "Banking keyword used on insecure HTTP connection", severity: "high" };
    }
  }
  return null;
}

/**
 * Checks if domain is a raw IP address
 */
function checkIpAddressDomain(hostname) {
  return /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(hostname);
}

/**
 * Checks for multiple hyphens domain pattern
 */
function checkSuspiciousDomainPattern(hostname) {
  return /[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\./i.test(hostname);
}

/**
 * Checks if the domain label has a length >= 25 characters
 */
function checkVeryLongDomain(hostname) {
  const parts = hostname.split('.');
  return parts.some(part => part.length >= 25);
}

/**
 * Checks for long numeric digits sequences (> 10 digits)
 */
function checkLongNumericSequence(url) {
  return /[0-9]{10,}/.test(url);
}

/**
 * Checks for common social engineering/scam words
 */
function checkSuspiciousPromotionalContent(url) {
  return /free|prize|winner|lottery|click.*here|urgent|act.*now/i.test(url);
}

/**
 * Checks for redirect/navigational keys in query params
 */
function checkSuspiciousParams(url) {
  try {
    const u = new URL(url);
    const params = new URLSearchParams(u.search);
    const suspiciousKeys = ['redirect', 'url', 'link', 'goto', 'target', 'next', 'continue'];
    for (const key of suspiciousKeys) {
      if (params.has(key)) {
        return key;
      }
    }
  } catch (e) {}
  return null;
}

/**
 * Checks if the URL specifies a port other than 80, 443, 8080, or 8443
 */
function checkSuspiciousPort(url) {
  try {
    const u = new URL(url);
    if (u.port) {
      const portInt = parseInt(u.port, 10);
      if (![80, 443, 8080, 8443].includes(portInt)) {
        return portInt;
      }
    }
  } catch (e) {}
  return null;
}

/**
 * Checks if popular brand names are present in the domain but are not the actual official domain
 */
function checkPopularDomainSquatting(hostname) {
  const popularBrands = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'netflix'];
  const regDomain = getRegisteredDomain(hostname);
  const parts = regDomain.split('.');
  const mainLabel = parts[0];
  
  for (const brand of popularBrands) {
    if (hostname.includes(brand) && mainLabel !== brand) {
      return brand;
    }
  }
  return null;
}

/**
 * Unified local heuristics analyzer for URLs and page context.
 * Performs deep, instant synchronous inspections and outputs a weighted confidence score.
 */
function evaluateLocalHeuristics(urlStr, linkText, hasPasswordFields, hasCardInputs) {
  try {
    const isEmail = isEmailOrMailto(urlStr);
    let checkUrl = urlStr;
    if (isEmail) {
      const emailDomain = extractDomainFromEmailOrMailto(urlStr);
      checkUrl = "https://" + emailDomain;
    }
    const u = new URL(checkUrl);
    const rawHostname = u.hostname;
    const protocol = isEmail ? "mailto:" : u.protocol;
    const pathname = u.pathname.toLowerCase();
    const search = u.search.toLowerCase();
    const linkTextClean = (linkText || "").trim().toLowerCase();
    
    const hostname = decodePunycode(rawHostname);
    const regDom = getRegisteredDomain(hostname);
    const label = regDom.split('.')[0];
    const entropy = calculateEntropy(label);
    
    // Determine file extension
    const fileExtMatch = pathname.match(/\.([a-z0-9]+)($|\?)/);
    const fileExt = fileExtMatch ? fileExtMatch[1] : "";
    
    const execExts = ["exe", "msi", "scr", "bat", "cmd", "vbs", "ps1", "lnk"];
    const archiveExts = ["zip", "rar", "tar", "gz", "iso", "apk", "7z", "cab", "docm", "xlsm"];
    
    const shorteners = [
      "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly", 
      "rebrand.ly", "lnkd.in", "db.tt", "qr.ae", "adf.ly", "bit.do", 
      "goog.gl", "mcaf.ee", "su.pr", "fur.ly", "tiny.cc"
    ];
    const isShortener = shorteners.some(s => hostname === s || hostname.endsWith("." + s));
    const hasRedirectParam = /(\?|&)(url|redirect|goto|next|link|to)=/i.test(urlStr);
    
    const isSquat = checkTyposquatting(hostname);
    const isSpoof = checkBrandImpersonation(hostname);
    const isHomoglyph = detectScriptMixture(hostname);
    const badTld = checkSuspiciousTLD(hostname);
    const bankCheck = checkBankHeuristic(hostname, protocol);

    // Additional URL Heuristics
    const isRawIp = checkIpAddressDomain(rawHostname);
    const isSuspiciousPattern = checkSuspiciousDomainPattern(rawHostname);
    const isVeryLongDomain = checkVeryLongDomain(rawHostname);
    const isLongNumeric = checkLongNumericSequence(urlStr);
    const isPromoContent = checkSuspiciousPromotionalContent(urlStr);
    const suspParam = checkSuspiciousParams(urlStr);
    const suspPort = checkSuspiciousPort(urlStr);
    const isBrandSquat = checkPopularDomainSquatting(rawHostname);

    // Collect signals
    const signals = [];
    const findings = [];

    // 1. Connection check
    if (protocol === "http:") {
      signals.push({ id: "insecure", severity: "MEDIUM", confidence: "MEDIUM" });
      findings.push({
        category: "suspicious",
        title: "Insecure Protocol (HTTP)",
        desc: "Credentials and input data are transmitted unencrypted over the wire."
      });
    }

    // 2. Homoglyph Mixture Check
    if (isHomoglyph) {
      signals.push({ id: "homoglyph", severity: "HIGH", confidence: "HIGH" });
      findings.push({
        category: "danger",
        title: "Homograph Domain Spoofing",
        desc: "The domain mixes character scripts (e.g. Cyrillic/Greek and Latin) to impersonate a brand."
      });
    }

    // 3. Brand Impersonation Check
    if (isSpoof) {
      signals.push({ id: "spoof", severity: "MEDIUM", confidence: "MEDIUM" });
      findings.push({
        category: "danger",
        title: `Spoofing Impersonation: ${isSpoof.name.toUpperCase()}`,
        desc: `This link contains the name '${isSpoof.name}' but is hosted on a different registered domain (${getRegisteredDomain(hostname)}).`
      });
    }

    // 4. Typosquatting Check
    if (isSquat) {
      signals.push({ id: "typosquatting", severity: "MEDIUM", confidence: "MEDIUM" });
      findings.push({
        category: "danger",
        title: "Typosquatting Detected",
        desc: `Matches closely to official brand '${isSquat.brand}' (Levenshtein distance: ${isSquat.distance}).`
      });
    }

    // 5. Cheap/Suspicious TLD Check
    if (badTld) {
      signals.push({ id: "badTld", severity: "MEDIUM", confidence: "LOW" });
      findings.push({
        category: "suspicious",
        title: "Untrusted Top-Level Domain (TLD)",
        desc: `Uses the .${badTld} registry, which is frequently associated with high levels of spam and brand abuse.`
      });
    }

    // 6. Entropy Context check (ONLY trigger entropy suspicion IF COMBINED WITH: redirects, shorteners, spoofing, homoglyphs, or executable payloads)
    const isExec = execExts.includes(fileExt);
    const isArchive = archiveExts.includes(fileExt);
    const entropyContextTriggers = hasRedirectParam || isShortener || isSquat || isSpoof || isHomoglyph || isExec || isArchive;
    
    if (entropy > 3.8 && label.length > 5) {
      if (entropyContextTriggers) {
        signals.push({ id: "entropy", severity: "WEAK", confidence: "LOW" });
        findings.push({
          category: "suspicious",
          title: "High Entropy String (Randomness)",
          desc: `The main domain name has high structural entropy (${entropy.toFixed(2)}), which matches random Domain Generation Algorithms (DGA).`
        });
      }
    }

    // 7. Bank heuristic checks
    if (bankCheck) {
      if (bankCheck.reason.includes("TLD")) {
        signals.push({ id: "bankBadTld", severity: "CRITICAL", confidence: "VERY HIGH" });
      } else {
        signals.push({ id: "bankInsecure", severity: "CRITICAL", confidence: "VERY HIGH" });
      }
      findings.push({
        category: "danger",
        title: "Banking Security Risk",
        desc: bankCheck.reason
      });
    }

    // 8. Redirect Parameter
    if (hasRedirectParam) {
      signals.push({ id: "redirectParam", severity: "WEAK", confidence: "LOW" });
      findings.push({
        category: "suspicious",
        title: "Redirect Parameter Detected",
        desc: "The URL query contains a redirection parameter designed to redirect the browser to external web routing domains."
      });
    }

    // 9. Shortener
    if (isShortener) {
      signals.push({ id: "shortener", severity: "MEDIUM", confidence: "MEDIUM" });
      findings.push({
        category: "suspicious",
        title: "Shortened Redirect Origin",
        desc: "The link originates from a URL shortener service, which is frequently used to mask suspicious destinations."
      });
    }

    // 10. Executable payload target
    if (isExec) {
      signals.push({ id: "execPayload", severity: "CRITICAL", confidence: "VERY HIGH" });
      findings.push({
        category: "danger",
        title: "Executable Payload Target",
        desc: "This page references executable or script-based payload delivery (.exe/.msi)."
      });
    } else if (isArchive) {
      signals.push({ id: "archivePayload", severity: "HIGH", confidence: "HIGH" });
      findings.push({
        category: "suspicious",
        title: "Archive Payload Target",
        desc: "This page references compressed archive or macro-enabled download payload delivery."
      });
    }

    // 11. Suspicious Threat Keywords Check
    const keywords = getSuspiciousKeywords(urlStr);
    if (keywords.length > 0) {
      signals.push({ id: "keywords", severity: "WEAK", confidence: "LOW" });
      findings.push({
        category: "suspicious",
        title: "Suspicious Threat Keywords",
        desc: `Contains keywords linked to social engineering: ${keywords.join(', ')}.`
      });
    }

    // 12. Credential Parameter Exposure Check
    const hasCredParams = /(\?|&)(email|usr|user|username|signin|login|pwd|pass|password)=/i.test(urlStr);
    if (hasCredParams) {
      signals.push({ id: "credParams", severity: "WEAK", confidence: "LOW" });
      findings.push({
        category: "suspicious",
        title: "Credential Parameter Exposure",
        desc: "The URL structure exposes query parameters typically related to user identity, common in targeted credential harvesting."
      });
    }

    // 13. IP Address Domain Check
    if (isRawIp) {
      signals.push({ id: "rawIpDomain", severity: "HIGH", confidence: "HIGH" });
      findings.push({
        category: "danger",
        title: "IP Address Hostname",
        desc: `URL references a raw numeric IP address (${rawHostname}) instead of a resolved domain name, bypassing typical DNS checks.`
      });
    }

    // 14. Suspicious Domain Pattern
    if (isSuspiciousPattern) {
      signals.push({ id: "suspDomainPattern", severity: "MEDIUM", confidence: "MEDIUM" });
      findings.push({
        category: "suspicious",
        title: "Suspicious Subdomain Pattern",
        desc: "Domain pattern exhibits multiple hyphenated word structures typical of dynamic generated names."
      });
    }

    // 15. Very Long Domain
    if (isVeryLongDomain) {
      signals.push({ id: "longDomainLabel", severity: "WEAK", confidence: "MEDIUM" });
      findings.push({
        category: "suspicious",
        title: "Excessive Domain Label Length",
        desc: "Contains a domain segment exceeding 25 characters, which is typical of obfuscation tactics."
      });
    }

    // 16. Long Numeric Sequence
    if (isLongNumeric) {
      signals.push({ id: "longNumeric", severity: "WEAK", confidence: "MEDIUM" });
      findings.push({
        category: "suspicious",
        title: "Long Numeric Sequence",
        desc: "Contains a sequence of more than 10 consecutive digits in the URL structure."
      });
    }

    // 17. Suspicious Promotional Content
    if (isPromoContent) {
      signals.push({ id: "promoContent", severity: "WEAK", confidence: "LOW" });
      findings.push({
        category: "suspicious",
        title: "Promotional Scam Keywords",
        desc: "Contains text matching high-probability social engineering phrases (free, lottery, prize, winner, click here)."
      });
    }

    // 18. Suspicious Parameters
    if (suspParam) {
      signals.push({ id: "suspParam", severity: "MEDIUM", confidence: "MEDIUM" });
      findings.push({
        category: "suspicious",
        title: `Suspicious Redirect Parameter`,
        desc: `Uses query parameter '${suspParam}' representing redirect intents, often masking third-party destination routing.`
      });
    }

    // 19. Suspicious Port
    if (suspPort) {
      signals.push({ id: "suspPort", severity: "HIGH", confidence: "HIGH" });
      findings.push({
        category: "danger",
        title: `Suspicious Protocol Port`,
        desc: `Requests network connection through an unusual port (${suspPort}), typical of non-standard administrative backend endpoints.`
      });
    }

    // 20. Brand Squatting
    if (isBrandSquat) {
      signals.push({ id: "brandSquatting", severity: "HIGH", confidence: "HIGH" });
      findings.push({
        category: "danger",
        title: `Popular Brand Squatting`,
        desc: `Contains popular brand name '${isBrandSquat}' inside the domain, but is not hosted on that brand's official domain name.`
      });
    }

    // Compute weighted confidence score
    let maxSeverity = "NONE";
    let baseScore = 0;
    let overallConfidence = "Strong";

    // Map severity weights
    const severityWeights = {
      "NONE": { score: 0, confidence: "Strong" },
      "WEAK": { score: 20, confidence: "Low" },
      "MEDIUM": { score: 45, confidence: "Medium" },
      "HIGH": { score: 75, confidence: "High" },
      "CRITICAL": { score: 90, confidence: "Very High" }
    };

    // Find highest severity signal
    signals.forEach(sig => {
      const currentWeight = severityWeights[sig.severity].score;
      const maxWeight = severityWeights[maxSeverity].score;
      if (currentWeight > maxWeight) {
        maxSeverity = sig.severity;
      }
    });

    baseScore = severityWeights[maxSeverity].score;
    overallConfidence = severityWeights[maxSeverity].confidence;

    // Small increments for additional active signals of the same or lower level
    let finalScore = baseScore;
    if (maxSeverity === "MEDIUM") {
      const extraSignals = signals.filter(s => s.id !== "entropy" && s.id !== "redirectParam" && s.severity === "MEDIUM").length - 1;
      if (extraSignals > 0) {
        finalScore += extraSignals * 10;
      }
      finalScore = Math.min(finalScore, 55); // Clamp Medium category
    } else if (maxSeverity === "HIGH") {
      const extraSignals = signals.filter(s => s.severity === "HIGH" || s.severity === "MEDIUM").length - 1;
      if (extraSignals > 0) {
        finalScore += extraSignals * 5;
      }
      finalScore = Math.min(finalScore, 84); // Clamp High category
    } else if (maxSeverity === "WEAK") {
      const extraSignals = signals.length - 1;
      if (extraSignals > 0) {
        finalScore += extraSignals * 5;
      }
      finalScore = Math.min(finalScore, 29); // Clamp Weak category
    }

    // 11. Intent and Page-Type Confidence
    let intent = "GENERAL WEB CONTENT";
    let intentConfidence = "Strong";

    const isThreatIntel = [
      "virustotal.com", "abuseipdb.com", "abuse.ch", "urlhaus.abuse.ch", 
      "alienvault.com", "threatminer.org", "shodan.io", "censys.io"
    ].some(domain => hostname === domain || hostname.endsWith("." + domain));

    const isCloudStorage = [
      "drive.google.com", "dropbox.com", "mediafire.com", "mega.nz", 
      "onedrive.live.com", "s3.amazonaws.com", "github.com"
    ].some(domain => hostname === domain || hostname.endsWith("." + domain));

    const isCrypto = [
      "wallet", "binance", "metamask", "coinbase", "trustwallet", "crypto", 
      "phantom", "uniswap", "kraken", "ledger"
    ].some(kw => hostname.includes(kw) || linkTextClean.includes(kw));

    if (isEmail) {
      intent = "EMAIL CORRESPONDENCE";
      intentConfidence = "Strong";
    } else if (isExec) {
      intent = "EXECUTABLE DISTRIBUTION";
      intentConfidence = "Strong";
    } else if (isArchive) {
      intent = "ARCHIVE / DOWNLOAD PAYLOAD";
      intentConfidence = "Strong";
    } else if (isShortener) {
      intent = "SHORTENER";
      intentConfidence = "Strong";
    } else if (isThreatIntel) {
      intent = "THREAT INTELLIGENCE PLATFORM";
      intentConfidence = "Strong";
    } else if (isCloudStorage) {
      intent = "CLOUD STORAGE / HOSTING";
      intentConfidence = "Strong";
    } else if (isCrypto) {
      intent = "CRYPTO / WALLET PLATFORM";
      intentConfidence = "Strong";
    } else if (
      pathname.includes("checkout") || pathname.includes("payment") || 
      pathname.includes("stripe") || pathname.includes("billing") || 
      pathname.includes("pay") || search.includes("pay") ||
      linkTextClean.includes("pay") || linkTextClean.includes("checkout") || 
      linkTextClean.includes("buy") || hasCardInputs
    ) {
      intent = "PAYMENT / TRANSACTION GATEWAY";
      intentConfidence = hasCardInputs ? "Strong" : "Weak";
    } else if (
      pathname.includes("login") || pathname.includes("signin") || 
      pathname.includes("auth") || pathname.includes("oauth") || 
      pathname.includes("register") || pathname.includes("signup") ||
      pathname.includes("verification") || pathname.includes("verify") ||
      linkTextClean.includes("login") || linkTextClean.includes("sign in") || 
      linkTextClean.includes("verify") || linkTextClean.includes("register") ||
      linkTextClean.includes("account") || hasPasswordFields
    ) {
      intent = "LOGIN / ACCESS PORTAL";
      intentConfidence = hasPasswordFields ? "Strong" : "Weak";
    } else if (
      pathname.includes("download") || pathname.includes("install") || 
      pathname.includes("setup") || pathname.includes("get") ||
      linkTextClean.includes("download") || linkTextClean.includes("install") ||
      linkTextClean.includes("setup") || linkTextClean.includes("get the app")
    ) {
      intent = "FILE DOWNLOAD INTERFACE";
      intentConfidence = "Strong";
    } else if (hasRedirectParam) {
      intent = "LINK REDIRECT ROUTER";
      intentConfidence = "Strong";
    }

    // 12. Non-Authoritative Caution Wording
    let cautionLevel = "No immediate structural threats detected";
    let risk = "LOW";
    
    if (finalScore >= 55) {
      cautionLevel = "Multiple high-risk structural indicators detected. Behavioral execution analysis unavailable.";
      risk = "HIGH";
    } else if (finalScore >= 25) {
      cautionLevel = "This page exhibits patterns commonly associated with suspicious infrastructure.";
      risk = "MEDIUM";
    }

    // 13. Dynamic Narrative Explanation
    let explanation = "";
    if (isExec) {
      explanation = "This page references executable or script-based payload delivery.";
    } else if (isArchive) {
      explanation = "This page references compressed archive or macro-enabled download payload delivery.";
    } else if (isSquat || isSpoof || isHomoglyph || isBrandSquat) {
      explanation = "Contains visual brand mimicry or character-spoofing homoglyphs targeting official registered domains.";
    } else if (isShortener) {
      explanation = "Uses a shortened link service which masks the final destination.";
    } else if (protocol === "http:") {
      explanation = "Insecure connection route. Input data or credentials will be sent without encryption.";
    } else if (hasRedirectParam || suspParam) {
      explanation = "Contains query instructions designed to redirect the browser to external web routing domains.";
    } else if (finalScore >= 25) {
      explanation = "Displays subtle structural anomalies, including unusual top-level domains or randomized entropy.";
    } else {
      explanation = "Standard URL structure configured with secure protocols and mature reputation markers.";
    }

    return {
      success: true,
      score: finalScore,
      risk: risk,
      cautionLevel: cautionLevel,
      intent: intent,
      intentConfidence: intentConfidence,
      explanation: explanation,
      findings: findings,
      hostname: hostname,
      fileExt: fileExt,
      signals: signals
    };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

/**
 * Checks if a URL string represents a mailto link or raw email address.
 */
function isEmailOrMailto(urlStr) {
  if (!urlStr) return false;
  const clean = urlStr.trim().toLowerCase();
  if (clean.startsWith("mailto:")) return true;
  return /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(clean);
}

/**
 * Extracts the domain part of an email address or mailto link.
 */
function extractDomainFromEmailOrMailto(urlStr) {
  if (!urlStr) return "";
  let clean = urlStr.trim();
  if (clean.toLowerCase().startsWith("mailto:")) {
    clean = clean.substring(7);
  }
  const parts = clean.split('@');
  if (parts.length > 1) {
    return parts[1].split('?')[0].toLowerCase();
  }
  return clean;
}

/**
 * Calculates additive threat indicator weights for explanation.
 * Shared between background (for hover tooltip) and popup (for full report).
 */
function getScoreExplainItems(urlStr, isEmail, findings, activeDnsResult, activeAgeResult, activeTabBehaviors, activeReputationData) {
  let urlObj;
  try {
    let checkUrl = urlStr;
    if (isEmail) {
      const emailDomain = extractDomainFromEmailOrMailto(urlStr);
      checkUrl = "https://" + emailDomain;
    }
    urlObj = new URL(checkUrl);
  } catch (e) {
    return [];
  }

  const hostname = isEmail ? extractDomainFromEmailOrMailto(urlStr) : urlObj.hostname;
  const regDomain = getRegisteredDomain(hostname);
  const label = regDomain ? regDomain.split('.')[0] : "";

  let explainItems = [];

  // Protocol check
  if (!isEmail) {
    if (urlObj.protocol === "http:") {
      explainItems.push({
        name: "HTTP only",
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
  if (checkSuspiciousPort(urlStr)) {
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
        name: "Missing reverse DNS",
        score: 10,
        observed: "No active IPv4 A records found for this domain name",
        inferred: "DNS infrastructure exhibits structural anomaly",
        category: "structural"
      });
    }
  }

  // MX / SPF records (only for email)
  if (isEmail && activeDnsResult && activeDnsResult.success && activeDnsResult.dnsRecords) {
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

  // Heuristics findings
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
    if (activeReputationData.vt) {
      if (activeReputationData.vt.status === "success" && activeReputationData.vt.malicious > 0) {
        explainItems.push({
          name: `VirusTotal detections (${activeReputationData.vt.malicious})`,
          score: activeReputationData.vt.malicious * 10,
          observed: `Flagged as malicious by ${activeReputationData.vt.malicious} engine(s) on VirusTotal`,
          inferred: "External threat reports confirm active suspicious activity",
          category: "reputation"
        });
        hasReputationIndicator = true;
      }
    }
    if (activeReputationData.abuse) {
      if (activeReputationData.abuse.status === "success" && activeReputationData.abuse.abuseScore > 10) {
        explainItems.push({
          name: `AbuseIPDB report flag (${activeReputationData.abuse.abuseScore}%)`,
          score: Math.floor(activeReputationData.abuse.abuseScore / 2),
          observed: `IP hosting infrastructure has a ${activeReputationData.abuse.abuseScore}% abuse report rate`,
          inferred: "IP has high volumes of abuse traffic reports (spam, DDoS, ports)",
          category: "reputation"
        });
        hasReputationIndicator = true;
      }
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

  return explainItems;
}
