const phishingKeywords = [
    "verify your account",
    "login to continue",
    "your account has been suspended",
    "update your information",
    "confirm your identity",
    "password expired",
    "secure verification"
  ];
  
  function containsPhishingKeywords(text) {
    return phishingKeywords.some(keyword =>
      text.toLowerCase().includes(keyword)
    );
  }
  
  function isIpAddress(url) {
    const ipRegex = /^https?:\/\/(\d{1,3}\.){3}\d{1,3}/;
    return ipRegex.test(url);
  }
  
  function isSuspiciousUrl(url) {
    return url.length > 75 || url.includes('@') || url.includes('=');
  }
  
  function containsPasswordInput() {
    return !!document.querySelector('input[type="password"]');
  }
  
  function calculatePhishingScore(url, pageText, domainInfo = {}) {
    let score = 0;
  
    if (isIpAddress(url)) score += 15;
    if (!url.startsWith('https://')) score += 10;
    if (isSuspiciousUrl(url)) score += 5;
  
    if (containsPasswordInput()) score += 10;
    if (containsPhishingKeywords(pageText)) score += 10;
  
    if (domainInfo.isNewDomain) score += 15;
    if (domainInfo.isBlacklisted) score += 30;
  
    return score;
  }
  
  // Auto-run when the page finishes loading
  window.addEventListener("load", () => {
    const url = window.location.href;
    const pageText = document.body.innerText || "";
  
    // Dummy domain info for now — later, fetch WHOIS or a blacklist
    const domainInfo = {
      isNewDomain: false,
      isBlacklisted: false
    };
  
    const score = calculatePhishingScore(url, pageText, domainInfo);
    console.log("[Phishing Detector] Score:", score);
  
    if (score >= 30) {
      alert("⚠️ This page may be a phishing attempt!");
    }
  });
  