// truncates domain to last two parts
function getBaseDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length >= 2) {
    return parts.slice(-2).join('.');
  }
  return hostname;
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url && tab.active) {
      const domain = new URL(tab.url).hostname;
      const keywords = getBaseDomain(domain);
  
      checkNVDScore(keywords).then(cvssScore => {
        const scaledScore = Math.min(cvssScore * 2, 20); // Scale 0–10 to 0–20
        console.log(`[NVD] CVSS Score for ${domain}: ${cvssScore} → Scaled: ${scaledScore}`);
  
        if (scaledScore >= 15) {
          chrome.scripting.executeScript({
            target: { tabId: tabId },
            func: () => alert("⚠️ Warning: This site may be vulnerable according to the National Vulnerability Database.")
          });
  
          chrome.action.setBadgeText({ tabId, text: "⚠️" });
          chrome.action.setBadgeBackgroundColor({ tabId, color: "#FF0000" });
        } else {
          chrome.action.setBadgeText({ tabId, text: "" });
        }
      });
    }
  });

  chrome.identity.getProfileUserInfo(function(userInfo) {
    currUser_email = userInfo.email;
    currUser_ID = userInfo.id;
  });
  
  async function checkNVDScore(keyword) {
    try {
      const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${keyword}&resultsPerPage=5`, {
        headers: {
          "apiKey": "9f2edcdf-9980-47c4-9be3-8a0498032ba0"  // Optional but recommended
        }
      });
      console.log("Fetching URL:", `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${keyword}&resultsPerPage=5`);
      const data = await response.json();
      console.log("API response: ", data)
      if (!data.vulnerabilities || data.vulnerabilities.length === 0) return 0;
  
      const scores = data.vulnerabilities
        .map(v => v.cvssMetricV31?.[0]?.cvssData?.baseScore || 0)
        .filter(score => score > 0)
        .slice(0, 3);
  
      if (scores.length === 0) return 0;
  
      const avgScore = scores.reduce((a, b) => a + b, 0) / scores.length;
      return avgScore;
    } catch (err) {
      console.error("[NVD Error]", err);
      return 0;
    }
  }
    