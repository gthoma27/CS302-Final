chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url && tab.active) {
      const domain = new URL(tab.url).hostname;
      const keywords = domain;
  
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
  
  async function checkNVDScore(keyword) {
    try {
      const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${keyword}&resultsPerPage=5`, {
        headers: {
          "apiKey": "eef9dfda-aa71-41fd-adb4-8e36682a827b"  // Optional but recommended
        }
      });
  
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
  