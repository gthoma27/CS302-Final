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

      getSimilarWebsites(domain).then(similarSites => {
        if (similarSites.length > 0) {
          chrome.scripting.executeScript({
            target: { tabId: tabId },
            func: (sites) => {
              const message = "Similar websites you might be interested in:\n" + sites.join('\n');
              alert(message);
            },
            args: [similarSites]
          });
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
          "apiKey": "888a352e-c59e-4a55-8ca3-38a98ff23af9"  // Optional but recommended
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
  
  function setOpenAIKey(key) {
    chrome.storage.sync.set({ 'openaiApiKey': key }, function() {
      console.log('API key saved');
    });
  }
  
  function getOpenAIKey() {
    return new Promise((resolve) => {
      chrome.storage.sync.get(['openaiApiKey'], function(result) {
        resolve(result.openaiApiKey || '');
      });
    });
  }
  
  async function getSimilarWebsites(domain) {
    try {
      const apiKey = await getOpenAIKey();
      if (!apiKey) {
        console.error("OpenAI API key not set");
        return [];
      }

      const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          model: "gpt-3.5-turbo",
          messages: [
            {
              role: "system",
              content: "You are a helpful assistant that suggests similar websites based on the given domain."
            },
            {
              role: "user",
              content: `Suggest 3 similar websites to ${domain}. Return only the domain names, one per line.`
            }
          ],
          temperature: 0.7,
          max_tokens: 100
        })
      });

      const data = await response.json();
      if (data.choices && data.choices[0]) {
        return data.choices[0].message.content.split('\n').filter(Boolean);
      }
      return [];
    } catch (err) {
      console.error("[OpenAI Error]", err);
      return [];
    }
  }
  