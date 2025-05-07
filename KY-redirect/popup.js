let sorted = [];

// Helper to extract base domain (same as background.js)
function getBaseDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length >= 2) {
    return parts.slice(-2).join('.');
  }
  return hostname;
}

// ----------------- NVD API: Get vulnerability score -----------------
//
async function getNVDScore(domain) {
  const keyword = getBaseDomain(domain);
  try {
    const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${keyword}&resultsPerPage=5`, {
      headers: {
        "apiKey": "6d889317-07c4-463b-86c3-8bed8b89be00"
      }
    });
    console.log(response);
    if (!response.ok) {
      console.error(`NVD API error: ${response.status} ${response.statusText}`);
      return 0;
    }
    const data = await response.json();
    if (!data.vulnerabilities || data.vulnerabilities.length === 0) return 0;

    const scores = data.vulnerabilities
      .map(vuln => {
        const metrics = vuln.cve.metrics || {};
        const v3 = metrics.cvssMetricV31?.[0]?.cvssData?.baseScore;
        const v2 = metrics.cvssMetricV2?.[0]?.cvssData?.baseScore;
        return v3 ?? v2 ?? 0;
      })
      .filter(score => score > 0)
      .slice(0, 3);

    if (scores.length === 0) return 0;
    return scores.reduce((a, b) => a + b, 0) / scores.length;
  } catch (err) {
    console.error("NVD fetch error:", err);
    return 0;
  }
}

// ----------------- OpenAI API: Get ChatGPT suggestions -----------------
async function getChatGPTRecommendations(domain) {
  const prompt = `
If the website "${domain}" has a high vulnerability risk, recommend 3 alternative safe and reputable websites that provide similar services. 
If you don't recognize the website, recommend general safe websites like Google, Wikipedia, or DuckDuckGo.
Return them as a list.
`;

  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer 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',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: "gpt-3.5-turbo",
        messages: [
          { role: "system", content: "You are a helpful assistant that recommends safer websites." },
          { role: "user", content: prompt }
        ],
        temperature: 0.5,
        max_tokens: 300
      })
    });

    const data = await response.json();
    if (data.choices && data.choices.length > 0) {
      return data.choices[0].message.content.trim();
    } else {
      return "No suggestions found.";
    }
  } catch (error) {
    console.error('Error fetching ChatGPT recommendations:', error);
    return "Error fetching recommendations.";
  }
}




// ----------------- Utilities: Save scan result -----------------
function roundToTenths(number) {
  return Math.round(number * 10) / 10;
}

function saveScanResult(domain, score) {
  chrome.storage.local.get(['scanHistory'], (res) => {
    const history = res.scanHistory || [];
    const updatedHistory = history.filter(entry => entry.domain !== domain);
    updatedHistory.push({ domain, score, scannedAt: Date.now() });
    chrome.storage.local.set({ scanHistory: updatedHistory }, () => {
      if (chrome.runtime.lastError) {
        console.error("Error saving scan history:", chrome.runtime.lastError);
      }
    });
  });
}

function loadScanHistory(order = 'desc') {
  chrome.storage.local.get(['scanHistory'], (res) => {
    const history = res.scanHistory || [];
    const container = document.getElementById('history');
    container.innerHTML = '';

    // Sort based on order
    history.sort((a, b) => order === 'asc' ? a.score - b.score : b.score - a.score);

    history.forEach(entry => {
      const div = document.createElement('div');
      div.textContent = `${entry.domain} – Score: ${entry.score <= 0 ? 'No vulnerabilities found' : roundToTenths(entry.score)}`;
      container.appendChild(div);
    });
  });
}

// ----------------- MAIN -----------------
document.addEventListener('DOMContentLoaded', () => {
  loadScanHistory();

  // Add event listeners for sort buttons
  const sortHighBtn = document.getElementById('sort-high');
  const sortLowBtn = document.getElementById('sort-low');
  if (sortHighBtn && sortLowBtn) {
    sortHighBtn.addEventListener('click', () => loadScanHistory('desc'));
    sortLowBtn.addEventListener('click', () => loadScanHistory('asc'));
  }

  // Add event listener for clear history button
  const clearBtn = document.getElementById('clear-history');
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      chrome.storage.local.set({ scanHistory: [] }, () => loadScanHistory());
    });
  }
});

// ----------------- When popup opens -----------------
chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
  if (!tabs || tabs.length === 0) {
    console.error('No active tab found');
    return;
  }

  const tab = tabs[0];
  if (!tab.url) {
    console.error('No URL found for tab');
    return;
  }

  const url = new URL(tab.url);
  const domain = url.hostname;
  document.getElementById("domain").textContent = domain;

  const cvssScore = await getNVDScore(domain);
  const scaled = Math.min(cvssScore * 2, 20);
  const scoreElem = document.getElementById("score");
  const statusElem = document.getElementById("status");

  scoreElem.textContent = `${cvssScore.toFixed(1)} / 10`;

  if (cvssScore === 0) {
    scoreElem.className = "safe";
    statusElem.textContent = "✅ No known vulnerabilities.";
  } else if (cvssScore > 0 && cvssScore <= 3) {
    scoreElem.className = "low-risk";
    statusElem.textContent = "⚠️ Low risk site. Consider alternatives.";

    const suggestions = await getChatGPTRecommendations(domain);
    console.log("GPT Suggestions for", domain, ":", suggestions);

    const suggestionsDiv = document.createElement('div');
    suggestionsDiv.innerHTML = `
      <h4 class="text-xl font-semibold text-gray-700 mt-4 mb-2">Recommended Alternatives:</h4>
      <p class="text-gray-600 whitespace-pre-line">${suggestions}</p>

    `;
    document.body.appendChild(suggestionsDiv);

  } else if (cvssScore > 3 && cvssScore <= 7) {
    scoreElem.className = "medium-risk";
    statusElem.textContent = "⚠️ Medium risk site. Consider alternatives.";

    const suggestions = await getChatGPTRecommendations(domain);
    console.log("GPT Suggestions for", domain, ":", suggestions);

    const suggestionsDiv = document.createElement('div');
    suggestionsDiv.innerHTML = `
      <h4 class="text-xl font-semibold text-gray-700 mt-4 mb-2">Recommended Alternatives:</h4>
      <p class="text-gray-600 whitespace-pre-line">${suggestions}</p>

    `;
    document.body.appendChild(suggestionsDiv);

  } else if (cvssScore > 7 && cvssScore <= 10) {
    scoreElem.className = "high-risk";
    statusElem.textContent = "🚨 High risk site! Safer alternatives recommended.";

    const suggestions = await getChatGPTRecommendations(domain);
    console.log("GPT Suggestions for", domain, ":", suggestions);

    const suggestionsDiv = document.createElement('div');
    suggestionsDiv.innerHTML = `
      <h4 class="text-xl font-semibold text-gray-700 mt-4 mb-2">Recommended Alternatives:</h4>
      <p class="text-gray-600 whitespace-pre-line">${suggestions}</p>

    `;
    document.body.appendChild(suggestionsDiv);
  }

  saveScanResult(domain, cvssScore);
  loadScanHistory();
});