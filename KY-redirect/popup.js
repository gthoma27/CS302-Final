let sorted = [];

// ----------------- NVD API: Get vulnerability score -----------------
//
async function getNVDScore(domain) {
  const keyword = domain.split('.').slice(0, -1).join('.');
  try {
    const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${keyword}&resultsPerPage=5`, {
      headers: {
        "apiKey": "888a352e-c59e-4a55-8ca3-38a98ff23af9"
      }
    });

    const data = await response.json();
    if (!data.vulnerabilities || data.vulnerabilities.length === 0) return -1;

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
You are a cybersecurity assistant. 
If the website "${domain}" has a high vulnerability risk, recommend 3 alternative safe and reputable websites that provide similar services. 
If you don't recognize the website, recommend 3 general safe websites like Google, Wikipedia, or DuckDuckGo.
Format your answer nicely in a list.
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
    console.log("OpenAI response:", data);

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

function loadScanHistory() {
  chrome.storage.local.get(['scanHistory'], (res) => {
    const history = res.scanHistory || [];
    const container = document.getElementById('history');
    container.innerHTML = '';

    history
      .sort((a, b) => b.score - a.score)
      .forEach(entry => {
        const div = document.createElement('div');
        div.textContent = `${entry.domain} – Score: ${roundToTenths(entry.score)}`;
        container.appendChild(div);
      });
  });
}

// ----------------- MAIN -----------------
document.addEventListener('DOMContentLoaded', () => {
  loadScanHistory();
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

  const forceBadSite = true;  // 🔥 Set to 'true' for always triggering ChatGPT during testing

  if (forceBadSite || scaled >= 15) {
    scoreElem.className = "danger";
    statusElem.textContent = "⚠️ Warning: High vulnerability risk!";

    const suggestions = await getChatGPTRecommendations(domain);
    const suggestionsDiv = document.createElement('div');
    suggestionsDiv.innerHTML = `
      <h4 class="text-xl font-semibold text-gray-700 mt-4 mb-2">Recommended Alternatives:</h4>
      <p class="text-gray-600">${(await suggestions).replace(/\n/g, "<br>")}</p>
    `;
    document.body.appendChild(suggestionsDiv);

  } else if (cvssScore === -1) {
    scoreElem.className = "danger";
    statusElem.textContent = "Website Unknown - Use caution!";
  } else {
    scoreElem.className = "safe";
    statusElem.textContent = "✅ No major known vulnerabilities.";
  }

  saveScanResult(domain, cvssScore);
  loadScanHistory();
});
