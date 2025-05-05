let sorted = [];

// Helper to extract base domain (same as background.js)
function getBaseDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length >= 2) {
    return parts.slice(-2).join('.');
  }
  return hostname;
}

// ML Model weights and configuration
const weights = {
  "having_IP_Address": 0.35,
  "URL_Length": 0.08,
  "having_At_Symbol": 0.15,
  "double_slash_redirecting": -0.13,
  "Prefix_Suffix": 3.07,
  "having_Sub_Domain": 0.64,
  "URL_of_Anchor": 3.6,
  "HTTPS_token": -0.29,
  "SFH": 0.78,
  "Iframe": -0.28
};

const intercept = 4.50696702;
const threshold = 0.6;

// Calculate ML model probability
function calculateMLProbability(features) {
  let z = intercept;
  for (const feature in weights) {
    if (features[feature]) {
      z += (weights[feature] + Math.random()/10) * parseFloat(features[feature]);
    }
  }
  return 1 / (1 + Math.pow(Math.E, (z * -1)));
}

// Google Safe Browsing API check
async function checkGoogleSafeBrowsing(url) {
  const API_KEY = 'AIzaSyC8cknUlHcUJb0NjagV4mfJZ9-0mAxnQEY';
  try {
    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: {
          clientId: "CS_TEST",
          clientVersion: "1.5.2"
        },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url: url }]
        }
      })
    });

    const data = await response.json();
    return data && data.matches ? 1.0 : 0.0; // Return 1.0 if unsafe, 0.0 if safe
  } catch (error) {
    console.error('Google Safe Browsing API Error:', error);
    return 0.0;
  }
}

// NVD API check
async function checkNVDScore(domain) {
  try {
    const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${domain}&resultsPerPage=5`, {
      headers: {
        "apiKey": "888a352e-c59e-4a55-8ca3-38a98ff23af9"
      }
    });

    const data = await response.json();
    if (!data.vulnerabilities || data.vulnerabilities.length === 0) return 0;

    const scores = data.vulnerabilities
      .map(v => v.cvssMetricV31?.[0]?.cvssData?.baseScore || 0)
      .filter(score => score > 0)
      .slice(0, 3);

    if (scores.length === 0) return 0;
    return scores.reduce((a, b) => a + b, 0) / scores.length / 10; // Normalize to 0-1 scale
  } catch (err) {
    console.error("[NVD Error]", err);
    return 0;
  }
}

// Get website suggestions
async function getSuggestions(domain) {
  const prompt = `The website "${domain}" appears unsafe. Suggest 3 reputable alternative websites that offer similar content or services.`;

  try {
    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": "Bearer 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",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "gpt-3.5-turbo",
        messages: [{ role: "user", content: prompt }],
        max_tokens: 100,
        temperature: 0.7
      })
    });

    const data = await response.json();
    if (data.choices && data.choices[0]) {
      const suggestionsDiv = document.getElementById("suggestions");
      suggestionsDiv.innerHTML = `
        <h4 class="text-xl font-semibold text-gray-700 mt-4 mb-2">Recommended Alternatives:</h4>
        <p class="text-gray-600">${data.choices[0].message.content.replace(/\n/g, "<br>")}</p>
      `;
    }
  } catch (err) {
    console.error("Error getting suggestions:", err);
    document.getElementById("suggestions").innerHTML = "Failed to get suggestions.";
  }
}

// Add these functions for API key management
function getOpenAIKey() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(['openaiApiKey'], function(result) {
      resolve(result.openaiApiKey || '');
    });
  });
}

function setOpenAIKey(key) {
  return new Promise((resolve) => {
    chrome.storage.sync.set({ 'openaiApiKey': key }, function() {
      resolve();
    });
  });
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

  // Add API key handling
  const apiKeyInput = document.getElementById('apiKey');
  const saveButton = document.getElementById('saveKey');
  const keyStatus = document.getElementById('keyStatus');

  // Load existing API key
  getOpenAIKey().then(key => {
    if (key) {
      apiKeyInput.value = key;
      keyStatus.textContent = 'API key is set';
      keyStatus.className = 'text-green-600';
    }
  });

  saveButton.addEventListener('click', async function() {
    const apiKey = apiKeyInput.value.trim();
    
    if (!apiKey) {
      keyStatus.textContent = 'Please enter an API key';
      keyStatus.className = 'text-red-600';
      return;
    }

    await setOpenAIKey(apiKey);
    keyStatus.textContent = 'API key saved successfully!';
    keyStatus.className = 'text-green-600';
    
    // Hide the status message after 3 seconds
    setTimeout(() => {
      keyStatus.textContent = 'API key is set';
    }, 3000);
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

    // Get all scores
    const [mlScore, googleScore, nvdScore] = await Promise.all([
      new Promise(resolve => {
        chrome.storage.local.get("features", (result) => {
          resolve(result.features ? calculateMLProbability(result.features) : 0);
        });
      }),
      checkGoogleSafeBrowsing(tab.url),
      checkNVDScore(domain)
    ]);

    // Get the highest score
    const highestScore = Math.max(mlScore, googleScore, nvdScore);
    const scoreElem = document.getElementById("score");
    const statusElem = document.getElementById("status");

    scoreElem.textContent = `${(highestScore * 100).toFixed(1)}%`;

    if (highestScore >= 0.6) {
      scoreElem.className = "danger";
      statusElem.textContent = "⚠️ Warning: High risk detected!";
      getSuggestions(domain);
    } else if (highestScore === 0) {
      scoreElem.className = "safe";
      statusElem.textContent = "✅ No major risks detected.";
    } else {
      scoreElem.className = "warning";
      statusElem.textContent = "⚠️ Moderate risk detected.";
    }

    saveScanResult(domain, highestScore);
    loadScanHistory();
  });
});


