// popup.js

// ─────────────────────────────────────────────────────────────────────────────
// 1) Insert your IPQS key here (or fetch from chrome.storage/env)
const IPQS_KEY = "rdOjzzP6q6Am7NMkMxDZ2dlVmdIdfTgE";
const OPENAI_API_KEY = "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";



// ─────────────────────────────────────────────────────────────────────────────
// 2) ML Model weights (unchanged)
let sorted = [];

const weights = {
  having_IP_Address: 0.32,
  URL_Length:        0.01,
  having_At_Symbol:  0.18,
  double_slash_redirecting: 0.03,
  Prefix_Suffix:     3.25,
  having_Sub_Domain: 0.69,
  URL_of_Anchor:     3.75,
  HTTPS_token:      -0.36,
  SFH:               0.77,
  Links_in_tags:     0.92,
  Submitting_to_email: -0.14
};


// ─────────────────────────────────────────────────────────────────────────────
// 3) Helper: extract base domain
function getBaseDomain(hostname) {
  const parts = hostname.split('.');
  return parts.length >= 2
    ? parts.slice(-2).join('.')
    : hostname;
}


// ─────────────────────────────────────────────────────────────────────────────
// 4) Google Safe Browsing check (unchanged)
async function safe_check(url) {
  const API_KEY = 'AIzaSyC8cknUlHcUJb0NjagV4mfJZ9-0mAxnQEY';
  try {
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: "yourclient", clientVersion: "1.5.2" },
          threatInfo: {
            threatTypes:      ["MALWARE","SOCIAL_ENGINEERING"],
            platformTypes:    ["WINDOWS"],
            threatEntryTypes: ["URL"],
            threatEntries:    [{ url }]
          }
        })
      }
    );
    const data = await response.json();
    return data.matches ? "Unsafe" : "Safe";
  } catch (err) {
    console.error("Google Safe Browsing error:", err);
    return "Error";
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// 5) IPQS Malicious URL Scanner API call
//    Returns { unsafe: bool, phishing: bool, riskScore: 0–100 }
async function getIPQSScore(url) {
  const endpoint = 
    `https://www.ipqualityscore.com/api/json/url/${IPQS_KEY}/${encodeURIComponent(url)}`;
  try {
    const resp = await fetch(endpoint);
    const data = await resp.json();
    return {
      unsafe:    !!data.unsafe,
      phishing:  !!data.phishing,
      riskScore: Number.isFinite(data.risk_score) ? data.risk_score : 0
    };
  } catch (err) {
    console.error("IPQS lookup error:", err);
    // default to safe
    return { unsafe: false, phishing: false, riskScore: 0 };
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// 6) Load feature vector from content script and compute ML probability
function get_feature_data() {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get("features", (res) => {
      const f = res.features || {};
      // logistic regression: σ(w·x)
      let dot = 0;
      for (const [k,v] of Object.entries(weights)) {
        dot += (f[k] || 0) * v;
      }
      const prob = Math.round((1 / (1 + Math.exp(-dot))) * 100);
      resolve(prob);
    });
  });
}


// ─────────────────────────────────────────────────────────────────────────────
// 7) Get ChatGPT suggestions (unchanged)
async function getChatGPTRecommendations(domain) {
  const prompt = `
If the website "${domain}" has a high vulnerability risk, recommend safe and reputable websites that provide similar services. 
If you don't recognize the website, recommend general safe websites like Google, Wikipedia, or DuckDuckGo.
Return them as a list.
  `;
  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${OPENAI_API_KEY}`
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: prompt }]
      })
    });
    const json = await response.json();
    return json.choices?.[0]?.message?.content.trim() 
      || "No suggestions available.";
  } catch (err) {
    console.error("ChatGPT error:", err);
    return "Error fetching suggestions.";
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// 8) Save & display scan history (unchanged)
function saveScanResult(domain, score) {
  chrome.storage.local.get(['scanHistory'], (res) => {
    const history = res.scanHistory || [];
    const filtered = history.filter(e => e.domain !== domain);
    filtered.push({ domain, score, scannedAt: Date.now() });
    chrome.storage.local.set({ scanHistory: filtered });
  });
}

function loadScanHistory(order = 'desc') {
  chrome.storage.local.get(['scanHistory'], (res) => {
    const history = res.scanHistory || [];
    const container = document.getElementById('history');
    container.innerHTML = '';
    history.sort((a,b) => 
      order === 'asc' ? a.score - b.score : b.score - a.score
    );
    for (const entry of history) {
      const when = new Date(entry.scannedAt).toLocaleTimeString();
      const el = document.createElement('div');
      el.className = 'flex justify-between bg-gray-100 p-2 rounded';
      el.innerHTML = `<span>${entry.domain}</span><span>${entry.score}%</span><span>${when}</span>`;
      container.appendChild(el);
    }
  });
}

// setup sort buttons
document.getElementById('sort-low')?.addEventListener('click', () => loadScanHistory('asc'));
document.getElementById('sort-high')?.addEventListener('click', () => loadScanHistory('desc'));
document.getElementById('clear-history')?.addEventListener('click', () => {
  chrome.storage.local.set({ scanHistory: [] }, () => loadScanHistory());
});


// ─────────────────────────────────────────────────────────────────────────────
// 9) Main: when popup opens
chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
  if (!tabs.length) return;
  const tab = tabs[0];
  if (!tab.url) return;

  // Domain display
  const urlObj = new URL(tab.url);
  const domain = urlObj.hostname;
  document.getElementById("domain").textContent = domain;

  // Google Safe Browsing
  const safety = await safe_check(tab.url);
  document.getElementById("safety").textContent = safety;

  // ML Model Score
  const probability = await get_feature_data();
  document.getElementById("Ml_score").textContent = `${probability}%`;

  // IPQS Risk Score + Phishing flag
  const { unsafe, phishing, riskScore } = await getIPQSScore(tab.url);
  document.getElementById("score").textContent    = `${riskScore} / 100`;
  document.getElementById("phishing").textContent = phishing ? "Yes" : "No";

  // Final status & suggestions
  const statusElem = document.getElementById("status");
  // high risk if phishing/unsafe or very high riskScore or ML>65
  if (phishing || unsafe || riskScore >= 75 || probability > 65) {
    statusElem.textContent = "🚨 High risk site! Safer alternatives recommended.";
    const suggestions = await getChatGPTRecommendations(domain);
    const box = document.createElement("div");
    box.innerHTML = `
      <h4 class="text-xl font-semibold text-gray-700 mt-4 mb-2">
        Recommended Alternatives:
      </h4>
      <p class="text-gray-600 whitespace-pre-line">${suggestions}</p>
    `;
    document.body.appendChild(box);

  // medium risk if mid-range riskScore or ML 50–65
  } else if ((riskScore >= 50 && riskScore < 75) || (probability > 50 && probability <= 65)) {
    statusElem.textContent = "⚠️ Medium risk site. Consider alternatives.";
    const suggestions = await getChatGPTRecommendations(domain);
    const box = document.createElement("div");
    box.innerHTML = `
      <h4 class="text-xl font-semibold text-gray-700 mt-4 mb-2">
        Recommended Alternatives:
      </h4>
      <p class="text-gray-600 whitespace-pre-line">${suggestions}</p>
    `;
    document.body.appendChild(box);

  } else {
    // low risk
    statusElem.textContent = "✅ Low risk. Looks safe.";
  }

  // persist & refresh history
  saveScanResult(domain, riskScore);
  loadScanHistory();
});
