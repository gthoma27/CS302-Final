// popup.js

const IPQS_KEY = "l0Q0IKxBvvMsJoeuV03EkycJSuPkwgkg";

const weights = { // These are the weights for the following features calculated in the jupiter notebook
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

async function safe_check(url){

  const API_KEY = 'AIzaSyC8cknUlHcUJb0NjagV4mfJZ9-0mAxnQEY';

  // Test site that should work: 'http://malware.testing.google.test/testing/malware/'

  // Make a http post request to google url site
  try {
    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      // POST requests are usually inputted in JSON formatt
      body: JSON.stringify({
        // Proper Payload format documented on googles website : https://developers.google.com/safe-browsing/v4/lookup-api
        "client": {
          "clientId":      "CS_TEST",
          "clientVersion": "1.5.2"
        },
        "threatInfo": {
          "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          "platformTypes":    ["ANY_PLATFORM"],
          "threatEntryTypes": ["URL"],
          "threatEntries": [
            {"url": url}   // Url to be inputted
      ]
    }


      })
    });

    // Grab data from response
    const data = await response.json();

    // Check if the data.matches object is established
    if (data && data.matches) {
      return "Site is not Safe!"
    } else { // If not, the site was not found or was not listed as unsafe
      return "Site is not documented";
    }
  } catch (error) { // Possible HTTP error
    console.error('HTTP Post Error', error);
    return "Error Using API";
  }

}

async function getIPQSScore(url) {
  try {
    const res = await fetch(
      `https://www.ipqualityscore.com/api/json/url/${IPQS_KEY}/${encodeURIComponent(url)}`
    );
    const data = await res.json();
    return {
      unsafe:   !!data.unsafe,
      phishing: !!data.phishing,
      riskScore: Number.isFinite(data.risk_score) ? data.risk_score : 0
    };
  } catch {
    return { unsafe: false, phishing: false, riskScore: 0 };
  }
}

<<<<<<< HEAD
// ─────────────────────────────────────────────────────────────────────────────
// 6) Load feature vector from content script and compute ML probability
=======
>>>>>>> main
function get_feature_data() {
  // Have to create a promise in order to handle asynchronous Calls
  // Resolve means the call is successful, reject means there was a error
  return new Promise(resolve => {
    chrome.storage.local.get("features", res => {
      // Grab the features and calculate the Probability with a sigmoid function
      const f = res.features || {};

      let dot = 4.50696702; // Intercept, found in Jupiter notebook
      for (const [k,v] of Object.entries(weights)) {
        dot += (f[k] || 0) * v;
      }
      // Properly round the result and resolve the promise
      resolve(Math.round((1/(1+Math.exp(-dot))) * 100));
    });
  });
}

<<<<<<< HEAD

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
function saveScanResult(domain, ipqsScore, googleScore, mlScore) {
  chrome.storage.local.get(['scanHistory'], (res) => {
    const history = res.scanHistory || [];
    const filtered = history.filter(e => e.domain !== domain);
    filtered.push({ domain, ipqsScore, googleScore, mlScore, scannedAt: Date.now() });
=======
function saveScanResult(domain, score) {
  chrome.storage.local.get('scanHistory', res => {
    const hist = res.scanHistory || [];
    const filtered = hist.filter(e => e.domain !== domain);
    filtered.push({ domain, score, scannedAt: Date.now() });
>>>>>>> main
    chrome.storage.local.set({ scanHistory: filtered });
  });
}

<<<<<<< HEAD
function loadScanHistory() {
  chrome.storage.local.get(['scanHistory'], (res) => {
    const history = res.scanHistory || [];
    const container = document.getElementById('history');
    container.innerHTML = '';

    // Get sort method from localStorage or default to 'ipqs'
    const sortBy = localStorage.getItem('leaderboardSort') || 'ipqs';

    // Sort based on selected method
    history.sort((a, b) => {
      if (sortBy === 'ipqs') return (b.ipqsScore ?? 0) - (a.ipqsScore ?? 0);
      if (sortBy === 'google') return (b.googleScore ?? 0) - (a.googleScore ?? 0);
      if (sortBy === 'ml') return (b.mlScore ?? 0) - (a.mlScore ?? 0);
      return 0;
    });

    for (const entry of history) {
      const when = new Date(entry.scannedAt).toLocaleTimeString();
      container.innerHTML += `
        <div class="flex justify-between bg-gray-100 p-2 rounded">
          <span>${entry.domain}</span>
          <span>
            IPQS: ${entry.ipqsScore ?? '-'} |
            Google: ${entry.googleScore ?? '-'} |
            ML: ${entry.mlScore ?? '-'}
          </span>
          <span>${when}</span>
        </div>
      `;
    }
=======
function loadScanHistory(order = 'desc') {
  chrome.storage.local.get('scanHistory', res => {
    const history = res.scanHistory || [];
    const container = document.getElementById('history');
    container.innerHTML = '';
    history.sort((a,b) => order==='asc' ? a.score - b.score : b.score - a.score);
    history.forEach(e => {
      const when = new Date(e.scannedAt).toLocaleTimeString();
      const div = document.createElement('div');
      div.className = 'flex justify-between bg-gray-100 p-2 rounded';
      div.innerHTML = `<span>${e.domain}</span><span>${e.score}%</span><span>${when}</span>`;
      container.appendChild(div);
    });
>>>>>>> main
  });
}

// MAIN
chrome.tabs.query({ active: true, currentWindow: true }, async tabs => {
  if (!tabs.length || !tabs[0].url) return;
  const url    = tabs[0].url;
  const domain = new URL(url).hostname;

<<<<<<< HEAD
// Add leaderboard sort dropdown event handler
function setupLeaderboardSortDropdown() {
  const leaderboardSort = document.getElementById('leaderboardSort');
  if (leaderboardSort) {
    leaderboardSort.value = localStorage.getItem('leaderboardSort') || 'ipqs';
    leaderboardSort.addEventListener('change', (e) => {
      localStorage.setItem('leaderboardSort', e.target.value);
      loadScanHistory();
    });
  }
}
=======
  document.getElementById('domain').textContent = domain;
  document.getElementById('safety').textContent = await safe_check(url);
  document.getElementById('Ml_score').textContent = `${await get_feature_data()}%`;
>>>>>>> main

  const { unsafe, phishing, riskScore } = await getIPQSScore(url);
  document.getElementById('score').textContent    = `${riskScore} / 100`;
  document.getElementById('phishing').textContent = phishing ? "Yes" : "No";

  const statusEl = document.getElementById('status');
  const highThreshold = 75;
  const mlScore = parseInt(document.getElementById('Ml_score').textContent, 10);
  const isHighRisk = phishing || unsafe || riskScore >= 1 || mlScore > 65;

  if (riskScore >= highThreshold) {
    statusEl.textContent = "🚨 High risk site!";
  } else if (isHighRisk) {
    statusEl.textContent = "⚠️ Some risk indicators detected.";
  } else {
    statusEl.textContent = "✅ Low risk.";
  }

<<<<<<< HEAD
  // persist & refresh history
  saveScanResult(domain, riskScore, safety === 'Unsafe' ? 100 : 0, probability);
  loadScanHistory();
});

// ─────────────────────────────────────────────────────────────────────────────
// 10) Toggle feature visibility
function toggleFeature(feature) {
  const featureMap = {
    google: "google-container",
    ipqs: "ipqs-container",
    ml: "ml-container"
  };

  const elementId = featureMap[feature];
  const checkbox = document.getElementById(`toggle${feature.charAt(0).toUpperCase() + feature.slice(1)}`);
  const element = document.getElementById(elementId);

  if (checkbox) {
    checkbox.checked = localStorage.getItem(`show_${feature}`) !== "false";
    element.style.display = localStorage.getItem(`show_${feature}`) !== "false" ? "block" : "none";
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unified feature toggle and tab switching logic

document.addEventListener("DOMContentLoaded", () => {
  // Map feature names to checkbox and container IDs
  const features = [
    { key: "google", checkbox: "toggleGoogle", container: "google-container" },
    { key: "ipqs",   checkbox: "toggleIPQS",   container: "ipqs-container"   },
    { key: "ml",     checkbox: "toggleML",     container: "ml-container"     }
  ];

  // Initialize checkboxes and containers
  features.forEach(({ key, checkbox, container }) => {
    const cb = document.getElementById(checkbox);
    const cont = document.getElementById(container);
    if (!cb || !cont) return;

    // Set initial state from localStorage (default: true)
    const isVisible = localStorage.getItem(`show_${key}`) !== "false";
    cb.checked = isVisible;
    cont.style.display = isVisible ? "block" : "none";

    // Add event listener
    cb.addEventListener("change", () => {
      cont.style.display = cb.checked ? "block" : "none";
      localStorage.setItem(`show_${key}`, cb.checked ? "true" : "false");
    });
  });

  // (Optional) Dark mode toggle
  document.getElementById("darkToggle")?.addEventListener("change", (event) => {
    toggleDarkMode(event.target);
  });

  // Tab switching logic
  document.getElementById("tab-detector").addEventListener("click", () => {
    document.getElementById("content-detector").classList.remove("hidden");
    document.getElementById("content-settings").classList.add("hidden");
    document.getElementById("tab-detector").classList.add("text-blue-600", "border-b-2", "border-blue-600");
    document.getElementById("tab-settings").classList.remove("text-blue-600", "border-b-2", "border-blue-600");
  });

  document.getElementById("tab-settings").addEventListener("click", () => {
    document.getElementById("content-settings").classList.remove("hidden");
    document.getElementById("content-detector").classList.add("hidden");
    document.getElementById("tab-settings").classList.add("text-blue-600", "border-b-2", "border-blue-600");
    document.getElementById("tab-detector").classList.remove("text-blue-600", "border-b-2", "border-blue-600");
  });

  // Setup leaderboard sort dropdown
  setupLeaderboardSortDropdown();
});
=======
  saveScanResult(domain, riskScore);
  loadScanHistory();
});

// Tab-switching
document.getElementById('tab-scan').onclick = () => {
  document.getElementById('tab-scan').classList.add('text-blue-600','border-blue-500');
  document.getElementById('tab-history').classList.remove('text-blue-600','border-blue-500');
  document.getElementById('tab-scan-content').classList.remove('hidden');
  document.getElementById('tab-history-content').classList.add('hidden');
};
document.getElementById('tab-history').onclick = () => {
  document.getElementById('tab-history').classList.add('text-blue-600','border-blue-500');
  document.getElementById('tab-scan').classList.remove('text-blue-600','border-blue-500');
  document.getElementById('tab-history-content').classList.remove('hidden');
  document.getElementById('tab-scan-content').classList.add('hidden');
};
>>>>>>> main
