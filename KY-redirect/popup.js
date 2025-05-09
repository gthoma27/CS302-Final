const IPQS_KEY = "l0Q0IKxBvvMsJoeuV03EkycJSuPkwgkg";

const weights = { // These are the weights for the following features calculated in the jupiter notebook
  having_IP_Address: 0.32,
  URL_Length: 0.01,
  having_At_Symbol: 0.18,
  double_slash_redirecting: 0.03,
  Prefix_Suffix: 3.25,
  having_Sub_Domain: 0.69,
  URL_of_Anchor: 3.75,
  HTTPS_token: -0.36,
  SFH: 0.77,
  Links_in_tags: 0.92,
  Submitting_to_email: -0.14,
  External_Favicon: 0.4,
  Forms_Using_GET: 0.7,
  Uses_OnMouseOver: 1.1,
  Right_Click_Disabled: 0.6,
  Uses_IFrame: 0.9,
  Domain_Age_Young: 0.5,
  Empty_Title: 0.8,
  Excess_Scripts: 0.6,
  Email_In_Body: 1.0,
  Suspicious_Keywords: 1.3
};

<<<<<<< HEAD
// Fetch Google Safe Browsing result
async function safe_check(url) {
  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSy…`, // Replace with your key
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: "yourclient", clientVersion: "1.5.2" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
            platformTypes: ["WINDOWS"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }]
          }
        })
      }
    );
    const data = await res.json();
    return data.matches ? "Unsafe" : "Safe";
  } catch {
    return "Error";
=======
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
>>>>>>> dadc630d63949eaf70f87832757f054097f38401
  }

}

// Fetch IPQS phishing risk score
async function getIPQSScore(url) {
  try {
    const res = await fetch(
      `https://www.ipqualityscore.com/api/json/url/${IPQS_KEY}/${encodeURIComponent(url)}`
    );
    const data = await res.json();
    return {
      unsafe: !!data.unsafe,
      phishing: !!data.phishing,
      riskScore: Number.isFinite(data.risk_score) ? data.risk_score : 0
    };
  } catch {
    return { unsafe: false, phishing: false, riskScore: 0 };
  }
}

// Compute ML score from feature weights
function get_feature_data() {
  // Have to create a promise in order to handle asynchronous Calls
  // Resolve means the call is successful, reject means there was a error
  return new Promise(resolve => {
    chrome.storage.local.get("features", res => {
      // Grab the features and calculate the Probability with a sigmoid function
      const f = res.features || {};
<<<<<<< HEAD
      let dot = 0;
      for (const [k, v] of Object.entries(weights)) {
        dot += (f[k] || 0) * v;
      }
      const score = Math.round((1 / (1 + Math.exp(-dot))) * 100);
      resolve({ score, features: f });
=======

      let dot = 4.50696702; // Intercept, found in Jupiter notebook
      for (const [k,v] of Object.entries(weights)) {
        dot += (f[k] || 0) * v;
      }
      // Properly round the result and resolve the promise
      resolve(Math.round((1/(1+Math.exp(-dot))) * 100));
>>>>>>> dadc630d63949eaf70f87832757f054097f38401
    });
  });
}

// Show feature weights in popup
function showFeatureBreakdown(features) {
  const container = document.getElementById("feature-breakdown");
  container.innerHTML = "";

  const table = document.createElement("table");
  table.className = "w-full text-sm text-left text-gray-600";

  for (const [key, value] of Object.entries(features)) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td class="py-1 pr-2 font-medium">${key}</td>
      <td class="py-1">${value}</td>
    `;
    table.appendChild(row);
  }

  container.appendChild(table);
}

// Update the ML score progress bar
function updateMLProgressBar(score) {
  const bar = document.getElementById("ml-progress");
  bar.style.width = `${score}%`;
  bar.textContent = `${score}%`;

  if (score >= 75) {
    bar.className = "bg-red-500 text-white text-xs text-center p-1";
  } else if (score >= 40) {
    bar.className = "bg-yellow-500 text-white text-xs text-center p-1";
  } else {
    bar.className = "bg-green-500 text-white text-xs text-center p-1";
  }
}

// Save domain scan results
function saveScanResult(domain, score) {
  chrome.storage.local.get('scanHistory', res => {
    const hist = res.scanHistory || [];
    const filtered = hist.filter(e => e.domain !== domain);
    filtered.push({ domain, score, scannedAt: Date.now() });
    chrome.storage.local.set({ scanHistory: filtered });
  });
}

// Load scan history
function loadScanHistory(order = 'desc') {
  chrome.storage.local.get('scanHistory', res => {
    const history = res.scanHistory || [];
    const container = document.getElementById('history');
    container.innerHTML = '';
    history.sort((a, b) => order === 'asc' ? a.score - b.score : b.score - a.score);
    history.forEach(e => {
      const when = new Date(e.scannedAt).toLocaleTimeString();
      const div = document.createElement('div');
      div.className = 'flex justify-between bg-gray-100 dark:bg-gray-700 p-2 rounded';
      div.innerHTML = `<span>${e.domain}</span><span>${e.score}%</span><span>${when}</span>`;
      container.appendChild(div);
    });
  });
}

// ==============================
// MAIN SCAN LOGIC
// ==============================
chrome.tabs.query({ active: true, currentWindow: true }, async tabs => {
  if (!tabs.length || !tabs[0].url) return;
  const url = tabs[0].url;
  const domain = new URL(url).hostname;

  document.getElementById('domain').textContent = domain;
  document.getElementById('safety').textContent = await safe_check(url);

  const { score: mlScore, features } = await get_feature_data();
  document.getElementById('Ml_score').textContent = `${mlScore}%`;
  updateMLProgressBar(mlScore);
  showFeatureBreakdown(features);
  console.log("🔬 ML Feature Vector:", features);

  const { unsafe, phishing, riskScore } = await getIPQSScore(url);
  document.getElementById('score').textContent = `${riskScore} / 100`;
  document.getElementById('phishing').textContent = phishing ? "Yes" : "No";

  const isHighRisk = phishing || unsafe || riskScore >= 1 || mlScore > 65;
  const highThreshold = 75;

  const statusEl = document.getElementById('status');
  const badge = document.getElementById('status-badge');

  if (riskScore >= highThreshold) {
    statusEl.textContent = "🚨 High risk site!";
    badge.textContent = "High Risk";
    badge.className = "text-xs bg-red-200 text-red-800 px-3 py-1 rounded-full animate-pulse";
  } else if (isHighRisk) {
    statusEl.textContent = "⚠️ Some risk indicators detected.";
    badge.textContent = "Moderate Risk";
    badge.className = "text-xs bg-yellow-200 text-yellow-800 px-3 py-1 rounded-full";
  } else {
    statusEl.textContent = "✅ Low risk.";
    badge.textContent = "Low Risk";
    badge.className = "text-xs bg-green-200 text-green-800 px-3 py-1 rounded-full";
  }

  saveScanResult(domain, riskScore);
  loadScanHistory();
});

// ==============================
// TAB SWITCHING
// ==============================
document.getElementById('tab-scan').onclick = () => {
  document.getElementById('tab-scan-content').classList.remove('hidden');
  document.getElementById('tab-history-content').classList.add('hidden');
  document.getElementById('tab-scan').classList.add('text-blue-600', 'border-blue-500');
  document.getElementById('tab-history').classList.remove('text-blue-600', 'border-blue-500');
  document.getElementById('tab-history').classList.add('text-gray-500', 'border-transparent');
};

document.getElementById('tab-history').onclick = () => {
  document.getElementById('tab-history-content').classList.remove('hidden');
  document.getElementById('tab-scan-content').classList.add('hidden');
  document.getElementById('tab-history').classList.add('text-blue-600', 'border-blue-500');
  document.getElementById('tab-scan').classList.remove('text-blue-600', 'border-blue-500');
  document.getElementById('tab-scan').classList.add('text-gray-500', 'border-transparent');
};

// ==============================
// CLEAR HISTORY
// ==============================
document.getElementById('clear-history').onclick = () => {
  chrome.storage.local.set({ scanHistory: [] }, () => {
    loadScanHistory();
  });
};
