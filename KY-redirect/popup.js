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

function saveScanResult(domain, score) {
  chrome.storage.local.get('scanHistory', res => {
    const hist = res.scanHistory || [];
    const filtered = hist.filter(e => e.domain !== domain);
    filtered.push({ domain, score, scannedAt: Date.now() });
    chrome.storage.local.set({ scanHistory: filtered });
  });
}

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
  });
}

// MAIN
chrome.tabs.query({ active: true, currentWindow: true }, async tabs => {
  if (!tabs.length || !tabs[0].url) return;
  const url    = tabs[0].url;
  const domain = new URL(url).hostname;

  document.getElementById('domain').textContent = domain;
  document.getElementById('safety').textContent = await safe_check(url);
  document.getElementById('Ml_score').textContent = `${await get_feature_data()}%`;

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
