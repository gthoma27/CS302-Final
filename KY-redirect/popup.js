// popup.js

const IPQS_KEY = "rdOjzzP6q6Am7NMkMxDZ2dlVmdIdfTgE";
const OPENAI_API_KEY = "sk-…";  // truncated for brevity

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

async function safe_check(url) {
  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSy…`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: "yourclient", clientVersion: "1.5.2" },
          threatInfo: {
            threatTypes: ["MALWARE","SOCIAL_ENGINEERING"],
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
  return new Promise(resolve => {
    chrome.storage.local.get("features", res => {
      const f = res.features || {};
      let dot = 0;
      for (const [k,v] of Object.entries(weights)) {
        dot += (f[k] || 0) * v;
      }
      resolve(Math.round((1/(1+Math.exp(-dot)))*100));
    });
  });
}

async function getChatGPTRecommendations(domain) {
  const prompt = `If the website "${domain}" is high risk, recommend reputable alternatives.`;
  try {
    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${OPENAI_API_KEY}`
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: prompt }]
      })
    });
    const j = await r.json();
    return j.choices?.[0]?.message?.content.trim() || "No suggestions.";
  } catch {
    return "Unable to fetch suggestions.";
  }
}

function saveScanResult(domain, score) {
  chrome.storage.local.get('scanHistory', res => {
    const hist = res.scanHistory || [];
    const filtered = hist.filter(e => e.domain !== domain);
    filtered.push({ domain, score, scannedAt: Date.now() });
    chrome.storage.local.set({ scanHistory: filtered });
  });
}

function loadScanHistory(order='desc') {
  chrome.storage.local.get('scanHistory', res => {
    const history = res.scanHistory || [];
    const container = document.getElementById('history');
    container.innerHTML = '';
    history.sort((a,b) => order==='asc' ? a.score-b.score : b.score-a.score);
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
  const url = tabs[0].url;
  const domain = new URL(url).hostname;
  document.getElementById('domain').textContent = domain;

  document.getElementById('safety').textContent = await safe_check(url);
  document.getElementById('Ml_score').textContent = `${await get_feature_data()}%`;

  const { unsafe, phishing, riskScore } = await getIPQSScore(url);
  document.getElementById('score').textContent = `${riskScore} / 100`;
  document.getElementById('phishing').textContent = phishing ? "Yes" : "No";

  const status = document.getElementById('status');
  const recs = document.getElementById('recommendations');
  if (phishing || unsafe || riskScore>=75 || parseInt(document.getElementById('Ml_score').textContent) > 65) {
    status.textContent = "🚨 High risk! Consider alternatives.";
    recs.textContent = await getChatGPTRecommendations(domain);
  } else {
    status.textContent = "✅ Low risk.";
    recs.textContent = "";
  }

  saveScanResult(domain, riskScore);
  loadScanHistory();
});

// Tab switching
document.getElementById('tab-scan').addEventListener('click', () => {
  document.getElementById('tab-scan').classList.add('text-blue-600','border-blue-500');
  document.getElementById('tab-history').classList.remove('text-blue-600','border-blue-500');
  document.getElementById('tab-scan-content').classList.remove('hidden');
  document.getElementById('tab-history-content').classList.add('hidden');
});
document.getElementById('tab-history').addEventListener('click', () => {
  document.getElementById('tab-history').classList.add('text-blue-600','border-blue-500');
  document.getElementById('tab-scan').classList.remove('text-blue-600','border-blue-500');
  document.getElementById('tab-history-content').classList.remove('hidden');
  document.getElementById('tab-scan-content').classList.add('hidden');
});
