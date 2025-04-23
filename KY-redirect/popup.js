let sorted = [];


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

        return v3 ?? v2 ?? 0; // Prefer v3.1 > fallback to v2 > else 0
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

function roundToTenths(number) {
  return Math.round(number * 10) / 10;
}

function saveScanResult(domain, score) {
  chrome.storage.local.get(['scanHistory'], (res) => {
    const history = res.scanHistory || [];

    const updatedHistory = history.filter(entry => entry.domain !== domain);
    updatedHistory.push({
      domain,
      score,
      scannedAt: Date.now()
    });

    chrome.storage.local.set({ scanHistory: updatedHistory }, () => {
      if (chrome.runtime.lastError) {
        console.error("Error saving scan history:", chrome.runtime.lastError);
      } else {
        console.log(`Scan saved for ${domain}`);
      }
    });
  });
}

function loadScanHistory() {
  chrome.storage.local.get(['scanHistory'], (res) => {
    console.log("Retrieved scan history:", res.scanHistory);
    const history = res.scanHistory || [];
    const container = document.getElementById('history');
    container.innerHTML = ''; // Clear old entries

    // Sort by score in descending order
    history
      .sort((a, b) => b.score - a.score) // Sort by score (highest to lowest)
      .forEach(entry => {
        const div = document.createElement('div');
        div.textContent = `${entry.domain} – Score: ${roundToTenths(entry.score)}`;
        container.appendChild(div);
      });
  });
}

document.addEventListener('DOMContentLoaded', () => {
  loadScanHistory();

  document.getElementById('clearBtn').addEventListener('click', () => {
    clearScanHistory();
    loadScanHistory();
  });
});

chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
  const tab = tabs[0];
  const url = new URL(tab.url);
  const domain = url.hostname;

  document.getElementById("domain").textContent = domain;

  const cvssScore = await getNVDScore(domain);
  const scaled = Math.min(cvssScore * 2, 20);
  const scoreElem = document.getElementById("score");

  scoreElem.textContent = `${cvssScore.toFixed(1)} / 10`;

  const statusElem = document.getElementById("status");
  if (scaled >= 15) {
    scoreElem.className = "danger";
    statusElem.textContent = "⚠️ Warning: High vulnerability risk!";
  } else if (cvssScore == -1) {
    scoreElem.className = "danger";
    statusElem.textContent = "Website Unknown - Use caution!";
  } else {
    scoreElem.className = "safe";
    statusElem.textContent = "✅ No major known vulnerabilities.";
  }

  // Save the scan result automatically
  saveScanResult(domain, cvssScore);

  // Reload the scan history to include the new scan
  loadScanHistory();
});