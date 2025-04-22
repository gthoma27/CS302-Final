async function getNVDScore(domain) {
  const keyword = domain.split('.').slice(0, -1).join('.');
  try {
    const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${keyword}&resultsPerPage=5`, {
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
    return scores.reduce((a, b) => a + b, 0) / scores.length;
  } catch (err) {
    console.error("NVD fetch error:", err);
    return 0;
  }
}

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
  } else {
    scoreElem.className = "safe";
    statusElem.textContent = "✅ No major known vulnerabilities.";
  }
});
