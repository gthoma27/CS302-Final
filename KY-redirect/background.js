// background.js

// ─────────────────────────────────────────────────────────────────────────────
// 1) Put your Malicious URL Scanner API key here.
//    For production you can load this from chrome.storage instead of hard-coding.
const IPQS_KEY = "l0Q0IKxBvvMsJoeuV03EkycJSuPkwgkg";

// ─────────────────────────────────────────────────────────────────────────────
// 2) Utility: pull the “base” domain (e.g. from sub.example.com → example.com)
function getBaseDomain(hostname) {
  const parts = hostname.split('.');
  return parts.length >= 2
    ? parts.slice(-2).join('.')
    : hostname;
}

// ─────────────────────────────────────────────────────────────────────────────
// 3) Call the IPQS Malicious URL Scanner endpoint for a given URL
//    Returns { unsafe: bool, phishing: bool, riskScore: 0–100 }
async function checkIPQS(url) {
  const endpoint =
    `https://www.ipqualityscore.com/api/json/url/${IPQS_KEY}/${encodeURIComponent(url)}`;
  try {
    const resp = await fetch(endpoint);
    const data = await resp.json();
    return {
      unsafe:   !!data.unsafe,
      phishing: !!data.phishing,
      riskScore: typeof data.risk_score === 'number'
        ? data.risk_score
        : 0
    };
  } catch (err) {
    console.error("IPQS lookup error:", err);
    return { unsafe: false, phishing: false, riskScore: 0 };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4) When any tab finishes loading, run the IPQS check and set a badge/alert
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && tab.active) {
    checkIPQS(tab.url).then(({ unsafe, phishing, riskScore }) => {
      const isHighRisk = phishing || unsafe || riskScore >= 75;

      if (isHighRisk) {
        chrome.scripting.executeScript({
          target: { tabId },
          func: () => alert("🚨 Warning: This site may be malicious!")
        });
        chrome.action.setBadgeText({ tabId, text: "!" });
        chrome.action.setBadgeBackgroundColor({ tabId, color: "#E53935" });
      } else {
        chrome.action.setBadgeText({ tabId, text: "" });
      }
    });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 5) On install, clear any badge so you start “clean”
chrome.runtime.onInstalled.addListener(() => {
  chrome.action.setBadgeText({ text: "" });
});
