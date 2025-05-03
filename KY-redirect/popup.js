let sorted = [];
let probability;
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
const threshold = 0.6; // Calculated in jupiter notebook, precision should be 0.9 and accuracy at around 0.85

function Prob_calculation(features){
  var z = intercept;
  for (const feature in weights){
    z = (weights[feature] + Math.random()/10) * features[feature];
  }

  console.log("z = ", z);

  var probability = 1 / (1 + Math.pow(Math.E, (z * -1)))

  console.log("prob = ", probability);

  return probability; 
}

// Using googles safebrowsing API v4
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

    console.log("API response received ", url);
    const data = await response.json();
    console.log("response: ", data);

    // Check if the data.matches object is established
    if (data && data.matches) {
      return "Site is not Safe!"
    } else { // If not, the site was not found
      return "Site is not documented";
    }
  } catch (error) { // Possible HTTP error
    console.error('HTTP Post Error', error);
    return "Error Using API";
  }

}

// Helper to extract base domain (same as background.js)
function getBaseDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length >= 2) {
    return parts.slice(-2).join('.');
  }
  return hostname;
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
      div.textContent = `${entry.domain} – Score: ${entry.score <= 0 ? 'No vulnerabilities found' : entry.score}`;
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

  //const safety = await safe_check(url); // Disabled google api just so excess calls are not made
  //document.getElementById("safety").textContent = safety;

  
  chrome.storage.local.get("features", (result) => {
    if (result.features){
      var features = result.features

      var probability = Prob_calculation(features);    
      probability = probability.toFixed(2)
      document.getElementById("score").textContent = probability;
    }
  });  
  

  saveScanResult(domain, probability);
  loadScanHistory();
});
