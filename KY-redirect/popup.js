const API_KEY = "AIzaSyBxE_YdQP1S0H-LkS0QEt83SXBwyOahdqA";  // Replace with your key

document.getElementById("redirectBtn").addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    chrome.tabs.update(tabs[0].id, { url: "https://example.com" });
  });
});

document.getElementById("checkPhishingBtn").addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const url = tabs[0].url;

    fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${AIzaSyBxE_YdQP1S0H-LkS0QEt83SXBwyOahdqA}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: {
          clientId: "yourcompanyname",
          clientVersion: "1.5.2"
        },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url: url }]
        }
      })
    })
    .then(response => response.json())
    .then(data => {
      const result = document.getElementById("result");
      if (data && data.matches && data.matches.length > 0) {
        result.textContent = "Unsafe: This site is flagged!";
      } else {
        result.textContent = "Safe: No threats detected.";
      }
    })
    .catch(error => {
      console.error("Error checking site:", error);
      document.getElementById("result").textContent = "Error checking site.";
    });
  });
});