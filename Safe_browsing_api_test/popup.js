
// Using googles safebrowsing API v4
async function safe_check(url){

  const API_KEY = '----';

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
  const safety = await safe_check(url); 
  console.log(await safety);
  document.getElementById("status").textContent = `Safety Status: ${safety}`;

});