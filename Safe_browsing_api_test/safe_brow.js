API_Key = 'AIzaSyC8cknUlHcUJb0NjagV4mfJZ9-0mAxnQEY';

const elmUrl = document.getElementById("url");

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const url = tabs[0].url;
  console.log("url=", url);
  elmUrl.innerText = url;
});
