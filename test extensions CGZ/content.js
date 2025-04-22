function applyDarkMode(enabled) {
    if (enabled) {
        document.documentElement.style.filter = "invert(1) hue-rotate(180deg)";
        document.body.style.backgroundColor = "#121212";
    } else {
        document.documentElement.style.filter = "";
        document.body.style.backgroundColor = "";
    }
}

chrome.storage.sync.get("enabled", (data) => {
    applyDarkMode(data.enabled);
});

// Optional: listen for toggle changes in real time
chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "sync" && changes.enabled) {
        applyDarkMode(changes.enabled.newValue);
    }
});
