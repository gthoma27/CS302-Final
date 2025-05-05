import React from 'react';
import { createRoot } from 'react-dom/client';
import NVDSecurityChecker from './NVDSecurityChecker.js';

const container = document.getElementById('root');
if (!container) throw new Error('Root element not found');
const root = createRoot(container);
root.render(<NVDSecurityChecker />);

// Collect ML features from the webpage
function collectFeatures() {
  const features = {};
  const url = window.location.href;
  const urlDomain = window.location.hostname;
  const onlyDomain = urlDomain.replace('www.', '');

  // Check for IP Address
  const ipPattern = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
  features["having_IP_Address"] = ipPattern.test(urlDomain) ? "1" : "-1";

  // URL Length
  if (url.length < 54) {
    features["URL_Length"] = "-1";
  } else if (url.length >= 54 && url.length <= 75) {
    features["URL_Length"] = "0";
  } else {
    features["URL_Length"] = "1";
  }

  // Prefix/Suffix
  features["Prefix_Suffix"] = urlDomain.includes('-') ? "1" : "-1";

  // Sub Domain
  const subDomainCount = (onlyDomain.match(/\./g) || []).length;
  if (subDomainCount === 1) {
    features["having_Sub_Domain"] = "-1";
  } else if (subDomainCount === 2) {
    features["having_Sub_Domain"] = "0";
  } else {
    features["having_Sub_Domain"] = "1";
  }

  // @ Symbol
  features["@ Symbol"] = url.includes('@') ? "1" : "-1";

  // Double Slash Redirecting
  features["Redirecting using //"] = url.lastIndexOf("//") > 7 ? "1" : "-1";

  // SFH (Server Form Handler)
  const forms = document.getElementsByTagName("form");
  let sfh = "-1";
  for (let i = 0; i < forms.length; i++) {
    const action = forms[i].getAttribute("action");
    if (!action || action === "") {
      sfh = "1";
      break;
    }
  }
  features["SFH"] = sfh;

  // URL of Anchor
  const aTags = document.getElementsByTagName("a");
  let phishCount = 0;
  let legitCount = 0;

  for (let i = 0; i < aTags.length; i++) {
    const href = aTags[i].getAttribute("href");
    if (!href) continue;

    if (ipPattern.test(href)) {
      legitCount++;
    } else if (href.charAt(0) === '#' || (href.charAt(0) === '/' && href.charAt(1) !== '/')) {
      legitCount++;
    } else {
      phishCount++;
    }
  }

  const totalCount = phishCount + legitCount;
  const outRequest = (phishCount / totalCount) * 100;
  features["Anchor"] = outRequest < 31 ? "-1" : "1";

  // HTTPS Token
  features["HTTPS_token"] = url.startsWith('https://') ? "-1" : "1";

  // Iframe
  features["Iframe"] = document.getElementsByTagName("iframe").length > 0 ? "1" : "-1";

  // Save features to storage
  chrome.storage.local.set({ features });
}

// Run feature collection when page loads
collectFeatures();