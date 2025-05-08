// features.js
// CITATION: Adapted from https://github.com/picopalette/phishing-detection-plugin

var features = {
    "having_IP_Address": 0,
    "URL_Length": 0,
    "having_At_Symbol": 0,
    "double_slash_redirecting": 0,
    "Prefix_Suffix": 0,
    "having_Sub_Domain": 0,
    "URL_of_Anchor": 0,
    "HTTPS_token": 0,
    "SFH": 0,
    "Links_in_tags": 0,
    "Submitting_to_email": 0
  };
  
  var url = window.location.href;
  var domain = window.location.hostname;
  var bare = domain.replace('www.', '');
  
  // 1) IP address in domain?
  var ipPat  = /\d+\.\d+\.\d+\.\d+/;
  var decPat = /(25[0-5]|2[0-4]\d|1\d\d|\d{1,2})(\.|$){4}/;
  var hexPat = /0x[0-9A-F]+(\.|$){4}/;
  features.having_IP_Address = (ipPat.test(domain) || decPat.test(domain) || hexPat.test(domain)) ? 1 : -1;
  
  // 2) URL length
  features.URL_Length = url.length < 54 ? -1
                     : url.length <= 75      ?  0
                                             :  1;
  
  // 3) Prefix-suffix (hyphen) in domain
  features.Prefix_Suffix = /-/.test(domain) ? 1 : -1;
  
  // 4) Number of subdomains
  var dotCount = (bare.match(/\./g) || []).length;
  features.having_Sub_Domain = dotCount < 2 ? -1
                              : dotCount === 2 ? 0
                                               : 1;
  
  // 5) “@” symbol in URL
  features.having_At_Symbol = /@/.test(url) ? 1 : -1;
  
  // 6) Redirect (“//” after protocol)
  features.double_slash_redirecting = url.indexOf('//', 8) !== -1 ? 1 : -1;
  
  // 7) Server Form Handler (SFH)
  var forms = document.getElementsByTagName('form');
  var sfhRes = -1;
  for (var i = 0; i < forms.length; i++) {
    var a = forms[i].getAttribute('action');
    if (!a || a === '') {
      sfhRes = 1;
      break;
    }
    if (!(/^\/|^https?:\/\//.test(a))) {
      sfhRes = 0;
    }
  }
  features.SFH = sfhRes;
  
  // 8) URL of anchor tags
  var anchors = document.getElementsByTagName('a');
  var phish = 0, legit = 0;
  for (var i = 0; i < anchors.length; i++) {
    var h = anchors[i].getAttribute('href');
    if (!h) continue;
    if (/^https?:\/\//.test(h) ||
        (h.charAt(0) === '/' && h.charAt(1) !== '/') ||
        h.charAt(0) === '#') {
      legit++;
    } else {
      phish++;
    }
  }
  var total = phish + legit;
  var rate = total ? (phish / total) * 100 : 0;
  features.URL_of_Anchor = rate < 31 ? -1
                           : rate <= 67 ? 0
                                        : 1;
  
  // 9) HTTPS token in URL
  features.HTTPS_token = /^https:\/\//.test(url) ? -1 : 1;
  
  // 10) Links in <script> and <link> tags
  var scripts = document.getElementsByTagName('script');
  var links   = document.getElementsByTagName('link');
  phish = 0; legit = 0;
  [...scripts, ...links].forEach(el => {
    var src = el.src || el.getAttribute('href');
    if (!src) return;
    if (/^https?:\/\//.test(src) || (src.charAt(0) === '/' && src.charAt(1) !== '/')) {
      legit++;
    } else {
      phish++;
    }
  });
  total = phish + legit;
  rate  = total ? (phish / total) * 100 : 0;
  features.Links_in_tags = rate < 17   ? -1
                         : rate <= 81   ?  0
                                        :  1;
  
  // 11) Submitting to email (mailto:)
  var mailRes = -1;
  for (var i = 0; i < forms.length; i++) {
    var act = forms[i].getAttribute('action') || '';
    if (act.startsWith('mailto:')) {
      mailRes = 1;
      break;
    }
  }
  features.Submitting_to_email = mailRes;
  
  // Finally, persist the feature vector for popup.js to read:
  chrome.storage.local.set({ features });
  