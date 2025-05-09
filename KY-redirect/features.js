// CITATION: A majority of this code was taken and augmented from
// https://github.com/picopalette/phishing-detection-plugin/blob/master/frontend/js/features.js

// Set up features object
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

// Having Ip-Address

var url = window.location.href; // Grab the current URL

var urlDomain = window.location.hostname; // Grab the domain name

var onlyDomain = urlDomain.replace('www.',''); // Remove the www. from the domain

// Ip adress patterns to check for
var patt = /(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]?[0-9])(\.|$){4}/;
var patt2 = /(0x([0-9][0-9]|[A-F][A-F]|[A-F][0-9]|[0-9][A-F]))(\.|$){4}/;
var ip = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;

// Test if the domain is an ip-adress or matches patterns
if(ip.test(urlDomain)||patt.test(urlDomain)||patt2.test(urlDomain)){ 
    features["having_IP_Address"]=1;
}else{
    features["having_IP_Address"]=-1;
}

// URL length

if(url.length<54){ // If the url length is smaller
    features["URL_Length"]=-1;
}else if(url.length>=54&&url.length<=75){ // If it is of usual size
    features["URL_Length"]=0;
}else{ // If it is very long
    features["URL_Length"]=1;
}

// Prefix_Suffix:            

patt=/-/;

// Test the domain to see if there is a hyphen
if(patt.test(urlDomain)){ 
    features["Prefix_Suffix"]=1;
}else{
    features["Prefix_Suffix"]=-1;
}

// having_Sub_Domain:          

// Checks the number of sub_domains by counting the dots
if((onlyDomain.match(RegExp('\\.','g'))||[]).length==1){ 
    features["having_Sub_Domain"]=-1;
}else if((onlyDomain.match(RegExp('\\.','g'))||[]).length==2){ 
    result["No. of Sub Domains"]=0;    
}else{
    features["having_Sub_Domain"]=1;
}

//  having_At_Symbol:             

// Test and see if there is a @ in the url
patt=/@/;
if(patt.test(url)){ 
    features["@ Symbol"]=1;
}else{
    features["@ Symbol"]=-1;
}

// double_slash_redirecting: 

// Checks if there is a double slash // in Url ahead of the https// start
if(url.lastIndexOf("//")>7){
    features["Redirecting using //"]=1;
}else{
    features["Redirecting using //"]=-1;
}

// SFH - Server form Handler

// grabs the form from the page
var forms = document.getElementsByTagName("form");
var res = -1; // start at -1 by default

for(var i = 0; i < forms.length; i++) {
    var action = forms[i].getAttribute("action");
    if(!action || action == "") { // If the form has no action
        res = 1; 
        break;
    } else if(!(action.charAt(0)=="/" || patt.test(action))) {
        res = "0";
    }
}
features["SFH"] = res;

// URL_OF_ANCHOR

// Grab all achor tags
var aTags = document.getElementsByTagName("a");

phishCount=0;
legitCount=0;
var allhrefs="";

for(var i = 0; i < aTags.length; i++){ // Loop through the anchor tabs
    
    // grab the link destination from the anchor, and make sure it isnt undefined
    var hrefs = aTags[i].getAttribute("href");
    if(!hrefs) continue;

    allhrefs+=hrefs+"       ";
    if(patt.test(hrefs)){
        legitCount++;
    }else if(hrefs.charAt(0)=='#'||(hrefs.charAt(0)=='/'&&hrefs.charAt(1)!='/')){ 
        legitCount++;
    }else{ // Phishing sites often have tags to external sites
        phishCount++;
    }
}

// Find the proportion of phish anchors to legit ones
totalCount=phishCount+legitCount;
outRequest=(phishCount/totalCount)*100;

// Depending on the proportion, It should be flagged accordingly as a feature
if(outRequest<31){
    features["Anchor"]=-1;
}else if(outRequest>=31&&outRequest<=67){
    result["Anchor"]=0;
}else{
    features["Anchor"]=1;
}

// HTTPS token

patt=/https:\/\//;

// Checks if the https is declared unusually 
if(patt.test(url)){
    features["HTTPS_token"]=-1;
}else{
    features["HTTPS_token"]=1;
}


// Links in tags

// Grab the script and link tags
var sTags = document.getElementsByTagName("script");
var lTags = document.getElementsByTagName("link");

phishCount=0;
legitCount=0;

allhrefs="sTags  ";

// For script tags
for(var i = 0; i < sTags.length; i++){
    var sTag = sTags[i].getAttribute("src"); // More undefined checks
    if(sTag!=null){ 
        allhrefs+=sTag+"      ";
        if(patt.test(sTag)){ // Checks if the tag is a regular https:// url
            legitCount++;
        }else if(sTag.charAt(0)=='/'&&sTag.charAt(1)!='/'){ // Checks for single slash tags, which are usually indicate it is on the same domain
            legitCount++;                                   // Double slashes can be risky
        }else{ 
            phishCount++;
        }
    }
}

// For link tags, Does the same as the s tags
allhrefs+="      lTags   ";
for(var i = 0; i < lTags.length; i++){
    var lTag = lTags[i].getAttribute("href");
    if(!lTag) continue;
    allhrefs+=lTag+"       ";
    if(patt.test(lTag)){
        legitCount++;
    }else if(lTag.charAt(0)=='/'&&lTag.charAt(1)!='/'){
        legitCount++;
    }else{
        phishCount++;
    }
}

// Checks the proportions of legit and phish tags, similar to how anchor tags does it
totalCount=phishCount+legitCount;
outRequest=(phishCount/totalCount)*100;

if(outRequest<17){
    features["Links_in_tags"]=-1;
}else if(outRequest>=17&&outRequest<=81){
    features["Links_in_tags"]=0;
}else{
    features["Links_in_tags"]=1;
}

// Submitting to email

// Grab all forms on page
var forms = document.getElementsByTagName("form");
var res = -1;

for(var i = 0; i < forms.length; i++) {
    var action = forms[i].getAttribute("action");
    if(!action) continue;
    if(action.startsWith("mailto")) { // If the forms sends data through email
        res = 1;
        break;
    }
}
features["Submitting_to_email"] = res;


// Add to local storage so it can be accessed in the popup.js file
chrome.storage.local.set({features});