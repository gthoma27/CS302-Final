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
    "Iframe": 0
  };

// Having Ip-Address

var url = window.location.href;

var urlDomain = window.location.hostname;

var onlyDomain = urlDomain.replace('www.','');

var patt = /(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]?[0-9])(\.|$){4}/;
var patt2 = /(0x([0-9][0-9]|[A-F][A-F]|[A-F][0-9]|[0-9][A-F]))(\.|$){4}/;
var ip = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;


if(ip.test(urlDomain)||patt.test(urlDomain)||patt2.test(urlDomain)){ 
    features["having_IP_Address"]=1;
}else{
    features["having_IP_Address"]=-1;
}

// URL length

if(url.length<54){
    features["URL_Length"]=-1;
}else if(url.length>=54&&url.length<=75){
    features["URL_Length"]=0;
}else{
    features["URL_Length"]=1;
}

// Prefix_Suffix:                coef = 3.3223, Ratio = 27.72

patt=/-/;

if(patt.test(urlDomain)){ 
    features["Prefix_Suffix"]=1;
}else{
    features["Prefix_Suffix"]=-1;
}

// having_Sub_Domain:            coef = 0.6760, Ratio = 1.97

if((onlyDomain.match(RegExp('\\.','g'))||[]).length==1){ 
    features["having_Sub_Domain"]=-1;
}else if((onlyDomain.match(RegExp('\\.','g'))||[]).length==2){ 
    result["No. of Sub Domains"]=0;    
}else{
    features["having_Sub_Domain"]=1;
}

//  having_At_Symbol:             coef = 0.2251, Ratio = 1.25

patt=/@/;
if(patt.test(url)){ 
    features["@ Symbol"]=1;
}else{
    features["@ Symbol"]=-1;
}

// double_slash_redirecting:     coef = 0.1932, Ratio = 1.21

if(url.lastIndexOf("//")>7){
    features["Redirecting using //"]=1;
}else{
    features["Redirecting using //"]=-1;
}

// SFH

var forms = document.getElementsByTagName("form");
var res = -1;

for(var i = 0; i < forms.length; i++) {
    var action = forms[i].getAttribute("action");
    if(!action || action == "") {
        res = 1;
        break;
    } 
}
features["SFH"] = res;

// URL_OF_ANCHOR

var aTags = document.getElementsByTagName("a");

phishCount=0;
legitCount=0;
var allhrefs="";

for(var i = 0; i < aTags.length; i++){
    var hrefs = aTags[i].getAttribute("href");
    if(!hrefs) continue;
    allhrefs+=hrefs+"       ";
    if(patt.test(hrefs)){
        legitCount++;
    }else if(hrefs.charAt(0)=='#'||(hrefs.charAt(0)=='/'&&hrefs.charAt(1)!='/')){
        legitCount++;
    }else{
        phishCount++;
    }
}
totalCount=phishCount+legitCount;
outRequest=(phishCount/totalCount)*100;

if(outRequest<31){
    features["Anchor"]=-1;
}else{
    features["Anchor"]=1;
}

// HTTPS token

patt=/https:\/\//;
if(patt.test(url)){
    features["HTTPS_token"]=-1;
}else{
    features["HTTPS_token"]=1;
}

// Iframe

var iframes = document.getElementsByTagName("iframe");

if(iframes.length == 0) {
    features["Iframe"] = -1;
} else {
    features["Iframe"] = 1;
}

// Add to local storage, may be a better way to do this 
chrome.storage.local.set({features});