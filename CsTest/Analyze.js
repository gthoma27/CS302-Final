// Very simple extension which sends a HTTP request To analyze webpage

// HTTP request code
function download_check(link) {
    const Http = new XMLHttpRequest();
    const url= link;
    Http.open("GET", url);
    const contentDisposition = Http.getResponseHeader('Content-Disposition');
    
    Http.onreadystatechange = (e) => {
        console.log(Http.responseText)
}
    
}

// Grabs everything link or HTML object on the page
const links = document.getElementsByTagName('a')

for (link of links) {

    download_check(link);

}




