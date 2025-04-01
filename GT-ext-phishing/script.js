async function fetchData(){
    const url = 'https://exerra-phishing-check.p.rapidapi.com/all/domains';
    const options = {
        method: 'GET',
        headers: {
            'x-rapidapi-key': 'f42fd73749msh191acb525843d0fp17660ajsn0c7a8a078536',
            'x-rapidapi-host': 'exerra-phishing-check.p.rapidapi.com'
        }
    };
    
    try {
        const response = await fetch(url, options);
        const result = await response.text();
        console.log(result);
    } catch (error) {
        console.error(error);
    }

}

fetchData();

// NOTE, gave up on exterra, limited support and subscription likely needed
// https://rapidapi.com/Exerra/api/exerra-phishing-check/playground/apiendpoint_47974f95-7775-4e31-b6d1-aaa8bf304836\
