async function fetchData() {
    const url = 'https://concerts-artists-events-tracker.p.rapidapi.com/location?name=Knoxville&minDate=2025-04-04&maxDate=2025-04-07&page=1';
const options = {
	method: 'GET',
	headers: {
		'x-rapidapi-key': 'f42fd73749msh191acb525843d0fp17660ajsn0c7a8a078536',
		'x-rapidapi-host': 'concerts-artists-events-tracker.p.rapidapi.com'
	}
};

try {
	const response = await fetch(url, options);
	const data = await response.json();
	console.log(data);

    const events = data.data;
    if (Array.isArray(events)) {
        document.getElementById("concerts").innerHTML = events
        .map(item => `<li>${item.name}</li>`).join('');
    } else {
        document.getElementById("concerts").innerHTML = 'No events found';
    }

} catch (error) {
	console.error(error);
    document.getElementById("concerts").innerHTML = 'Error loading events';
}


}

fetchData();
// https://www.youtube.com/watch?v=B8Ihv3xsWYs