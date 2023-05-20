import requests
import time
import os

# Your VirusTotal API Key
api_key = os.getenv('VT_API_KEY')

def get_url_report(url):
    params = {'apikey': api_key, 'resource': url}
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
    json_response = response.json()

    # Check if the request was successful
    if json_response['response_code'] == 1:
        # Return the positive detections and total scans
        return json_response['positives'], json_response['total']
    else:
        return None

def analyze_urls(urls):
    for url in urls:
        result = get_url_report(url)
        if result:
            positives, total = result
            print(f'URL: {url}\nDetected Threats: {positives}\nTotal Scans: {total}\n')
        else:
            print(f'No information available for URL: {url}\n')

        # Sleep for 15 seconds to avoid exceeding the VirusTotal API rate limit
        time.sleep(15)

# List of URLs to analyze
urls = [
    'http://google.com',
    'http://bing.com',
    'http://facebook.com',
]

analyze_urls(urls)