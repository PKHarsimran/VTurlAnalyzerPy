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
        # Return additional information
        positives = json_response['positives']
        total = json_response['total']
        scan_date = json_response['scan_date']
        scan_id = json_response['scan_id']
        permalink = json_response['permalink']
        return positives, total, scan_date, scan_id, permalink
    else:
        return None

def analyze_urls(urls):
    for url in urls:
        result = get_url_report(url)
        if result:
            positives, total, scan_date, scan_id, permalink = result
            print(f'URL: {url}\nDetected Threats: {positives}\nTotal Scans: {total}\nScan Date: {scan_date}\nScan ID: {scan_id}\nPermalink: {permalink}\n')
        else:
            print(f'No information available for URL: {url}\n')

        # Sleep for 15 seconds to avoid exceeding the VirusTotal API rate limit
        time.sleep(15)

# Read URLs from file
with open('url.txt', 'r') as file:
    urls = file.read().split(',')

analyze_urls(urls)
