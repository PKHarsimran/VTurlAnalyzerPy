import requests
import time
import os

# Your VirusTotal API Key
api_key = os.getenv('VT_API_KEY')

def get_url_report(url):
    # Prepare parameters for the API request
    params = {'apikey': api_key, 'resource': url}

    # Make a GET request to the VirusTotal API
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)

    # Parse the response as JSON
    json_response = response.json()

    # Check if the request was successful
    if json_response['response_code'] == 1:
        # Parse and return useful information from the response
        positives = json_response['positives']
        total = json_response['total']
        scan_date = json_response['scan_date']
        scan_id = json_response['scan_id']
        permalink = json_response['permalink']
        return positives, total, scan_date, scan_id, permalink
    else:
        # In case of an unexpected response, print debug info and return None
        print(f"Unexpected response for URL {url}: {json_response}")
        return None

def analyze_urls(urls):
    for url in urls:
        # Get the report for the URL
        result = get_url_report(url)

        # If we got a valid result, print the information
        if result:
            positives, total, scan_date, scan_id, permalink = result
            print(f'URL: {url}\nDetected Threats: {positives}\nTotal Scans: {total}\nScan Date: {scan_date}\nScan ID: {scan_id}\nPermalink: {permalink}\n')
        else:
            # If the result was None, we've already printed debug info in get_url_report
            print(f'No information available for URL: {url}\n')

        # Sleep for 15 seconds to avoid exceeding the VirusTotal API rate limit
        time.sleep(15)

# Read URLs from file
with open('urls.txt', 'r') as file:
    urls = file.read().split(',')

# Analyze each URL in the list
analyze_urls(urls)
