import click
import requests
import time
import os

# Retrieve the VirusTotal API Key from environment variables
api_key = os.getenv('VT_API_KEY')

def get_url_report(url):
    # Prepare parameters for the request
    params = {'apikey': api_key, 'resource': url}
    
    # Make a GET request to the VirusTotal URL Report API
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
    json_response = response.json()

    # Check if the API response is successful
    if json_response['response_code'] == 1:
        # Extract key information from the response
        positives = json_response['positives']
        total = json_response['total']
        scan_date = json_response['scan_date']
        scan_id = json_response['scan_id']
        permalink = json_response['permalink']
        
        # Return the extracted information
        return positives, total, scan_date, scan_id, permalink
    else:
        # If the API response is not successful, print a warning message
        print(f"Unexpected response for URL {url}: {json_response}")
        return None

def analyze_urls(urls):
    # Iterate through each URL in the list
    for url in urls:
        # Get the report for the URL
        result = get_url_report(url)
        
        # Check if the report was successful
        if result:
            # Unpack the result
            positives, total, scan_date, scan_id, permalink = result
            
            # Print the result
            print(f'URL: {url}\nDetected Threats: {positives}\nTotal Scans: {total}\nScan Date: {scan_date}\nScan ID: {scan_id}\nPermalink: {permalink}\n')
        else:
            # If the report was not successful, print a warning message
            print(f'No information available for URL: {url}\n')
        
        # Pause for 15 seconds to avoid hitting the VirusTotal API rate limit
        time.sleep(15)

@click.command()
@click.argument('file_path', type=click.Path(exists=True))
def main(file_path):
    # Open the file containing the URLs
    with open(file_path, 'r') as file:
        # Read the URLs from the file and split them into a list
        urls = file.read().split(',')
    
    # Analyze the URLs
    analyze_urls(urls)

# If the script is run directly (instead of being imported), run the main function
if __name__ == "__main__":
    main()
