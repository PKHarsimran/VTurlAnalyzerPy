import subprocess
import sys
import os

def install_and_import(package):
    try:
        __import__(package)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# List of required packages
required_packages = ['requests', 'pandas', 'click', 'tqdm']

# Install required packages
for package in required_packages:
    install_and_import(package)

import click
import requests
import time
import pandas as pd
import logging
from tqdm import tqdm

# Set up logging
logging.basicConfig(filename='vt_analysis.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s')

# Retrieve the VirusTotal API Key from environment variables
API_KEY = os.getenv('VT_API_KEY')

def get_url_report(url):
    """Retrieve the URL report from VirusTotal."""
    params = {'apikey': API_KEY, 'resource': url}
    logging.debug(f"Requesting report for URL: {url}")
    
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
    
    if response.status_code != 200:
        logging.error(f"HTTP error {response.status_code} for URL: {url}")
        return None

    json_response = response.json()
    logging.debug(f"Response for URL {url}: {json_response}")

    if json_response.get('response_code') == 1:
        categories = json_response.get('categories', {})
        if categories:
            category = ', '.join([f"{vendor}: {cat}" for vendor, cat in categories.items()])
        else:
            category = 'Unknown'
        
        return {
            'URL': url,
            'Detected Threats': json_response.get('positives', 0),
            'Total Scans': json_response.get('total', 0),
            'Scan Date': json_response.get('scan_date', 'Unknown'),
            'Scan ID': json_response.get('scan_id', 'Unknown'),
            'Permalink': json_response.get('permalink', 'Unknown'),
            'Category': category
        }
    
    logging.warning(f"Unexpected response for URL {url}: {json_response}")
    return None

def analyze_urls(urls):
    """Analyze a list of URLs by retrieving their reports from VirusTotal."""
    results = []
    total_urls = len(urls)
    
    for i, url in enumerate(tqdm(urls, desc="Analyzing URLs", unit="url")):
        start_time = time.time()
        result = get_url_report(url)
        end_time = time.time()
        
        elapsed_time = end_time - start_time
        remaining_urls = total_urls - (i + 1)
        estimated_time_left = remaining_urls * 15  # 15 seconds per URL due to rate limiting

        if result:
            results.append(result)
            logging.info(f"Successfully retrieved report for URL: {url}")
        else:
            results.append({
                'URL': url,
                'Detected Threats': None,
                'Total Scans': None,
                'Scan Date': None,
                'Scan ID': None,
                'Permalink': None,
                'Category': None
            })
            logging.warning(f"No information available for URL: {url}")
        
        logging.info(f"Processed {i + 1}/{total_urls} URLs. Estimated time left: {estimated_time_left / 60:.2f} minutes")
        time.sleep(max(0, 15 - elapsed_time))  # Ensure at least 15 seconds between requests
    
    return results

@click.command()
@click.argument('file_path', type=click.Path(exists=True))
def main(file_path):
    """Main function to read CSV, analyze URLs, and save the results."""
    logging.info(f"Reading CSV file from path: {file_path}")
    
    try:
        df = pd.read_csv(file_path)
    except Exception as e:
        logging.error(f"Error reading CSV file: {e}")
        return
    
    urls = df['Domain'].dropna().tolist()
    logging.debug(f"Extracted URLs: {urls}")

    results = analyze_urls(urls)
    results_df = pd.DataFrame(results)
    
    output_file = 'vt_results.csv'
    results_df.to_csv(output_file, index=False)
    logging.info(f"Results saved to {output_file}")

if __name__ == "__main__":
    main()
