import subprocess
import sys
import os

def install_and_import(package):
    """
    Function to import a package. If the package is not installed,
    it installs the package using pip.
    """
    try:
        # Try importing the package
        __import__(package)
    except ImportError:
        # If package is not installed, install it using pip
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# List of required packages
required_packages = ['requests', 'pandas', 'click', 'tqdm']

# Install required packages
for package in required_packages:
    install_and_import(package)

# Import necessary libraries
import click
import requests
import time
import pandas as pd
import logging
from tqdm import tqdm

# Set up logging configuration
logging.basicConfig(filename='vt_analysis.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s')

# Retrieve the VirusTotal API Key from environment variables
API_KEY = os.getenv('VT_API_KEY')

def get_url_report(url):
    """Retrieve the URL report from VirusTotal."""
    # Set the parameters for the API request
    params = {'apikey': API_KEY, 'resource': url}
    logging.debug(f"Requesting report for URL: {url}")
    
    # Make a GET request to the VirusTotal URL report API
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
    
    # Check for HTTP errors
    if response.status_code != 200:
        logging.error(f"HTTP error {response.status_code} for URL: {url}")
        return None

    # Parse the JSON response from the API
    json_response = response.json()
    logging.debug(f"Response for URL {url}: {json_response}")

    # Check if the response code indicates success
    if json_response.get('response_code') == 1:
        # Extract the categories if available
        categories = json_response.get('categories', {})
        if categories:
            category = ', '.join([f"{vendor}: {cat}" for vendor, cat in categories.items()])
        else:
            category = 'Unknown'
        
        # Return the extracted information as a dictionary
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
    results = []  # List to store the results
    total_urls = len(urls)  # Total number of URLs to analyze
    
    for i, url in enumerate(tqdm(urls, desc="Analyzing URLs", unit="url")):
        start_time = time.time()  # Record the start time of the request
        result = get_url_report(url)  # Get the report for the URL
        end_time = time.time()  # Record the end time of the request
        
        elapsed_time = end_time - start_time  # Calculate the elapsed time
        remaining_urls = total_urls - (i + 1)  # Calculate the remaining URLs
        estimated_time_left = remaining_urls * 15  # Estimate the time left based on the rate limit (15 seconds per URL)

        if result:
            results.append(result)  # Append the result to the list if available
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
        # Ensure at least 15 seconds between requests to comply with API rate limits
        time.sleep(max(0, 15 - elapsed_time))
    
    return results

@click.command()
@click.argument('file_path', type=click.Path(exists=True))
def main(file_path):
    """Main function to read CSV, analyze URLs, and save the results."""
    logging.info(f"Reading CSV file from path: {file_path}")
    
    try:
        # Read the CSV file
        df = pd.read_csv(file_path)
    except Exception as e:
        logging.error(f"Error reading CSV file: {e}")
        return
    
    # Extract URLs from the 'Domain' column and drop any missing values
    urls = df['Domain'].dropna().tolist()
    logging.debug(f"Extracted URLs: {urls}")

    # Analyze the URLs and get the results
    results = analyze_urls(urls)
    results_df = pd.DataFrame(results)  # Create a DataFrame from the results
    
    # Save the results to a CSV file
    output_file = 'vt_results.csv'
    results_df.to_csv(output_file, index=False)
    logging.info(f"Results saved to {output_file}")

if __name__ == "__main__":
    main()
