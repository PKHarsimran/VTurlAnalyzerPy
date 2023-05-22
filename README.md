# VTurlAnalyzerPy
This script uses the VirusTotal API to analyze a list of URLs for potential security threats. It provides detailed information about each URL, including the number of positive detections from various antivirus engines, total scans, the date of the last scan, scan ID, and a permalink to the scan report.

## Libraries Used and Why
* **requests:** This library is used for making HTTP requests to the VirusTotal API. It is simple and concise, making it a popular choice for interacting with REST APIs in Python.
* **os:** The os module in Python provides functions for interacting with the operating system. It's used in this script to read the VirusTotal API key from an environment variable.
* **time:** This module provides various time-related functions. In this script, it's used to pause execution between API requests to avoid exceeding the VirusTotal API rate limit.
* **click:** Click is a Python package for creating beautiful command-line interfaces. In this script, it's used to accept a file path as a command-line argument.

## Setup

1. Clone this repository to your local machine.
2. Install the required Python libraries. You can do this by running pip install -r requirements.txt (make sure you have Python and pip installed).
3. Get your VirusTotal API key. If you don't have one, you can register for a free account and get it.
4. Set your VirusTotal API key as an environment variable named VT_API_KEY.

## Usage

* Prepare a .txt file with a list of URLs you want to analyze, separated by commas (e.g., google.com,wscript.shell,techcommunity.microsoft.com,learn.microsoft.com,msrc.microsoft.com,a9tcsbn.run).
* Run the script with the following command: **python VTUrlAnalyzerPy.py <path_to_your_file>** , where **<path_to_your_file>** is the path to the .txt file containing the URLs.

The script will analyze each URL and print the results to the console. After analyzing each URL, the script will pause for 15 seconds to avoid exceeding the VirusTotal API rate limit.

## Output

For each URL, the script will print:

- URL
- Number of detected threats
- Total number of scans
- Date of the last scan
- Scan ID
- Permalink to the scan report

If the script is unable to retrieve information for a particular URL, it will print an error message and continue with the next URL.
