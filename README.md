# VirusTotal URL Analysis Script

This script reads a list of URLs from a CSV file, analyzes them using the VirusTotal API, and generates a report with detailed threat information. The results are saved to a new CSV file, and logs are maintained for debugging purposes.

## Features

- Reads URLs from a CSV file
- Analyzes URLs using the VirusTotal API
- Retrieves detected threats, total scans, scan date, scan ID, permalink, and categories
- Saves analysis results to a new CSV file
- Displays a progress bar with estimated time remaining
- Logs detailed information for debugging
- Automatically installs required packages

## Requirements

- Python 3.6 or higher

## Installation

1. Clone this repository or download the script file.
2. Create a `requirements.txt` file with the following content:
    ```
    requests
    pandas
    click
    tqdm
    ```

## Setup

1. Obtain a VirusTotal API key from [VirusTotal](https://www.virustotal.com/).
2. Set the `VT_API_KEY` environment variable:
    ```bash
    export VT_API_KEY='your_virustotal_api_key'
    ```

## Usage

1. Prepare a CSV file with a column named `Domain` containing the URLs to be analyzed.
2. Run the script with the path to your CSV file as an argument:
    ```bash
    python VTUAnalyzer.py path_to_your_csv_file.csv
    ```

## Example

The script will:
- Read the URLs from `domains.csv`
- Analyze each URL using the VirusTotal API
- Display a progress bar with the estimated time remaining
- Save the results to `vt_results.csv`
- Log detailed information to `vt_analysis.log`

## Output

The output CSV file (`vt_results.csv`) will contain columns:
- `URL`
- `Detected Threats`
- `Total Scans`
- `Scan Date`
- `Scan ID`
- `Permalink`
- `Category`

## Logging

Logs detailed information about the script execution to `vt_analysis.log`, including:
- Requests made to the VirusTotal API
- Responses received
- Progress information
- Errors and warnings

## Troubleshooting

- Ensure your VirusTotal API key is correctly set in the `VT_API_KEY` environment variable
- Verify the CSV file path is correct and the file exists
- Check `vt_analysis.log` for detailed error messages and debugging information

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Acknowledgments

- [VirusTotal](https://www.virustotal.com/) for the API
- Authors and contributors of the Python libraries used
