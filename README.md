 
API Logic
This application utilizes the VirusTotal API to analyze URLs extracted from CSV files containing Voluum lander data. The API logic is divided into the following steps:

Read File:
The application scans a specified directory for CSV files with the name pattern.
For each matching file, it reads the CSV data and extracts the "Lander URL" and "Clicks" columns.
URLs with at least one click are added to a list for further analysis.

Scan URL:
For each URL in the list, the application sends a POST request to the VirusTotal API endpoint (https://www.virustotal.com/api/v3/urls) with the URL as the payload.
The API responds with a JSON object containing an analysis ID for the submitted URL.

Analyze URL:
After submitting the URL for analysis, the application waits for 15 seconds to allow the analysis to complete.
The application then sends a GET request to the VirusTotal API endpoint (https://www.virustotal.com/api/v3/analyses/{analysis_id}), replacing {analysis_id} with the analysis ID obtained in the previous step.
The API responds with a JSON object containing the analysis result, including the number of engines that detected the URL as malicious.

Display Results:
The application prints the analyzed URL and the number of engines that detected it as malicious.
The application uses the requests library to interact with the VirusTotal API and the csv module to read and parse the CSV files.

API Key
To use the VirusTotal API, you need to obtain an API key from the VirusTotal website. The application reads the API key from the VT_API_KEY variable defined in the config.py file.

Dependencies
The following Python libraries are required to run this application:

requests
time
csv
pathlib