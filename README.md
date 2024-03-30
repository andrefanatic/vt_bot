
This app uses VirusTotal API to check URLs from CSV files. 

How it works:

**Read File:** It reads CSV files from a directory, extracts "Lander URL" and "Clicks" columns, and adds URLs with unique domains clicks to a list. 
Test version of the filter to avoid scanning ULRs that have no traffic.

**Scan URL:** It sends URLs to VirusTotal API and gets back an analysis ID. After 15 seconds(due to VT API quota, 4 lookups for 1 minute), it checks the analysis status and then gets the analysis result including malicious detections.

**Display Results:** It prints two lists, "Flagged URLs" with the number of engines detecting it as malicious and a list with "Clear" URLs.

API Key: You need a VirusTotal API key stored in a config file.
Dependencies: It uses Python libraries: requests, time, csv, pathlib, urllib.

Plan to realize such logic based on aiogram framework and telegram bot api library
