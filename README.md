This app uses [VirusTotal API](https://docs.virustotal.com/reference/overview) to scant URLs from CSV files.   

How it works:  

1. **Read File:** It reads CSV files from a directory, extracts "Lander URL" and "Clicks" columns, and adds URLs with unique domains clicks to a list.   
Test version of the filter to avoid scanning ULRs that have no traffic.

2. **Scan URL:** It sends URLs to VirusTotal API and gets back an analysis ID. After 15 seconds(due to VT API quota, 4 lookups for 1 minute), it checks the analysis status and then gets the analysis result including malicious detections.  

3. **Display Results:** It prints two lists, "Flagged URLs" with the number of engines detecting it as malicious and a list with "Clear" URLs.  

**Prerequisites**  
- API Key: You need a VirusTotal API key stored in a config file.
- Dependencies: It uses Python libraries: requests, time, csv, pathlib, urllib.

Plan to realize such logic on telegram bot framework and bot api
