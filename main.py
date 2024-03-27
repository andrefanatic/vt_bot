import requests
import json

from config import VT_API_KEY

scan_url = "https://patrynig.xyz/9Ck/9.html"
api_url = "https://www.virustotal.com/api/v3/urls"

payload_scan = {"url": scan_url}

# def scan_url(payload_scan):

headers_scan = {
    "accept": "application/json",
    "x-apikey": VT_API_KEY,
    "content-type": "application/x-www-form-urlencoded"
}

response_scan = requests.post(api_url, data=payload_scan, headers=headers_scan)
scan_result = response_scan.json()
analyses_id = scan_result["data"]["id"]

api_url_analyses = f"https://www.virustotal.com/api/v3/analyses/{analyses_id}"

headers_analyses = {
    "accept": "application/json",
    "x-apikey": VT_API_KEY
    }
response_analyses = requests.get(api_url_analyses, headers=headers_analyses)
analyses_result = response_analyses.json()
malicious_analys = analyses_result["data"]["attributes"]["stats"]["malicious"]

print(f"URL:{scan_url} marked as malicious {malicious_analys} times")

