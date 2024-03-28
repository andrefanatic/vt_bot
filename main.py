import requests
import time

from config import VT_API_KEY

scan_gap = 15

url_list = [
    "https://www.virustotal.com/"
]

def scan_url(url):
    api_url = "https://www.virustotal.com/api/v3/urls"
    payload_scan = {"url": url}

    headers_scan = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }

    response_scan = requests.post(api_url, data=payload_scan, headers=headers_scan)
    scan_result = response_scan.json() # нужно узнать про метод .get у requests lib, для более быстрого парсинга json файла
    analyses_id = scan_result["data"]["id"]

    return analyses_id


def analys_url(analyses_id):
    api_url_analyses = f"https://www.virustotal.com/api/v3/analyses/{analyses_id}"

    headers_analyses = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
        }
    
    response_analyses = requests.get(api_url_analyses, headers=headers_analyses)
    analyses_result = response_analyses.json()
    malicious_analys = analyses_result["data"]["attributes"]["stats"]["malicious"]

    return malicious_analys


def analyze_domains(url_scan_list):    

    for url in url_scan_list:
        analys_id = scan_url(url)
        # print(f"Analys of {url} successfully submit")

        time.sleep(scan_gap)
        result = analys_url(analys_id)

        print(f"{url} - {result}")

analyze_domains(url_list)


