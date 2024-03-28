import requests 
import time
import csv
import logging

from pathlib import Path
from config import VT_API_KEY


directory_path = Path("C:/Users/Admin/Downloads/")


def read_file():
    for file_path in directory_path.glob("*Voluum landers*"):
        logging.info(f"processing file: {file_path}")

        with file_path.open(mode="r", encoding="utf-8") as csv_file:
            csv_reader = csv.reader(csv_file)

            url_list = []

            header = next(csv_reader)
            lander_url_index = header.index("Lander URL")
            clicks_index = header.index("Clicks")

            for row in csv_reader:
                lander_url = row[lander_url_index]
                clicks = int(row[clicks_index])
                if clicks >= 1:
                    url_list.append(lander_url)
                    
            print(f"URLs to check {len(url_list)}, approximate minutes {15 * len(url_list) / 60}")

    return url_list


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


def analyze_domains():

    url_scan_list = read_file()    

    for url in url_scan_list:
        analys_id = scan_url(url)

        # print(f"Analys of {url} successfully submit")
        time.sleep(15)
        result = analys_url(analys_id)
        print(f"{url} - {result}")

analyze_domains()