import requests 
import time
import csv

from pathlib import Path
from urllib.parse import urlparse 
from config import VT_API_KEY

timer_gap = 2
directory_path = Path("C:/Users/Admin/Downloads/")

def read_file() -> tuple[list[str], int]:
    
    url_list =[]
    unique_urls = []

    for file_path in directory_path.glob("*Voluum landers*"):

        with file_path.open(mode="r", encoding="utf-8") as file:
            csv_reader = csv.reader(file)

            next(csv_reader)

            for row in csv_reader:
                url, clicks = row
                clicks = int(clicks)

                if clicks >= 1:
                    domain = urlparse(url).netloc

                    if domain not in unique_urls:
                        unique_urls.append(domain)
                        url_list.append(url)

            exec_time = len(url_list) * timer_gap
            minutes, seconds = divmod(exec_time, 60)

        print(f"URLs to check {len(url_list)}, approximate time {minutes:02d}:{seconds:02d}")

    return url_list, exec_time

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

    countdown_timer()

    url_scan_list = read_file()[0]
    flagged_urls = {}
    clear_urls = {}

    for url in url_scan_list:
        
        analys_id = scan_url(url) 
        time.sleep(timer_gap)
        result = int(analys_url(analys_id))

        if result <= 3:
            clear_urls.update({url: result})
        else:
            flagged_urls.update({url: result})

    print(f"{len(flagged_urls)} flagged URLs:")
    for url, result in flagged_urls.items():
            print(f"{url} - {result}")

    print(f"{len(clear_urls)} Clear URLs:")
    for url, result in clear_urls.items():
            print(f"{url} - {result}")


def countdown_timer():
    execution_time = read_file()[1]

    start_time = time.time()
    end_time = start_time + execution_time

    while time.time() < end_time:
        remaining_time = int(end_time - time.time())
        minutes, seconds = divmod(remaining_time, 60)
        print(f"Time remaing: {minutes:02d}:{seconds:02d}", end="\r", flush=True)
        time.sleep(1)
    
    print("Scanning complete")

analyze_domains()


