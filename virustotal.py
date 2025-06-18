import requests
import os
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3/"

HEADERS = {
    "x-apikey": VT_API_KEY
}


def lookup_ip(ip):
    url = f"{BASE_URL}ip_addresses/{ip}"
    response = requests.get(url, headers=HEADERS)
    return response.json()


def lookup_domain(domain):
    url = f"{BASE_URL}domains/{domain}"
    response = requests.get(url, headers=HEADERS)
    return response.json()


def lookup_hash(file_hash):
    url = f"{BASE_URL}files/{file_hash}"
    response = requests.get(url, headers=HEADERS)
    return response.json()
