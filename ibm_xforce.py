import requests
import os
from requests.auth import HTTPBasicAuth

# Loading credentials from .env

API_KEY = os.getenv("IBM_API_KEY")
API_ID = os.getenv("IBM_API_ID")

BASE_URL = "https://api.xforce.ibmcloud.com"

def lookup_ip(ip):
    url = f"{BASE_URL}/ipr/{ip}"
    response = requests.get(url, auth=HTTPBasicAuth(API_ID, API_KEY))
    response.raise_for_status()
    return response.json()

def lookup_domain(domain):
    url = f"{BASE_URL}/url/{domain}"
    response = requests.get(url, auth=HTTPBasicAuth(API_ID, API_KEY))
    response.raise_for_status()
    return response.json()

def lookup_hash(hash_val):
    url = f"{BASE_URL}/malware/{hash_val}"
    response = requests.get(url, auth=HTTPBasicAuth(API_ID, API_KEY))
    response.raise_for_status()
    return response.json()
