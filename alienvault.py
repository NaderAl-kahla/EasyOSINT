from OTXv2 import OTXv2
import os

'''
# Load API Key from .env
load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")
otx = OTXv2(OTX_API_KEY) '''


def get_otx_client(api_key):
    return OTXv2(api_key)


def lookup_ip(ip):
    return otx.get_indicator_details_by_section("IPv4", ip, "general")


def lookup_domain(domain):
    return otx.get_indicator_details_by_section("domain", domain, "general")


def lookup_hash(hash_val):
    return otx.get_indicator_details_by_section("file", hash_val, "general")
