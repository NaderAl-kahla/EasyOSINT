import os
import re

from dotenv import load_dotenv  # For loading .env config file
from datetime import datetime  # For time/date formatting
from dateutil.relativedelta import relativedelta  # For relative time (e.g. '3 months ago')

import virustotal  # Custom module to handle VirusTotal API calls
import alienvault  # Custom module to handle AlienVault OTX API calls

# Loading Environment Variables
load_dotenv()

# Loading API Keys from .env
VT_API_KEY = os.getenv("VT_API_KEY")
IBM_API_KEY = os.getenv("IBM_API_KEY")
IBM_API_ID = os.getenv("IBM_API_ID")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")


# Function to check if user inputs a valid IP, Domain, and hash
def detect_input_type(user_input):
    ip_regex = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    domain_regex = r"^(?!http)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    hash_regex = r"^[A-Fa-f0-9]{32,64}$"  # MD5/SHA1/SHA256

    if re.match(ip_regex, user_input):
        return "ip"
    elif re.match(domain_regex, user_input):
        return "domain"
    elif re.match(hash_regex, user_input):
        return "hash"
    else:
        return "unknown"


def main():
    user_input = input("🔍 Enter an IP, domain, or hash: ").strip()
    input_type = detect_input_type(user_input)

    if input_type == "unknown":
        print("❌ Invalid input format. Please try again.")
        return

    print(f"\n🛰️ OSINT on '{user_input}':\n")

    # Used to call the correct VT Function
    print("🔎 VirusTotal:", end=" ")

    '''
    try:

        print("🔎 AlienVault OTX:", end=" ")

        if input_type == "ip":
            otx_data = alienvault.lookup_ip(user_input)
            pulses = otx_data.get("pulse_info", {}).get("count", 0)
            tags = otx_data.get("pulse_info", {}).get("tags", [])
            print(f'"Pulses: {pulses}" | Tags: {", ".join(tags) if tags else "None"}')

        elif input_type == "domain":
            otx_data = alienvault.lookup_domain(user_input)
            pulses = otx_data.get("pulse_info", {}).get("count", 0)
            tags = otx_data.get("pulse_info", {}).get("tags", [])
            print(f'"Pulses: {pulses} | Tags: {", ".join(tags) if tags else "None"}')

        elif input_type == "hash":
            otx_data = alienvault.lookup_hash(user_input)
            pulses = otx_data.get("pulse_info", {}).get("count", 0)
            tags = otx_data.get("pulse_info", {}).get("tags", [])
            print(f'"Pulses: {pulses}" | Tags: {", ".join(tags) if tags else "None"}')
    except Exception as e:
        print(f"⚠️Error: {e}") '''

    try:
        # IP Address Logic
        if input_type == "ip":
            vt_data = virustotal.lookup_ip(user_input)
            stats = vt_data['data']['attributes']['last_analysis_stats']
            asn = vt_data['data']['attributes'].get('asn', 'N/A')
            as_owner = vt_data['data']['attributes'].get('as_owner', 'N/A')
            total = sum(stats.values())
            detected = stats.get('malicious', 0) + stats.get('suspicious', 0)

            print(f'"Detection Ratio: {detected}/{total}" | ASN: {asn} | AS Owner: {as_owner}')

            # Domain Logic
        elif input_type == "domain":
            vt_data = virustotal.lookup_domain(user_input)
            attr = vt_data['data']['attributes']

            # Get Detection Ratio
            stats = attr['last_analysis_stats']
            detected = stats.get('malicious', 0) + stats.get('suspicious', 0)
            total = sum(stats.values())

            # Extract A Record from DNS info
            dns_record = attr.get('last_dns_records', [])
            a_records = [r['value'] for r in dns_record if r['type'] == 'A']
            a_record_str = ', '.join(a_records) if a_records else 'N/A'

            # Extract VT's category tags (if any)
            categories = list(attr.get('categories', {}).values())
            categories_str = ', '.join(categories) if categories else 'None'

            # Extract and format creation date in relative time
            raw_creation_date = attr.get('creation_date')
            if raw_creation_date:
                try:
                    creation_dt = datetime.utcfromtimestamp(raw_creation_date)
                    now = datetime.utcnow()
                    diff = relativedelta(now, creation_dt)

                    if diff.years > 0:
                        creation_date = f"{diff.years} year{'s' if diff.years > 1 else ''} ago"
                    elif diff.months > 0:
                        creation_date = f"{diff.months} month{'s' if diff.months > 1 else ''} ago"
                    elif diff.days > 0:
                        creation_date = f"{diff.days} day{'s' if diff.days > 1 else ''}ago"
                    else:
                        creation_date = "today"
                except:
                    creation_date = "unknown"
            else:
                creation_date = "N/A"

            print(f'"Detection Ratio: {detected}/{total}" | A Record(s): {a_record_str} | Categories: {categories_str} | Creation Date: {creation_date}')

            # Hash Logic

        elif input_type == "hash":
            vt_data = virustotal.lookup_hash(user_input)
            attr = vt_data['data']['attributes']

            # Get Detection Ratio
            stats = attr['last_analysis_stats']
            detected = stats.get('malicious', 0) + stats.get('suspicious', 0)
            total = sum(stats.values())

            # Extract Popular Threat Label if suggested
            threat_label = attr.get("popular_threat_classification", {}).get("suggested_threat_label", "None")

            # File Name if Available
            file_name = attr.get('meaningful_name', 'N/A')

            # Signature info if signed
            signature_info = attr.get("signature_info", {})
            signers = signature_info.get("signers") or signature_info.get("signer")

            primary_signer = signers.split(';', 1)[0].strip() if signers else None
            signed = f"Signed by {primary_signer}" if primary_signer else "Unsigned"

            print(f'"Detection Ratio: {detected}/{total}" | Threat Label: {threat_label} | File Name: {file_name} | {signed}')

    except Exception as e:
        print(f"⚠️Error: {e}")


if __name__ == "__main__":
    main()
