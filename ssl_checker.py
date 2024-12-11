import argparse
import csv
import json
import os
import ssl
import socket
from datetime import datetime, timezone
import pytz
import pandas as pd
from tqdm import tqdm
import logging
from urllib.parse import urlparse

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Banner
BANNER = """
-------------------------------------------------------------------------------
             SSL Certificate Validity Checker

 Description: This tool checks the validity dates of SSL certificates for
              domains and categorizes their expiration status.

 Author: Afif Hidayatullah
 Organization: ITSEC Asia
-------------------------------------------------------------------------------
"""

# Function to resolve domain to an IP
def is_resolvable(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

# Function to clean domain input
def clean_domain(domain):
    try:
        parsed = urlparse(domain)
        if parsed.scheme:
            return parsed.hostname
        return domain
    except Exception as e:
        logging.error(f"Error cleaning domain {domain}: {str(e)}")
        return None

# Function to get SSL certificate dates and status
def get_ssl_dates(domain, timezone_code="UTC"):
    try:
        context = ssl.create_default_context()
        context.check_hostname = True

        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssl_sock:
                cert = ssl_sock.getpeercert()

                # Parse and determine the status
                return parse_certificate_dates(cert, timezone_code)

    except ssl.SSLError as ssl_error:
        # Handle specific CERTIFICATE_VERIFY_FAILED errors gracefully
        if "CERTIFICATE_VERIFY_FAILED" in str(ssl_error):
            if "certificate has expired" in str(ssl_error):
                logging.warning(f"SSL certificate verification failed for {domain}. Certificate has expired. Attempting manual extraction...")

                try:
                    # Retry with unverified context to extract the certificate
                    context = ssl._create_unverified_context()
                    context.check_hostname = False

                    with socket.create_connection((domain, 443), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=None) as ssl_sock:
                            cert = ssl_sock.getpeercert()

                            # Parse and determine the status (mark as expired with manual check note)
                            result = parse_certificate_dates(cert, timezone_code)
                            result["Status"] = "Expired [Manual check required due to verification failure]"
                            return result

                except Exception as retry_error:
                    logging.error(f"Failed to retrieve certificate for {domain} after retry: {retry_error}")
                    return {
                        "Validity Start": "Unknown",
                        "Validity End": "Unknown",
                        "Days Expired": "N/A",
                        "Status": "Expired [Manual check required due to verification failure]"
                    }
            else:
                # Other CERTIFICATE_VERIFY_FAILED errors
                logging.error(f"SSL verification error for {domain}: {ssl_error}")
                return {
                    "Validity Start": "Unknown",
                    "Validity End": "Unknown",
                    "Days Expired": "N/A",
                    "Status": f"SSL Error: {ssl_error}"
                }
    except Exception as e:
        logging.error(f"Error retrieving SSL certificate for {domain}: {e}")
        return {
            "Validity Start": "Unknown",
            "Validity End": "Unknown",
            "Days Expired": "N/A",
            "Status": "Error"
        }

# Function to parse certificate dates and determine status
def parse_certificate_dates(cert, timezone_code):
    # Extract notBefore and notAfter dates
    not_before = cert.get('notBefore', None)
    not_after = cert.get('notAfter', None)

    # Parse dates if available
    if not_before:
        not_before_date = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    else:
        not_before_date = None

    if not_after:
        not_after_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    else:
        not_after_date = None

    # Convert dates to specified timezone
    tz = pytz.utc
    if timezone_code.upper() != "UTC":
        try:
            tz = pytz.timezone(pytz.country_timezones[timezone_code.upper()][0])
        except KeyError:
            return {
                "Validity Start": "Error: Invalid timezone code",
                "Validity End": "Error: Invalid timezone code",
                "Days Expired": "Unknown",
                "Status": "Error"
            }

    not_before_str = (
        not_before_date.astimezone(tz).strftime("%A, %B %d, %Y at %I:%M:%S %p %Z")
        if not_before_date else "Unknown"
    )
    not_after_str = (
        not_after_date.astimezone(tz).strftime("%A, %B %d, %Y at %I:%M:%S %p %Z")
        if not_after_date else "Unknown"
    )

    # Determine status based on the expiry date and calculate days expired if applicable
    days_expired = None
    if not_after_date:
        now = datetime.now(timezone.utc).astimezone(tz)
        delta = not_after_date - now

        if delta.days > 90:
            status = "Valid"
        elif 30 < delta.days <= 90:
            status = "Almost Expired"
        elif 0 < delta.days <= 30:
            status = "Expiring Soon"
        else:
            status = "Expired"
            days_expired = abs(delta.days)  # Calculate how many days it has been expired
    else:
        status = "Unknown"

    return {
        "Validity Start": not_before_str,
        "Validity End": not_after_str,
        "Days Expired": days_expired if days_expired is not None else "N/A",
        "Status": status
    }

# Process domains
def process_domains(domains, timezone_code="UTC"):
    results = []
    for domain in tqdm(domains, desc="Processing domains", ncols=80):
        clean_dom = clean_domain(domain)
        if not clean_dom:
            results.append({
                "Domain": domain,
                "Validity Start": "Error: Invalid domain format",
                "Validity End": "Error: Invalid domain format",
                "Days Expired": "Unknown",
                "Status": "Unknown"
            })
            continue

        domain_result = {"Domain": domain}

        if not is_resolvable(clean_dom):
            domain_result.update({
                "Validity Start": "Error: Domain not resolvable",
                "Validity End": "Error: Domain not resolvable",
                "Days Expired": "Unknown",
                "Status": "Unknown"
            })
        else:
            cert_details = get_ssl_dates(clean_dom, timezone_code)
            domain_result.update(cert_details)

        results.append(domain_result)
    return results

# Save or display results
def save_results(results, output_format, output_path):
    if output_path:
        if output_format == "json":
            with open(output_path, "w") as json_file:
                json.dump(results, json_file, indent=4, default=str)
        elif output_format == "csv":
            keys = results[0].keys()
            with open(output_path, "w", newline="") as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=keys)
                writer.writeheader()
                writer.writerows(results)
        elif output_format == "xlsx":
            pd.DataFrame(results).to_excel(output_path, index=False)
        elif output_format == "txt":
            with open(output_path, "w") as txt_file:
                for result in results:
                    txt_file.write(f"{result}\n")
        print(f"Results saved to {output_path}")
    else:
        print(json.dumps(results, indent=4, default=str))

# Main function
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="SSL Certificate Validity Checker")
    parser.add_argument("--domain", type=str, help="Single domain to check")
    parser.add_argument("--file", type=str, help="File path for bulk domains (one domain per line)")
    parser.add_argument("--output", type=str, help="Output file path")
    parser.add_argument("--format", type=str, choices=["json", "csv", "xlsx", "txt"], default="json", help="Output file format (default: json)")
    parser.add_argument("--time", type=str, default="UTC", help="Timezone code (e.g., ID for Indonesia, KE for Kenya, default: UTC)")
    args = parser.parse_args()

    domains = []
    if args.domain:
        domains = [args.domain]
    elif args.file:
        if os.path.exists(args.file):
            with open(args.file, "r") as f:
                domains = [line.strip() for line in f.readlines()]
        else:
            print("Error: File not found.")
            return
    else:
        print("Error: Please specify a domain or file.")
        return

    results = process_domains(domains, timezone_code=args.time)
    save_results(results, args.format, args.output)

if __name__ == "__main__":
    main()
