import argparse
import csv
import json
import os
import ssl
import socket
import subprocess
import warnings
from datetime import datetime, timezone
import pytz
import pandas as pd
from tqdm import tqdm
import logging
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.utils import CryptographyDeprecationWarning

# Suppress cryptography deprecation warnings
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

# Setup logging
logging.basicConfig(filename="ssl_checker.log", level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s")

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
def get_ssl_dates(domain, port, timezone_code="UTC"):
    try:
        context = ssl.create_default_context()
        context.check_hostname = True

        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssl_sock:
                cert = ssl_sock.getpeercert()

                # Parse and determine the status
                return parse_certificate_dates(cert, timezone_code)

    except Exception as e:
        logging.warning(f"SSL module failed for {domain}:{port}: {e}")
        # Fallback to OpenSSL
        return get_certificate_with_openssl(domain, port)

# Fallback to OpenSSL when Python's SSL module fails
def get_certificate_with_openssl(target, port):
    try:
        command = [
            "openssl", "s_client", "-connect", f"{target}:{port}", "-showcerts",
            "-servername", target, "-verify_return_error"
        ]
        process = subprocess.run(
            command,
            input="QUIT\n",  # Send input to close the connection
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15
        )
        output = process.stdout + process.stderr

        # Extract the first PEM certificate
        pem_cert = extract_pem_certificate(output)
        if not pem_cert:
            logging.error("Failed to extract PEM certificate from OpenSSL output.")
            return {
                "Validity Start": "Unknown",
                "Validity End": "Unknown",
                "Status": "OpenSSL failed to extract certificate",
            }

        # Parse the certificate and extract only the required fields
        return parse_certificate(pem_cert)

    except subprocess.TimeoutExpired:
        logging.error(f"OpenSSL command timed out for {target}:{port}")
        return {
            "Validity Start": "Unknown",
            "Validity End": "Unknown",
            "Status": "Timeout while retrieving certificate",
        }
    except Exception as e:
        logging.error(f"Error retrieving certificate with OpenSSL: {e}")
        return {
            "Validity Start": "Unknown",
            "Validity End": "Unknown",
            "Status": "Error",
        }

def extract_pem_certificate(output):
    """
    Extract the first PEM-encoded certificate from the OpenSSL output.
    """
    start_marker = "-----BEGIN CERTIFICATE-----"
    end_marker = "-----END CERTIFICATE-----"
    start_index = output.find(start_marker)
    end_index = output.find(end_marker, start_index)

    if start_index != -1 and end_index != -1:
        return output[start_index:end_index + len(end_marker)]
    return None

def parse_certificate(pem_cert):
    """
    Parse a PEM-encoded certificate and extract only CN, Validity Start, and Validity End.
    """
    try:
        cert = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())

        # Extract CN (Common Name)
        common_name = None
        for attribute in cert.subject:
            if attribute.oid == x509.NameOID.COMMON_NAME:
                common_name = attribute.value
                break

        # Extract validity dates
        not_before = cert.not_valid_before.strftime("%Y-%m-%d %H:%M:%S")
        not_after = cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S")

        return {
            "Common Name (CN)": common_name,
            "Validity Start": not_before,
            "Validity End": not_after,
            "Status": "Valid",
        }
    except Exception as e:
        logging.error(f"Error parsing certificate: {e}")
        return {
            "Validity Start": "Unknown",
            "Validity End": "Unknown",
            "Status": "Parsing error",
        }

def adjust_timezone(results, timezone_code):
    """
    Adjusts Validity Start and End to the specified timezone and updates status based on expiry.
    """
    tz = pytz.utc
    if timezone_code.upper() != "UTC":
        try:
            tz = pytz.timezone(pytz.country_timezones[timezone_code.upper()][0])
        except KeyError:
            logging.warning(f"Invalid timezone code: {timezone_code}. Defaulting to UTC.")
            tz = pytz.utc

    for result in results:
        try:
            if result["Validity Start"] != "Unknown" and result["Validity End"] != "Unknown":
                # Convert dates
                validity_start = datetime.strptime(result["Validity Start"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                validity_end = datetime.strptime(result["Validity End"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)

                result["Validity Start"] = validity_start.astimezone(tz).strftime("%A, %B %d, %Y at %I:%M:%S %p %Z")
                result["Validity End"] = validity_end.astimezone(tz).strftime("%A, %B %d, %Y at %I:%M:%S %p %Z")

                # Check expiration status
                now = datetime.now(tz)
                if validity_end < now:
                    result["Status"] = "Expired"
                elif (validity_end - now).days <= 30:
                    result["Status"] = "Expiring Soon"
                elif (validity_end - now).days <= 90:
                    result["Status"] = "Almost Expired"
                else:
                    result["Status"] = "Valid"
        except Exception as e:
            # Log errors but do not stop processing
            logging.error(f"Error adjusting timezone or updating status: {e}")
    return results

# Process domains
def process_domains(domains, port, timezone_code="UTC"):
    results = []
    total_domains = len(domains)

    with tqdm(total=total_domains, desc="Calculating total domains checked", ncols=100, unit="domain") as pbar:
        for domain in domains:
            clean_dom = clean_domain(domain)
            if not clean_dom:
                results.append({
                    "Domain": domain,
                    "Validity Start": "Error: Invalid domain format",
                    "Validity End": "Error: Invalid domain format",
                    "Status": "Unknown"
                })
                pbar.update(1)
                continue

            domain_result = {"Domain": domain}

            if not is_resolvable(clean_dom):
                domain_result.update({
                    "Validity Start": "Error: Domain not resolvable",
                    "Validity End": "Error: Domain not resolvable",
                    "Status": "Unknown"
                })
            else:
                try:
                    cert_details = get_ssl_dates(clean_dom, port, timezone_code)
                    domain_result.update(cert_details)
                except Exception as e:
                    logging.error(f"Error processing domain {domain}: {e}")
                    domain_result.update({
                        "Validity Start": "Unknown",
                        "Validity End": "Unknown",
                        "Status": "Error"
                    })

            results.append(domain_result)
            pbar.update(1)
    return adjust_timezone(results, timezone_code)

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
    parser.add_argument("--port", type=int, default=443, help="Port to check (default: 443)")
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

    results = process_domains(domains, args.port, timezone_code=args.time)
    save_results(results, args.format, args.output)

if __name__ == "__main__":
    main()
