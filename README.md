# SSL Certificate Validity Checker

![SSL Checker Banner](https://img.shields.io/badge/SSL-Checker-blue)
---

## Introduction

The **SSL Certificate Validity Checker** is a Python-based tool designed to evaluate the validity of SSL certificates for domains. It determines the start and end dates of SSL certificates, categorizes the expiration status, and provides detailed insights into certificate issues.

This tool is ideal for security engineers, network administrators, and DevOps professionals who need to ensure their websites are protected by valid SSL certificates.

---

## Features

- Check SSL certificate validity for single or multiple domains.
- Identify issues such as expired or unresolvable domains.
- Automatic timezone adjustment for start and end dates.
- Flexible output formats: JSON, CSV, XLSX, and plain text.
- Bulk processing of domains from a file.
- Graceful handling of SSL verification failures.

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/threatlabindonesia/SSL-Certificate-Validity-Checker.git
   cd ssl-certificate-checker
   ```

2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

---

## Requirements

The project requires the following Python packages:

```plaintext
argparse
pandas
tqdm
pytz
openpyxl
```

Install them using:
```bash
pip install -r requirements.txt
```

---

## Usage

### Single Domain
To check a single domain:
```bash
python ssl_checker.py --domain example.com
```

### Bulk Domains
To process multiple domains from a file:
```bash
python ssl_checker.py --file domains.txt
```

### Output Formats
Specify an output file format and path:
```bash
python ssl_checker.py --file domains.txt --output results.json --format json
```

Supported formats:
- `json`
- `csv`
- `xlsx`
- `txt`

### Timezone Adjustment
Adjust the timezone for certificate dates:
```bash
python ssl_checker.py --file domains.txt --time ID
```

---

## Example

### Input: `domains.txt`
```plaintext
example.com
expired.example.com
invalid-domain
self-signed.badssl.com
```

### Command
```bash
python ssl_checker.py --file domains.txt --output results.json --format json
```

### Outputs

#### 1. JSON Output (`results.json`)
```json
[
    {
        "Domain": "example.com",
        "Validity Start": "Monday, January 01, 2024 at 12:00:00 AM UTC",
        "Validity End": "Monday, January 01, 2025 at 12:00:00 AM UTC",
        "Days Expired": "N/A",
        "Status": "Valid"
    },
    {
        "Domain": "expired.example.com",
        "Validity Start": "Friday, January 01, 2021 at 12:00:00 AM UTC",
        "Validity End": "Friday, January 01, 2022 at 12:00:00 AM UTC",
        "Days Expired": 365,
        "Status": "Expired"
    },
    {
        "Domain": "invalid-domain",
        "Validity Start": "Error: Domain not resolvable",
        "Validity End": "Error: Domain not resolvable",
        "Days Expired": "Unknown",
        "Status": "Unknown"
    },
    {
        "Domain": "self-signed.badssl.com",
        "Validity Start": "Thursday, January 01, 2023 at 12:00:00 AM UTC",
        "Validity End": "Thursday, January 01, 2024 at 12:00:00 AM UTC",
        "Days Expired": "N/A",
        "Status": "Expired [Manual check required due to verification failure]"
    }
]
```

#### Explanation of Verification Failure:
The domain `self-signed.badssl.com` uses a self-signed certificate. The script detected the certificate but couldn't verify it through normal methods. The output includes a fallback check that retrieves the certificate information and categorizes it as "Expired [Manual check required due to verification failure]".

#### 2. Logging Example
```plaintext
2024-12-11 12:00:00 - INFO - Starting SSL check for self-signed.badssl.com
2024-12-11 12:00:02 - WARNING - SSL certificate verification failed for self-signed.badssl.com. Certificate has expired. Attempting manual extraction...
2024-12-11 12:00:03 - INFO - Manual certificate retrieval successful for self-signed.badssl.com.
```

---

## Outputs for Other Formats

#### CSV Output (`results.csv`)
```csv
Domain,Validity Start,Validity End,Days Expired,Status
example.com,Monday, January 01, 2024 at 12:00:00 AM UTC,Monday, January 01, 2025 at 12:00:00 AM UTC,N/A,Valid
expired.example.com,Friday, January 01, 2021 at 12:00:00 AM UTC,Friday, January 01, 2022 at 12:00:00 AM UTC,365,Expired
invalid-domain,Error: Domain not resolvable,Error: Domain not resolvable,Unknown,Unknown
self-signed.badssl.com,Thursday, January 01, 2023 at 12:00:00 AM UTC,Thursday, January 01, 2024 at 12:00:00 AM UTC,N/A,Expired [Manual check required due to verification failure]
```

#### XLSX Output (`results.xlsx`)
| Domain                | Validity Start            | Validity End              | Days Expired | Status                                          |
|-----------------------|---------------------------|---------------------------|--------------|------------------------------------------------|
| example.com           | Monday, January 01, 2024 | Monday, January 01, 2025  | N/A          | Valid                                          |
| expired.example.com   | Friday, January 01, 2021  | Friday, January 01, 2022  | 365          | Expired                                        |
| invalid-domain        | Error: Domain not resolvable | Error: Domain not resolvable | Unknown     | Unknown                                       |
| self-signed.badssl.com| Thursday, January 01, 2023 | Thursday, January 01, 2024 | N/A         | Expired [Manual check required due to verification failure] |

#### TXT Output (`results.txt`)
```plaintext
{'Domain': 'example.com', 'Validity Start': 'Monday, January 01, 2024 at 12:00:00 AM UTC', 'Validity End': 'Monday, January 01, 2025 at 12:00:00 AM UTC', 'Days Expired': 'N/A', 'Status': 'Valid'}
{'Domain': 'expired.example.com', 'Validity Start': 'Friday, January 01, 2021 at 12:00:00 AM UTC', 'Validity End': 'Friday, January 01, 2022 at 12:00:00 AM UTC', 'Days Expired': 365, 'Status': 'Expired'}
{'Domain': 'invalid-domain', 'Validity Start': 'Error: Domain not resolvable', 'Validity End': 'Error: Domain not resolvable', 'Days Expired': 'Unknown', 'Status': 'Unknown'}
{'Domain': 'self-signed.badssl.com', 'Validity Start': 'Thursday, January 01, 2023 at 12:00:00 AM UTC', 'Validity End': 'Thursday, January 01, 2024 at 12:00:00 AM UTC', 'Days Expired': 'N/A', 'Status': 'Expired [Manual check required due to verification failure]'}
```

---

## Author

This tool was created by **Afif Hidayatullah**.

Feel free to connect with me on [LinkedIn](https://www.linkedin.com/in/afif-hidayatullah).

---

## Contribution

Contributions are welcome! Feel free to fork this repository and submit a pull request with your improvements.

---

## Acknowledgments

- **ITSEC Asia**: For supporting the development of this tool.
- Open-source libraries and contributors who made this project possible.
