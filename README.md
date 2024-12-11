# SSL Certificate Validity Checker

![SSL Checker Banner](https://img.shields.io/badge/SSL-Checker-blue)
---

## Introduction

The **SSL Certificate Validity Checker** is a Python-based tool designed to evaluate the validity of SSL certificates for domains and IP addresses. It determines the start and end dates of SSL certificates, categorizes the expiration status, and provides detailed insights into certificate issues. The tool supports custom port checks and allows you to adjust the timezone for certificate dates.

This tool is ideal for security engineers, network administrators, and DevOps professionals who need to ensure their websites are protected by valid SSL certificates.

---

## Features

- Check SSL certificate validity for single or multiple domains/IPs.
- Identify issues such as expired, soon-to-expire, or unresolvable domains.
- Automatic timezone adjustment for start and end dates (`--time` option).
- Flexible output formats: JSON, CSV, XLSX, and plain text.
- Bulk processing of domains from a file.
- Custom port support for SSL connections (`--port` option).
- Graceful handling of SSL verification failures and fallback to OpenSSL.
- Clean progress bar to show real-time status updates.

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/threatlabindonesia/SSL-Certificate-Validity-Checker.git
   cd SSL-Certificate-Validity-Checke
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
cryptography
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

### Custom Port
To specify a custom port for SSL:
```bash
python ssl_checker.py --domain example.com --port 8443
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
110.111.111.111
```

### Command
```bash
python ssl_checker.py --file domains.txt --output results.json --format json --time ID
```

### Outputs

#### 1. JSON Output (`results.json`)
```json
[
    {
        "Domain": "example.com",
        "Validity Start": "Saturday, October 01, 2024 at 7:00:00 AM WIB",
        "Validity End": "Saturday, October 18, 2025 at 6:59:59 AM WIB",
        "Status": "Valid"
    },
    {
        "Domain": "expired.example.com",
        "Validity Start": "Friday, October 01, 2021 at 7:00:00 AM WIB",
        "Validity End": "Friday, October 01, 2022 at 6:59:59 AM WIB",
        "Status": "Expired"
    },
    {
        "Domain": "invalid-domain",
        "Validity Start": "Error: Domain not resolvable",
        "Validity End": "Error: Domain not resolvable",
        "Status": "Unknown"
    },
    {
        "Domain": "self-signed.badssl.com",
        "Validity Start": "Thursday, October 01, 2023 at 7:00:00 AM WIB",
        "Validity End": "Thursday, October 01, 2024 at 6:59:59 AM WIB",
        "Status": "Expired [Manual check required due to verification failure]"
    },
    {
        "Domain": "110.111.111.111",
        "Validity Start": "Saturday, October 01, 2024 at 7:00:00 AM WIB",
        "Validity End": "Saturday, October 18, 2025 at 6:59:59 AM WIB",
        "Status": "Valid"
    }
]
```

---

### Outputs for Other Formats

#### CSV Output (`results.csv`)
```csv
Domain,Validity Start,Validity End,Status
example.com,Saturday, October 01, 2024 at 7:00:00 AM WIB,Saturday, October 18, 2025 at 6:59:59 AM WIB,Valid
expired.example.com,Friday, October 01, 2021 at 7:00:00 AM WIB,Friday, October 01, 2022 at 6:59:59 AM WIB,Expired
invalid-domain,Error: Domain not resolvable,Error: Domain not resolvable,Unknown
self-signed.badssl.com,Thursday, October 01, 2023 at 7:00:00 AM WIB,Thursday, October 01, 2024 at 6:59:59 AM WIB,Expired [Manual check required due to verification failure]
114.7.94.136,Saturday, October 01, 2024 at 7:00:00 AM WIB,Saturday, October 18, 2025 at 6:59:59 AM WIB,Valid
```

#### XLSX Output (`results.xlsx`)
| Domain                | Validity Start                     | Validity End                       | Status                                          |
|-----------------------|-------------------------------------|-------------------------------------|------------------------------------------------|
| example.com           | Saturday, October 01, 2024 at 7:00:00 AM WIB | Saturday, October 18, 2025 at 6:59:59 AM WIB | Valid                                          |
| expired.example.com   | Friday, October 01, 2021 at 7:00:00 AM WIB  | Friday, October 01, 2022 at 6:59:59 AM WIB  | Expired                                        |
| invalid-domain        | Error: Domain not resolvable       | Error: Domain not resolvable       | Unknown                                        |
| self-signed.badssl.com| Thursday, October 01, 2023 at 7:00:00 AM WIB | Thursday, October 01, 2024 at 6:59:59 AM WIB | Expired [Manual check required due to verification failure] |
| 110.111.111.111       | Saturday, October 01, 2024 at 7:00:00 AM WIB | Saturday, October 18, 2025 at 6:59:59 AM WIB | Valid                                          |

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
