
# AWS S3 Misconfiguration Detector

A Python-based cloud security tool that scans AWS S3 buckets and identifies common security misconfigurations.

## Features

* Detects disabled bucket versioning
* Detects missing encryption
* Detects public access configuration issues
* Severity-based findings (PASS, MEDIUM, HIGH, CRITICAL)
* Progress bar for bucket scanning
* JSON report generation
* CSV report generation
* Security score calculation

## Technologies Used

* Python
* AWS S3
* IAM
* Boto3
* Pandas
* Colorama
* tqdm

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python s3_misconfig_detector.py
```

## Example Output

```text
Bucket: my-security-bucket

[HIGH] Versioning Disabled
[PASS] Encryption Enabled
[PASS] Public Access Blocked

Security Score: 66/100
```

## Security Checks

* Bucket Versioning
* Bucket Encryption
* Public Access Block Configuration

## Sample output

<img width="1919" height="626" alt="Screenshot 2026-06-09 211746" src="https://github.com/user-attachments/assets/89508680-b59e-4f49-bb5a-68c51ba4d9df" />


## Author

Vishal
