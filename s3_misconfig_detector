import boto3
import json
import pandas as pd
from tqdm import tqdm
from colorama import Fore, Style, init
from botocore.exceptions import ClientError

init(autoreset=True)

s3 = boto3.client("s3")

report_data = []
passes = 0
findings = 0


def check_versioning(bucket_name):
    response = s3.get_bucket_versioning(Bucket=bucket_name)

    if response.get("Status") == "Enabled":
        return "[PASS] Versioning Enabled"

    return "[HIGH] Versioning Disabled"


def check_encryption(bucket_name):
    try:
        s3.get_bucket_encryption(Bucket=bucket_name)
        return "[PASS] Encryption Enabled"

    except ClientError:
        return "[MEDIUM] Encryption Disabled"


def check_public_access(bucket_name):
    try:
        response = s3.get_public_access_block(
            Bucket=bucket_name
        )

        config = response["PublicAccessBlockConfiguration"]

        if all(config.values()):
            return "[PASS] Public Access Blocked"

        return "[CRITICAL] Public Access Allowed"

    except ClientError:
        return "[CRITICAL] No Public Access Block Configuration"


print("\n" + "=" * 50)
print(" AWS S3 MISCONFIGURATION DETECTOR ")
print("=" * 50)

response = s3.list_buckets()
buckets = response["Buckets"]

if not buckets:
    print("No buckets found.")
    exit()

for bucket in tqdm(buckets, desc="Scanning Buckets"):

    bucket_name = bucket["Name"]

    print(f"\n{Fore.CYAN}Bucket: {bucket_name}")

    results = [
        check_versioning(bucket_name),
        check_encryption(bucket_name),
        check_public_access(bucket_name)
    ]

    for result in results:

        if "[PASS]" in result:
            print(Fore.GREEN + result)
            passes += 1
            status = "PASS"

        elif "[CRITICAL]" in result:
            print(Fore.RED + Style.BRIGHT + result)
            findings += 1
            status = "CRITICAL"

        elif "[HIGH]" in result:
            print(Fore.RED + result)
            findings += 1
            status = "HIGH"

        elif "[MEDIUM]" in result:
            print(Fore.YELLOW + result)
            findings += 1
            status = "MEDIUM"

        report_data.append({
            "Bucket": bucket_name,
            "Result": result,
            "Severity": status
        })

total_checks = passes + findings

if total_checks > 0:
    security_score = int((passes / total_checks) * 100)
else:
    security_score = 0

print("\n" + "=" * 50)
print("SCAN COMPLETE")
print("=" * 50)

print(f"Passes          : {passes}")
print(f"Findings        : {findings}")
print(f"Security Score  : {security_score}/100")

with open("report.json", "w") as file:
    json.dump(report_data, file, indent=4)

df = pd.DataFrame(report_data)
df.to_csv("report.csv", index=False)

print("\nReports Generated:")
print("report.json")
print("report.csv")
