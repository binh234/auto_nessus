import argparse
import logging
import os
import time

import pandas as pd
from tenable.nessus import Nessus
from tqdm import tqdm
from dotenv import load_dotenv
import uuid

load_dotenv()
access_key = os.getenv("ACCESS_KEY")
secret_key = os.getenv("SECRET_KEY")
# Initialize Tenable.io client
nessus = Nessus(access_key=access_key, secret_key=secret_key, url="https://127.0.0.1:8834")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s: [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def main(args):
    if args.file.endswith(".csv"):
        data = pd.read_csv(args.file, delimiter=args.delimiter)
    elif args.file.endswith(".xlsx"):
        data = pd.read_excel(args.file)
    else:
        print("Unsupported file format. Please provide a CSV or Excel file.")
        return

    data.columns = data.columns.str.lower()
    if "username/password" in data.columns:
        data[["username", "password"]] = data["username/password"].str.split(" ", expand=True)

    grouped = data.groupby(["username", "password", "method"])

    folder_id = create_folder(args.name)
    scan_ids = []
    for (username, password, method), group in grouped:
        ips = group["ip"].tolist()
        ip_list = ",".join(ips)
        scan_name = group.iloc[0]["name"] + "-" + ip_list
        logging.info(f"Creating scan for IPs: {ip_list}")

        scan_id = create_and_launch_scan(scan_name, ip_list, username, password, method, folder_id)
        if scan_id:
            scan_ids.append(scan_id)

    if args.output is not None:
        os.makedirs(args.output, exist_ok=True)
        for scan_id in tqdm(scan_ids):
            download_report(args.output, scan_id)


def create_folder(folder_name):
    folders = nessus.folders.list()
    for folder in folders:
        if folder["name"] == folder_name:
            logging.info(f"Found existing folder {folder_name}")
            return folder["id"]

    logging.info(f"Creating new folder {folder_name}")
    new_folder_id = nessus.folders.create(folder_name)
    return new_folder_id


def create_and_launch_scan(scan_name, ip_list, username, password, method, folder_id):
    # Prepare the credentials based on the authentication method
    if method.lower() == "ssh":
        credentials = {
            "add": {
            "Host": {
                "SSH": [{"auth_method":"password","username":username,"password":password,"elevate_privileges_with":"Nothing","custom_password_prompt":"","target_priority_list":""}]
            }}
        }
    elif method.lower() == "http":
        credentials = {
            "add": {
            "Plaintext Authentication":{"HTTP":[{"auth_method":"Automatic authentication","username":username,"password":password}]}}
        }
    else:
        logging.error(
            f"Unsupported authentication method: {method}. Skipping scan creation for {scan_name}."
        )
        return None
    
    # Create and launch scan
    scan_uuid = uuid.uuid4()
    scan = nessus.scans.create(
        uuid="731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65",
        settings={
            "name": scan_name,
            "folder_id": folder_id,
            "text_targets": ip_list,
        },
        credentials=credentials,
    )
    scan_id = scan["scan"]["id"]
    nessus.scans.launch(scan_id)
    return scan_id

def download_report(scan_id, scan_name):

    while True:
        details = nessus.scans.details(scan_id)
        if details["status"] == "completed":
            break
        time.sleep(10)

    # Download the report
    report_path = f"./{scan_name}_report.html"
    with open(report_path, "wb") as f:
        nessus.scans.export_scan(scan_id, format="html", fobj=f)
    logging.info(f"Report downloaded: {report_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Automate Nessus scans based on provided credentials."
    )
    parser.add_argument(
        "file", type=str, help="Path to the Excel or CSV file containing credentials."
    )
    parser.add_argument(
        "--name", "-n", type=str, required=True, help="Name of the Nessus folder to use or create."
    )
    parser.add_argument("--delimiter", "-d", type=str, default=",", help="CSV delimiter")
    parser.add_argument(
        "--output", "-o", type=str, default=None, help="Output folder to save reports"
    )

    args = parser.parse_args()
    main(args)
