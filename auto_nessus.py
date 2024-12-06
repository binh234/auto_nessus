import argparse
import logging
import os
import time

import coloredlogs
import pandas as pd
from dotenv import load_dotenv
from tenable.nessus import Nessus
from unidecode import unidecode

load_dotenv()

# Initialize logger
logger = logging.getLogger()
coloredlogs.install(
    level="INFO",
    logger=logger,
    fmt="%(asctime)s: [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Initialize Nessus client
access_key = os.getenv("ACCESS_KEY")
secret_key = os.getenv("SECRET_KEY")
nessus_url = os.getenv("NESSUS_URL", "https://127.0.0.1:8834")
nessus = Nessus(access_key=access_key, secret_key=secret_key, url=nessus_url)


def main(args):
    if args.file.endswith(".csv"):
        data = pd.read_csv(args.file, delimiter=args.delimiter)
    elif args.file.endswith(".xlsx"):
        data = pd.read_excel(args.file)
    else:
        print("Unsupported file format. Please provide a CSV or Excel file.")
        return

    if args.save:
        logger.info(f"Scan reports will be downloaed to directory {args.name}")
        os.makedirs(args.name, exist_ok=True)

    # Lower all column names
    data.columns = data.columns.str.lower()
    if "username/password" in data.columns:
        data[["username", "password"]] = data["username/password"].str.split(args.upd, expand=True)

    data["method"] = data["method"].fillna("ssh")  # Default authentication method to ssh
    data["name"] = data["name"].map(unidecode)

    folder_id = create_folder(args.name)
    scan_recs = []
    for _, row in data.iterrows():
        username = row["username"]
        password = row["password"]
        method = row["method"]
        ip_list = row["ip"]
        scan_name = row["name"] + "-" + ip_list
        logger.info(f"Creating scan for IPs: {ip_list}")

        scan_id = create_and_launch_scan(scan_name, ip_list, username, password, method, folder_id)
        if scan_id:
            scan_recs.append((scan_id, scan_name))

        if len(scan_recs) >= args.max:
            complete_idx = check_completed_scan_idx(scan_recs)
            complete_id, complete_name = scan_recs.pop(complete_idx)
            if args.save:
                download_report(args.name, complete_id, complete_name)


def create_folder(folder_name):
    folders = nessus.folders.list()
    for folder in folders:
        if folder["name"] == folder_name:
            logger.info(f"Found existing folder {folder_name}")
            return folder["id"]

    logger.info(f"Creating new folder {folder_name}")
    new_folder_id = nessus.folders.create(folder_name)
    return new_folder_id


def create_and_launch_scan(scan_name, ip_list, username, password, method, folder_id):
    # Prepare the credentials based on the authentication method
    if method.lower() == "ssh":
        credentials = {
            "add": {
                "Host": {
                    "SSH": [
                        {
                            "auth_method": "password",
                            "username": username,
                            "password": password,
                            "elevate_privileges_with": "Nothing",
                            "custom_password_prompt": "",
                            "target_priority_list": "",
                        }
                    ]
                }
            }
        }
    elif method.lower() == "http":
        credentials = {
            "add": {
                "Plaintext Authentication": {
                    "HTTP": [
                        {
                            "auth_method": "Automatic authentication",
                            "username": username,
                            "password": password,
                        }
                    ]
                }
            }
        }
    elif method.lower() == "windows":
        credentials = {
            "add": {
                "Host": {
                    "Windows": [
                        {
                            "auth_method": "Password",
                            "username": username,
                            "password": password,
                            "domain": "",
                        }
                    ]
                }
            }
        }
    else:
        logger.error(
            f"Unsupported authentication method: {method}. Skipping scan creation for {scan_name}."
        )
        return None

    # Create and launch scan
    scan = nessus.scans.create(
        uuid="731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65",  # Basic scan
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


def check_completed_scan_idx(scans):
    complete_idx = None
    while complete_idx is None:
        for idx, (scan_id, scan_name) in enumerate(scans):
            details = nessus.scans.details(scan_id)
            if details["info"]["status"] == "completed":
                logger.info(f"Scan {scan_name} finished")
                complete_idx = idx
                return complete_idx
            else:
                time.sleep(15)


def download_report(output, scan_id, scan_name):
    """Download Nessus scan report for scan ID

    Args:
        output (str): Output directory
        scan_id (int): Scan ID
        scan_name (str): Scan name
    """

    # Retrieve template id
    templates = nessus.get("reports/custom/templates", box=True)
    template_id = None
    template_name = "Vulnerability Operations"
    for template in templates:
        if template.name == template_name:
            template_id = template.id
            break

    if template_id is None:
        logger.error(f"Can not find template id for {template_name}")
        return

    details = nessus.scans.details(scan_id)
    if details["info"]["status"] == "completed":
        # Download the report
        report_path = os.path.join(output, f"{scan_name}_report.html")
        with open(report_path, "wb") as f:
            nessus.scans.export_scan(scan_id, format="html", template_id=template_id, fobj=f)
        logger.info(f"Report downloaded: {report_path}")
    else:
        logger.error(f"Scan {scan_name} is not finished yet!")


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
    parser.add_argument(
        "--max",
        "-m",
        type=int,
        default=8,
        help="Maximum scans to run cocurrently",
    )
    parser.add_argument(
        "--delimiter", "-d", type=str, default=",", help="CSV delimiter, defaults to ','"
    )
    parser.add_argument(
        "--upd",
        type=str,
        default="/",
        help="Username/password delimiter, defaults to '/'. Only affect when 'Username/password' column exists",
    )
    parser.add_argument(
        "--save",
        "-s",
        default=False,
        action="store_true",
        help="Whether to save reports in local directory",
    )

    args = parser.parse_args()
    main(args)
