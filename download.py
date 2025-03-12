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

BASIC_SCAN_UUID = "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65"

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

    logger.info(f"Scan reports will be downloaed to directory {args.name}")
    os.makedirs(args.name, exist_ok=True)

    folder_id = get_folder(args.name)
    scan_recs = [(scan['id'], scan['name']) for scan in nessus.scans.list(folder_id=folder_id)['scans']]

    # Wait for all scans finish
    for scan_id, scan_name in scan_recs:
        download_report(args.name, scan_id, scan_name)

def get_folder(folder_name):
    folders = nessus.folders.list()
    for folder in folders:
        if folder["name"] == folder_name:
            logger.info(f"Found existing folder {folder_name}")
            return folder["id"]

    raise ValueError(f"Can't find folder ID for {folder_name}")

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
        description="Download all Nessus scans inside a folder."
    )
    parser.add_argument(
        "--name", "-n", type=str, required=True, help="Name of the Nessus folder to use or create."
    )

    args = parser.parse_args()
    main(args)
