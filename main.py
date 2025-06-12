# -*- coding: utf-8 -*-
import argparse
import os
from datetime import datetime
from modules.patcher import IDA
from modules.banners import banners
from modules.logging import logger

def main():
    parser = argparse.ArgumentParser(description="IDA Pro License Generator and Patcher")

    parser.add_argument("-p", "--path", required=True, help="Full path to the IDA Pro installation directory")
    parser.add_argument("-n", "--name", default="HexRays User", help="Name for the license")
    parser.add_argument("-e", "--email", default="user@hexrays.com", help="Email for the license")
    parser.add_argument("-ed", "--end-date", type=int, help="End year of the license (e.g. 2035)")

    args = parser.parse_args()

    ida = IDA()
    ida.name = args.name
    ida.email = args.email
    ida.path = args.path.strip('"').strip()
    if not os.path.isdir(ida.path):
        logger.error(f"Invalid IDA path provided: {ida.path}")
        return

    now = datetime.now()
    end_year = args.end_date or (now + 10)
    ida.end_date = datetime(end_year, now.month, now.day, now.hour, now.minute, now.second).strftime("%Y-%m-%d %H:%M:%S")

    ida.generate_license_file()
    ida.patch_platform_binaries(ida.path)
    ida.move_license_file(ida.path)

if __name__ == "__main__":
    banners()
    main()
