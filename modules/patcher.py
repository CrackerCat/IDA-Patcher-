# -*- coding: utf-8 -*-
import json
import hashlib
import os
import platform
import shutil
from datetime import datetime, timedelta

# Constants
ADDONS = [
    "HEXX86", "HEXX64", "HEXARM", "HEXARM64", "HEXMIPS", "HEXMIPS64",
    "HEXPPC", "HEXPPC64", "HEXRV64", "HEXARC", "HEXARC64"
]
PATCH_ORIGINAL = bytes.fromhex("EDFD425CF978")
PATCHED = bytes.fromhex("EDFD42CBF978")
LICENSE_FILENAME = "idapro.hexlic"

# Public and private key values
pub_modulus_patched = int.from_bytes(
    bytes.fromhex(
        "EDFD42CBF978546E8911225884436C57140525650BCF6EBFE80EDBC5FB1DE68F4C66C29CB22EB668788AFCB0ABBB718044584B810F8970CDD"
        "F227385F75D5DDDD91D4F18937A08AA83B28C49D12DC92E7505BB38809E91BD0FBD2F2E6AB1D2E33C0C55D5BDDD478EE8BF845FCEF3C82B9D"
        "2929ECB71F4D1B3DB96E3A8E7AAF93"
    ),
    "little"
)
private_key = int.from_bytes(
    bytes.fromhex(
        "77C86ABBB7F3BB134436797B68FF47BEB1A5457816608DBFB72641814DD464DD640D711D5732D3017A1C4E63D835822F00A4EAB619A2C4791"
        "CF33F9F57F9C2AE4D9EED9981E79AC9B8F8A411F68F25B9F0C05D04D11E22A3A0D8D4672B56A61F1532282FF4E4E74759E832B70E98B9D102"
        "D07E9FB9BA8D15810B144970029874"
    ),
    "little"
)

def create_license_data():
    start_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    end_date = (datetime.now() + timedelta(days=365 * 10)).strftime("%Y-%m-%d %H:%M:%S")
    
    return {
        "header": {"version": 1},
        "payload": {
            "name": "IDAPRO9",
            "email": "idapro9@example.com",
            "licenses": [
                {
                    "id": "48-2137-ACAB-99",
                    "edition_id": "ida-pro",
                    "description": "license",
                    "license_type": "named",
                    "product": "IDA",
                    "product_id": "IDAPRO",
                    "product_version": "9.1",
                    "seats": 1,
                    "start_date": start_date,
                    "end_date": end_date,
                    "issued_on": start_date,
                    "owner": "HexRays",
                    "add_ons": [],
                    "features": [],
                }
            ],
        },
    }

def add_all_addons(license_dict):
    start_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    end_date = (datetime.now() + timedelta(days=365 * 10)).strftime("%Y-%m-%d %H:%M:%S")
    
    base = license_dict["payload"]["licenses"][0]
    for idx, code in enumerate(ADDONS, start=1):
        base["add_ons"].append({
            "id": f"48-1337-0000-{idx:02}",
            "code": code,
            "owner": base["id"],
            "start_date": start_date,
            "end_date": end_date,
        })

def json_stringify_sorted(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))

def int_to_le_bytes(i: int) -> bytes:
    return i.to_bytes((i.bit_length() + 7) // 8, "little")

def le_bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "little")

def encrypt(data: bytes) -> bytes:
    encrypted = pow(le_bytes_to_int(data[::-1]), private_key, pub_modulus_patched)
    return int_to_le_bytes(encrypted)

def sign_license(payload: dict) -> str:
    data_str = json_stringify_sorted({"payload": payload})
    buffer = bytearray(128)
    buffer[:33] = b"\x42" * 33
    digest = hashlib.sha256(data_str.encode()).digest()
    buffer[33:65] = digest
    encrypted = encrypt(buffer)
    return encrypted.hex().upper()

def patch_binary(file_path: str):
    if not os.path.exists(file_path):
        print(f"Skip: {file_path} - not found")
        return

    with open(file_path, "rb") as f:
        data = f.read()

    if PATCHED in data:
        print(f"Patch: {file_path} - already patched ✅")
        return
    if PATCH_ORIGINAL not in data:
        print(f"Patch: {file_path} - original pattern not found.")
        return

    data = data.replace(PATCH_ORIGINAL, PATCHED)
    with open(file_path, "wb") as f:
        f.write(data)

    print(f"Patch: {file_path} - OK")

def generate_license_file(output: str = LICENSE_FILENAME):
    license_data = create_license_data()
    add_all_addons(license_data)
    license_data["signature"] = sign_license(license_data["payload"])
    with open(output, "w") as f:
        f.write(json_stringify_sorted(license_data))
    print(f"Saved new license to: {output} ✅")

def patch_platform_binaries(ida_path: str):
    os_name = platform.system().lower()
    binaries = {
        "windows": ["ida.dll", "ida32.dll"],
        "linux": ["libida.so", "libida32.so"],
        "darwin": ["libida.dylib", "libida32.dylib"],
    }.get(os_name, [])

    if not binaries:
        print(f"Unsupported OS: {os_name}")
        return

    for binary in binaries:
        patch_binary(os.path.join(ida_path, binary))

def move_license_file(ida_path: str):
    try:
        dest = os.path.join(ida_path, LICENSE_FILENAME)
        shutil.move(LICENSE_FILENAME, dest)
        print(f"Moved license to: {dest} ✅\n")
    except Exception as e:
        print(f"❌ Failed to move license: {e}\n")
