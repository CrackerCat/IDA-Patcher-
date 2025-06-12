import json
import hashlib
import os
import platform
import shutil
from datetime import datetime, timedelta
from modules.logging import logger

class IDA:
    def __init__(self):
        self.path = None
        self.email = None
        self.name = None
        self.log = logger
        self.addons = ["HEXX86", "HEXX64", "HEXARM", "HEXARM64", "HEXMIPS", "HEXMIPS64", "HEXPPC", "HEXPPC64", "HEXRV64", "HEXARC", "HEXARC64"] # "HEXCX86", "HEXCX64", "HEXCARM", "HEXCARM64", "HEXCMIPS", "HEXCMIPS64", "HEXCPPC", "HEXCPPC64", "HEXCRV", "HEXCRV64", "HEXCARC", "HEXCARC64",
        self.patch_origin = bytes.fromhex("EDFD425CF978")
        self.patched = bytes.fromhex("EDFD42CBF978")
        self.license_filename = "idapro.hexlic"
        self.start_date = (datetime.now() - timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S")
        self.end_date = None

    def public_modules_patched(self):
        return int.from_bytes(
            bytes.fromhex(
                "EDFD42CBF978546E8911225884436C57140525650BCF6EBFE80EDBC5FB1DE68F4C66C29CB22EB668788AFCB0ABBB718044584B810F8970CDD"
                "F227385F75D5DDDD91D4F18937A08AA83B28C49D12DC92E7505BB38809E91BD0FBD2F2E6AB1D2E33C0C55D5BDDD478EE8BF845FCEF3C82B9D"
                "2929ECB71F4D1B3DB96E3A8E7AAF93"
            ),
            "little"
        )

    def private_keys(self):
        return int.from_bytes(
            bytes.fromhex(
                "77C86ABBB7F3BB134436797B68FF47BEB1A5457816608DBFB72641814DD464DD640D711D5732D3017A1C4E63D835822F00A4EAB619A2C4791"
                "CF33F9F57F9C2AE4D9EED9981E79AC9B8F8A411F68F25B9F0C05D04D11E22A3A0D8D4672B56A61F1532282FF4E4E74759E832B70E98B9D102"
                "D07E9FB9BA8D15810B144970029874"
            ),
            "little"
        )

    def generate_license(self):
        self.log.info(f"Generating license")
        return {
            "header": {"version": 1},
            "payload": {
                "name": self.name,
                "email": self.email,
                "licenses": [
                    {
                        "id": "48-2137-ACAB-99", # do not generate random license id
                        "edition_id": "ida-pro",
                        "description": "license",
                        "license_type": "named",
                        "product": "IDA",
                        "product_id": "IDAPRO",
                        "product_version": "9.1",
                        "seats": 1,
                        "start_date": self.start_date,
                        "end_date": self.end_date, # # This can't be more than 10 years!
                        "issued_on": self.start_date,
                        "owner": "HexRays",
                        "add_ons": [
                            # {
                            #     "id": "48-1337-DEAD-01",
                            #     "code": "HEXX86L",
                            #     "owner": "48-0000-0000-00",
                            #     "start_date": "2025-06-13 00:00:00",
                            #     "end_date": "2035-12-31 23:59:59",
                            # },
                            # {
                            #     "id": "48-1337-DEAD-02",
                            #     "code": "HEXX64L",
                            #     "owner": "48-0000-0000-00",
                            #     "start_date": "2025-06-13 00:00:00",
                            #     "end_date": "2035-12-31 23:59:59",
                            # },
                        ],
                        "features": [],
                    }
                ],
            },
        }

    def add_all_addons(self, license_dict):
        self.log.info(f"Adding {len(self.addons)} addons")
        base = license_dict["payload"]["licenses"][0]
        for idx, code in enumerate(self.addons, start=1):
            base["add_ons"].append({
                "id": f"48-1337-0000-{idx:02}",
                "code": code,
                "owner": base["id"],
                "start_date": self.start_date,
                "end_date": self.end_date,
            })

    def json_stringify_sorted(self, obj):
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))

    def int_to_le_bytes(self, i: int) -> bytes:
        return i.to_bytes((i.bit_length() + 7) // 8, "little")

    def le_bytes_to_int(self, b: bytes) -> int:
        return int.from_bytes(b, "little")

    def encrypt(self, data: bytes) -> bytes:
        encrypted = pow(self.le_bytes_to_int(data[::-1]), self.private_keys(), self.public_modules_patched())
        return self.int_to_le_bytes(encrypted)

    def sign_license(self, payload: dict) -> str:
        self.log.info("Signing license")
        data_str = self.json_stringify_sorted({"payload": payload})
        buffer = bytearray(128)
        buffer[:33] = b"\x42" * 33
        digest = hashlib.sha256(data_str.encode()).digest()
        buffer[33:65] = digest
        encrypted = self.encrypt(buffer)
        return encrypted.hex().upper()

    def patch_binary(self, file_path: str):
        self.log.info(f"Patching {file_path}")
        if not os.path.exists(file_path):
            self.log.warning(f"Skip: {file_path} - file does not exist")
            return

        with open(file_path, "rb") as f:
            data = f.read()

        if self.patched in data:
            self.log.warning(f"{file_path} is already patched")
            return
        if self.patch_origin not in data:
            self.log.warning(f"{file_path} - original patch pattern not found")
            return

        data = data.replace(self.patch_origin, self.patched)
        with open(file_path, "wb") as f:
            f.write(data)

        self.log.info(f"{file_path} has been successfully patched")

    def generate_license_file(self):
        license_data = self.generate_license()
        self.add_all_addons(license_data)
        license_data["signature"] = self.sign_license(license_data["payload"])
        license_dir = os.path.join(os.getcwd(), "license")
        os.makedirs(license_dir, exist_ok=True)
        license_path = os.path.join(license_dir, self.license_filename)
        with open(license_path, "w") as f:
            f.write(self.json_stringify_sorted(license_data))
        self.log.info(f"New license generated and saved to {license_path}")

    def patch_platform_binaries(self, ida_path: str):
        self.log.info("Patching platform binaries")
        os_name = platform.system().lower()
        binaries = {
            "windows": ["ida.dll", "ida32.dll"],
            "linux": ["libida.so", "libida32.so"],
            "darwin": ["libida.dylib", "libida32.dylib"],
        }.get(os_name, [])

        if not binaries:
            self.log.error(f"Unsupported operating system: {os_name}")
            return

        for binary in binaries:
            binary_path = os.path.join(ida_path, binary)
            self.patch_binary(binary_path)

    def move_license_file(self, ida_path: str):
        self.log.info("Copying license file")
        try:
            source_path = os.path.join(os.getcwd(), "license", self.license_filename)
            dest = os.path.join(ida_path, self.license_filename)
            shutil.copy2(source_path, dest)
            self.log.info(f"License file copied to: {dest}")
        except Exception as e:
            self.log.error(f"Failed to copy license file: {e}")
