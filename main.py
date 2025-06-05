from modules.patcher import generate_license_file, patch_platform_binaries, move_license_file
from modules.banners import banners
import os

if __name__ == "__main__":
    banners()
    generate_license_file()

    ida_path = input("📁 Enter full IDA installation path: ").strip('"').strip()
    if not os.path.isdir(ida_path):
        print(f"❌ Invalid path: {ida_path}")
    else:
        print()
        patch_platform_binaries(ida_path)
        move_license_file(ida_path)
