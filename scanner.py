import subprocess
import re

def is_bad_ip(ip):
    return (
        ip.startswith("169.254") or
        ip.startswith("224.") or
        ip.startswith("239.") or
        ip.startswith("255.") or
        ip == "127.0.0.1"
    )

def scan_network():
    devices = []

    try:
        result = subprocess.check_output(
            "arp -a",
            encoding="utf-8",
            errors="ignore"
        )

        pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{11,17})"
        matches = re.findall(pattern, result)

        for ip, mac in matches:
            if is_bad_ip(ip):
                continue

            clean_mac = mac.replace("-", ":").upper()

            if clean_mac in ["FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"]:
                continue

            devices.append({
                "ip": ip,
                "mac": clean_mac,
                "vendor": guess_vendor(clean_mac)
            })

        return devices

    except Exception as e:
        print("SCAN ERROR:", e)
        return []

def guess_vendor(mac):
    prefix = mac[:8].upper()

    vendors = {
        "B4:0C:25": "Palo Alto Networks",
        "00:50:56": "VMware",
        "00:04:A5": "Cisco",
        "70:CF:49": "Apple",
        "60:45:2E": "Intel",
        "8C:F8:C5": "Intel",
    }

    return vendors.get(prefix, "Unknown")