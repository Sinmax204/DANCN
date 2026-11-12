def calculate_risk(device):
    score = 0
    reasons = []

    status = device.get("status", "")
    vendor = device.get("vendor", "Unknown")
    mac = device.get("mac", "Unknown")

    if status == "Unknown Device":
        score += 40
        reasons.append("Thiết bị chưa xác thực")

    if vendor == "Unknown":
        score += 25
        reasons.append("Không xác định được nhà cung cấp")

    if mac == "Unknown":
        score += 20
        reasons.append("Không xác định được MAC Address")

    if mac != "Unknown" and mac.startswith(("02:", "06:", "0A:", "0E:")):
        score += 15
        reasons.append("MAC có dấu hiệu random/private")

    if score >= 70:
        level = "High"
    elif score >= 31:
        level = "Medium"
    else:
        level = "Low"

    return score, level, ", ".join(reasons) if reasons else "Thiết bị có rủi ro thấp"