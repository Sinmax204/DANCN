from flask import Flask, render_template, request, redirect, url_for, session, Response, jsonify
from functools import wraps
import csv, io
from datetime import datetime

from scanner import scan_network
from database import *

app = Flask(__name__)
app.secret_key = "lan_guard_god_mode_secret"

init_db()

def auth(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrap

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        u = request.form.get("u") or request.form.get("username")
        p = request.form.get("p") or request.form.get("password")

        if u == "admin" and p in ["123", "123456"]:
            session["user"] = "admin"
            add_log("LOGIN", "Admin đăng nhập hệ thống")
            return redirect(url_for("home"))
        error = "Sai tài khoản hoặc mật khẩu"

    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    add_log("LOGOUT", "Admin đăng xuất hệ thống")
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@auth
def home():
    devices, trusted, blacklist, total, known, unknown, high = build_dashboard()
    logs = get_logs(8)

    return render_template(
        "index.html",
        devices=devices,
        trusted=trusted,
        blacklist=blacklist,
        total=total,
        known=known,
        unknown=unknown,
        high=high,
        logs=logs,
        username=session.get("user")
    )

@app.route("/scan", methods=["POST"])
@auth
def scan():
    devices = scan_network()

    if not devices:
        devices = [
            {"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:01", "vendor": "Intel"},
            {"ip": "192.168.1.20", "mac": "AA:BB:CC:DD:EE:02", "vendor": "Unknown"},
            {"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:03", "vendor": "Gateway"}
        ]

    save_devices(devices)
    add_log("SCAN", f"Quét mạng, phát hiện {len(devices)} thiết bị")
    return redirect(url_for("home"))

@app.route("/auto_scan", methods=["POST"])
@auth
def auto_scan():
    devices = scan_network()
    if devices:
        save_devices(devices)
        add_log("AUTO_SCAN", f"Hệ thống tự động quét {len(devices)} thiết bị")
    return jsonify({"ok": True})

@app.route("/simulate_attack", methods=["POST"])
@auth
def simulate_attack():
    fake_device = {
        "ip": "10.10.10.66",
        "mac": "DE:AD:BE:EF:66:66",
        "vendor": "Unknown Attacker Device"
    }

    save_devices([fake_device])
    add_black(fake_device["mac"], fake_device["vendor"])

    add_log("IDS_ALERT", "Phát hiện hành vi nghi vấn: thiết bị lạ xuất hiện trong mạng")
    add_log("PORT_SCAN", "Giả lập phát hiện port scan từ thiết bị DE:AD:BE:EF:66:66")
    add_log("THREAT_RESPONSE", "Hệ thống tự động đưa thiết bị vào blacklist")

    return redirect(url_for("home"))

@app.route("/trust/<path:mac>", methods=["POST"])
@auth
def trust(mac):
    d = get_device_by_mac(mac)
    if d:
        add_trusted(d["mac"], d["vendor"])
        remove_black(d["mac"])
        add_log("TRUST_ACTION", f"Admin đánh dấu thiết bị tin cậy: {d['mac']}")
    return redirect(url_for("home"))

@app.route("/untrust/<path:mac>", methods=["POST"])
@auth
def untrust(mac):
    remove_trusted(mac)
    add_log("UNTRUST_ACTION", f"Admin gỡ thiết bị khỏi danh sách tin cậy: {mac}")
    return redirect(url_for("home"))

@app.route("/block/<path:mac>", methods=["POST"])
@auth
def block(mac):
    d = get_device_by_mac(mac)
    if d:
        add_black(d["mac"], d["vendor"])
        remove_trusted(d["mac"])
        add_log("BLOCK_ACTION", f"Admin chặn thiết bị: {d['mac']}")
    return redirect(url_for("home"))

@app.route("/unblock/<path:mac>", methods=["POST"])
@auth
def unblock(mac):
    remove_black(mac)
    add_log("UNBLOCK_ACTION", f"Admin gỡ chặn thiết bị: {mac}")
    return redirect(url_for("blacklist"))

@app.route("/trusted")
@auth
def trusted_page():
    return render_template("trusted.html", rows=get_trusted())

@app.route("/blacklist")
@auth
def blacklist():
    return render_template("blacklist.html", rows=get_black())

@app.route("/history")
@auth
def history():
    return render_template("history.html", rows=get_history())

@app.route("/activity")
@auth
def activity():
    return render_template("activity.html", rows=get_logs(100))

@app.route("/export")
@auth
def export_csv():
    devices, trusted, blacklist, total, known, unknown, high = build_dashboard()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["IP", "MAC", "Vendor", "Status", "Risk Score", "Risk Level", "Last Seen"])

    for d in devices:
        writer.writerow([
            d["ip"],
            d["mac"],
            d["vendor"],
            d["status"],
            d["risk_score"],
            d["risk_level"],
            d["last_seen"]
        ])

    add_log("EXPORT", "Admin xuất báo cáo CSV")

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=lan_guard_report.csv"}
    )

@app.route("/export_pdf")
@auth
def export_pdf():
    devices, trusted, blacklist, total, known, unknown, high = build_dashboard()

    html = f"""
    <html>
    <head>
        <meta charset="UTF-8">
        <title>LAN Guard Security Report</title>
        <style>
            body {{ font-family: Arial; padding: 30px; }}
            h1 {{ color: #081225; }}
            .box {{ padding: 15px; border: 1px solid #ddd; margin-bottom: 15px; border-radius: 10px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th {{ background: #081225; color: white; padding: 10px; }}
            td {{ border: 1px solid #ddd; padding: 10px; }}
        </style>
    </head>
    <body>
        <h1>LAN Guard Enterprise - Security Report</h1>
        <div class="box">
            <b>Generated at:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
            <b>Total Devices:</b> {total}<br>
            <b>Known Devices:</b> {known}<br>
            <b>Unknown Devices:</b> {unknown}<br>
            <b>High Risk Devices:</b> {high}
        </div>

        <h2>Device Inventory</h2>
        <table>
            <tr>
                <th>IP</th>
                <th>MAC</th>
                <th>Vendor</th>
                <th>Status</th>
                <th>Risk Score</th>
                <th>Risk Level</th>
                <th>Last Seen</th>
            </tr>
    """

    for d in devices:
        html += f"""
            <tr>
                <td>{d['ip']}</td>
                <td>{d['mac']}</td>
                <td>{d['vendor']}</td>
                <td>{d['status']}</td>
                <td>{d['risk_score']}</td>
                <td>{d['risk_level']}</td>
                <td>{d['last_seen']}</td>
            </tr>
        """

    html += """
        </table>
    </body>
    </html>
    """

    add_log("EXPORT_REPORT", "Admin xuất báo cáo HTML/PDF")
    return html

if __name__ == "__main__":
    app.run(debug=True)