from flask import Flask, render_template, request, jsonify
import nmap
import scapy.all as scapy
import requests
import pandas as pd
import smtplib
from email.message import EmailMessage
from sklearn.preprocessing import MinMaxScaler
import numpy as np

app = Flask(__name__)

# Fetch latest vulnerabilities from CVE database
def fetch_cve_data():
    url = "https://cve.circl.lu/api/last"
    response = requests.get(url)
    return response.json() if response.status_code == 200 else []

# Scan network for IoT devices
def scan_network(network_range):
    arp_request = scapy.ARP(pdst=network_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = [{"IP": pkt[1].psrc, "MAC": pkt[1].hwsrc} for pkt in answered_list]
    return devices

# Scan ports & services of discovered IoT devices
def scan_ports(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, '1-65535', '-sV')
    return {port: scanner[ip]['tcp'][port]['name'] for port in scanner[ip]['tcp'] if scanner[ip]['tcp'][port]['state'] == 'open'}

# AI-based risk scoring for IoT devices
def calculate_risk_score(open_ports, cve_data):
    risk_scores = [sum(1 for cve in cve_data if service.lower() in cve.get("summary", "").lower()) for service in open_ports.values()]
    return round(np.mean(MinMaxScaler(feature_range=(1, 10)).fit_transform(np.array(risk_scores).reshape(-1, 1)).flatten()), 2) if risk_scores else 1

# Send email alert for high-risk devices
def send_alert(ip, mac, risk_score):
    if risk_score < 7:
        return

    sender_email, receiver_email, password = "your_email@gmail.com", "admin_email@gmail.com", "your_password"
    msg = EmailMessage()
    msg.set_content(f"⚠️ High-Risk IoT Device Detected!\n\nIP: {ip}\nMAC: {mac}\nRisk Score: {risk_score}/10\nPlease investigate immediately.")
    msg["Subject"], msg["From"], msg["To"] = "🚨 IoT Security Alert", sender_email, receiver_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, password)
            server.send_message(msg)
    except Exception as e:
        print(f"❌ Email alert failed: {e}")

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    network = request.form['network']
    devices, cve_data = scan_network(network), fetch_cve_data()
    results = []

    for device in devices:
        open_ports = scan_ports(device["IP"])
        risk_score = calculate_risk_score(open_ports, cve_data)
        results.append({"IP": device["IP"], "MAC": device["MAC"], "Ports": open_ports, "Risk Score": risk_score})
        if risk_score >= 7:
            send_alert(device["IP"], device["MAC"], risk_score)

    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)
