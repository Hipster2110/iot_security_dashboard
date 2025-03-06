# iot_security_dashboard
# Secure IoT Network Scanner

## Overview
The **Secure IoT Network Scanner** is an advanced Python-based tool with a Flask web interface, designed to:
- Detect IoT devices on a network.
- Scan open ports and services.
- Assess security risks using AI-based risk scoring.
- Fetch the latest vulnerabilities from the CVE database.
- Send email alerts for high-risk devices.

## Features
- **Network Scanning**: Uses ARP requests to identify IoT devices.
- **Port & Service Detection**: Leverages Nmap to find open ports and services.
- **AI Risk Scoring**: Evaluates IoT device security risks based on CVE data.
- **Web Dashboard**: Interactive Flask-based UI for easy scanning and monitoring.
- **Email Alerts**: Sends notifications for high-risk IoT devices.

## Prerequisites
Ensure you have the following dependencies installed:

- **Python 3.x**
- **Scapy** (`pip install scapy`)
- **Nmap** (`apt install nmap` or `brew install nmap`)
- **python-nmap** (`pip install python-nmap`)
- **Flask** (`pip install flask`)
- **Requests** (`pip install requests`)
- **Scikit-learn** (`pip install scikit-learn`)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/Hipster2110/iot_security_dashboard.git
   cd iot_security_dashboard
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the Flask server:
   ```bash
   sudo python app.py
   ```
   > **Note:** Running as **root** is required for network scanning.

## Usage
1. Open the web interface in your browser:
   ```
   http://127.0.0.1:5000/
   ```
2. Enter the network range (e.g., `192.168.1.1/24`).
3. Click **Scan** to:
   - Detect IoT devices.
   - Identify open ports & services.
   - Calculate AI-based risk scores.
   - Send email alerts for high-risk devices.

## Example Output (JSON Response)
```json
[
    {
        "IP": "192.168.1.10",
        "MAC": "AA:BB:CC:DD:EE:FF",
        "Ports": {"22": "ssh", "80": "http"},
        "Risk Score": 8.5
    }
]
```

## Known Issues
- Requires **sudo/root** privileges for full functionality.
- Email alerts require valid SMTP credentials.
- Large network scans may take time.

## Future Enhancements
- **Device fingerprinting** to detect specific IoT device types.
- **Automated vulnerability scanning** for detected services.
- **Integration with a threat intelligence platform**.

## License
This project is licensed under the MIT License.

## Author
Developed by **Hipster2110**. Contributions and feedback are welcome!

## Repository Link
[GitHub Repository](https://github.com/Hipster2110/iot_security_dashboard.git)

## Disclaimer
This tool is intended for **ethical security testing** only. Do not use it on networks without proper authorization!

