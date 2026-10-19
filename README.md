# Network Anomaly Detector

## Overview

Network Anomaly Detector is a Python-based mini intrusion detection system (IDS) developed to identify selected network activity that may indicate suspicious behavior.

The project uses Scapy for packet inspection, Python-based detection logic, SQLite for storing alerts, and Flask to display stored alerts through a web dashboard.

## Features

- **TCP port-scan detection:** Tracks distinct destination ports for source and destination IP pairs within a time window.
- **SYN-flood detection:** Counts initial TCP SYN packets within a configured time window and generates a possible SYN-flood alert when a threshold is reached.
- **SQLite alert storage:** Stores alert details, including timestamps, source IP, destination IP, alert type, and severity.
- **Flask dashboard:** Displays stored alerts in a web-based table.
- **Automated tests:** Includes tests for SYN-flood detection and alert storage.

## Technologies

- Python
- Scapy
- Flask
- SQLite
- HTML

## Project Structure

```text
network-anomaly-detector/
├── app.py
├── database.py
├── sniffer.py
├── syn_flood_detector.py
├── test_database.py
├── test_alert_storage.py
├── test_syn_flood.py
└── templates/
    └── index.html
```

## Requirements

- Python 3
- Scapy
- Flask
- Appropriate permissions for packet capture
- A Linux environment is recommended for the packet-capture workflow used during development

## Setup

Create and activate a virtual environment if one does not already exist:

```bash
python3 -m venv ven3
source ven3/bin/activate
```

Install the required packages:

```bash
pip install scapy flask
```

## Running the Project

### 1. Run the TCP port-scan detector

```bash
sudo ./ven3/bin/python3 sniffer.py
```

This starts packet capture and checks TCP traffic for multiple distinct destination ports within the configured time window.

### 2. Run the SYN-flood detector

```bash
sudo ./ven3/bin/python3 syn_flood_detector.py
```

This starts packet capture and counts initial SYN packets within the configured window. When the configured threshold is reached, the detector generates a possible SYN-flood alert and stores it in SQLite.

### 3. Start the Flask dashboard

In a separate terminal:

```bash
./ven3/bin/python3 app.py
```

Open the dashboard in a browser:

http://127.0.0.1:5000

## Running Tests

Run the tests from the project directory:

```bash
./ven3/bin/python3 test_syn_flood.py
./ven3/bin/python3 test_database.py
./ven3/bin/python3 test_alert_storage.py
```

These tests exercise detection logic and database behavior. Synthetic packet tests do not, by themselves, demonstrate detection of a real network attack.

## Limitations

- The port-scan detector currently examines TCP packets and uses a simple threshold-based heuristic.
- The SYN-flood detector uses a configurable packet-count threshold and time window. These values are illustrative and may need adjustment for different networks.
- A detection alert indicates potentially suspicious activity, not proof of a malicious attack.
- Detection results depend on packet visibility, capture permissions, and the network environment.
- Telegram notifications and any additional features should only be considered implemented if they have been independently verified.

## Project Status

The detection logic, SQLite alert storage, and Flask dashboard have been exercised during development. Further live-network testing and improvements to detection accuracy remain possible future work.
