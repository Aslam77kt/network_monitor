Network Monitoring Tool
A simple network monitoring tool built with Python, Flask, and JavaScript to monitor network traffic, bandwidth usage, and latency in real-time.
Features

Real-time bandwidth monitoring (sent/received in MB/s)
Packet count tracking using Scapy
Latency measurement to a specified host
Web-based dashboard with live charts
Logging of network statistics
Support for multiple network interfaces

Prerequisites

Python 3.7+
pip for installing dependencies
Administrative/root privileges for packet sniffing

Installation

Clone the repository:

git clone <repository-url>
cd network-monitor


Install dependencies:

pip install psutil scapy flask


Create a templates directory and place index.html in it:

mkdir templates
mv index.html templates/

Usage

Run the application (requires root privileges for packet sniffing):

sudo python network_monitor.py


Access the dashboard at http://localhost:5000

Configuration

Modify the interface variable in network_monitor.py to match your network interface (e.g., 'eth0', 'wlan0').
Adjust the host parameter in the measure_latency function to ping a different server.
Update the Flask port or host in the app.run() call if needed.

Notes

Ensure you have the necessary permissions to sniff packets (root/admin).
The tool logs data to network_monitor.log for debugging and analysis.
The dashboard updates every 2 seconds with the latest metrics.
Charts retain the last 50 data points for performance.

Contributing
Contributions are welcome! Please submit a pull request or open an issue on GitHub.
License
MIT License
