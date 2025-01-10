# Network Traffic Dashboard
# A real-time network traffic dashboard built using Python and Streamlit.

# Overview
This dashboard provides a comprehensive view of network traffic, including packet capture, protocol analysis, and anomaly detection. It uses the Scapy library to capture network packets and the Streamlit library to create a interactive dashboard.

# Features
Real-time packet capture and analysis
Protocol analysis (TCP, UDP, ICMP, etc.)
Anomaly detection using Isolation Forest algorithm
Geographical IP mapping using GeoIP database
Customizable alerts and notifications
Interactive dashboard with filtering and sorting capabilities

# Requirements
Python 3.8+
Scapy library (for packet capture and analysis)
Streamlit library (for dashboard creation)
GeoIP database (for geographical IP mapping)
Isolation Forest library (for anomaly detection)

# Installation
Clone the repository: git clone https://github.com/dcarter7279/network-traffic-dashboard.git
Install the required libraries: pip install scapy streamlit geoip2 isolation-forest
Run the dashboard: streamlit run dashboard.py

# Usage
Open the dashboard in your web browser: http://localhost:8501
Select the network interface to capture packets from
Configure the packet capture settings (e.g., packet size, capture duration)
View the packet capture data in the dashboard
Analyze the packet data using the protocol analysis and anomaly detection features
Configure custom alerts and notifications

# Troubleshooting
Check the console output for any errors or warnings
Verify that the Scapy library is installed and configured correctly
Ensure that the GeoIP database is installed and configured correctly
Check the dashboard logs for any errors or warnings

# License
This project is licensed under the MIT License. See the LICENSE file for more information.

# Contributing
Contributions are welcome! Please submit a pull request with your changes and a brief description of what you've changed.
