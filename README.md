# scapy_script

scapy_script.py is a powerful and advanced network security testing tool designed for Man-in-the-Middle (MITM) attacks. Developed using Scapy, this tool helps penetration testers and security researchers perform ARP Spoofing attacks, intercept network traffic, and analyze captured packets.

Features

1. ARP Spoofing Attack

Intercept and manipulate network traffic between the victim and the gateway.

Target individual devices or entire networks.


2. Data Interception & Sensitive Information Extraction

Capture HTTP POST data containing login forms and sensitive information.

Extract Cookies from network traffic.


3. Multi-Network Support

Supports small home Wi-Fi networks as well as large corporate networks.


4. HTTPS Interception (Optional)

Option to enable SSLstrip to analyze HTTPS traffic (requires root privileges).


5. Port Management & Process Termination

Detects processes using specific ports and automatically terminates them to prevent conflicts.


Usage

1. Clone the repository and run the script

git clone https://github.com/yourusername/scapy_script.git  
cd scapy_script  
python scapy_script.py -i <interface> <target_ip/network> <gateway_ip>

2. Usage Examples

Attack a single device

python scapy_script.py -i wlan0 192.168.1.100 192.168.1.1

Attack an entire Wi-Fi network

python scapy_script.py -i wlan0 192.168.1.0/24 192.168.1.1

Attack a medium-sized corporate network

python scapy_script.py -i eth0 172.16.0.0/16 172.16.0.1

Attack a large corporate network (dangerous)

python scapy_script.py -i eth0 10.0.0.0/8 10.0.0.1

Security & Responsibility

❗ Warning: scapy_script is intended for educational purposes and cybersecurity research only. It should only be used on networks where you have legal permission to conduct security testing. The developer is not responsible for any illegal or malicious use of this tool.

Contribution

We welcome contributions and improvements! You can:

Add new features and enhance the tool’s functionality.

Report bugs or security issues.

Optimize performance and security.


Disclaimer

This tool is designed for legal security testing only. Explicit authorization is required before testing any network. The developer is not liable for any misuse or damages caused by this tool.
