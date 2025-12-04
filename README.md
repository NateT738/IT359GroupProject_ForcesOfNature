# IT359 Final Project: Automated MITM Attack Tool

**Group:** Forces of Nature
**Members:** Nathan Thomison, TJ Gerst
**Course:** IT359 - Penetration Testing

---

### Project Presentation
Video Link: https://youtu.be/aN27w8LvD60?si=pklfu90ixA6A2zSC

---

### Project Overview
This project demonstrates a **Man-in-the-Middle (MITM) attack** using ARP Poisoning. We developed a custom Python tool (`mitm_attack.py`) that leverages the **Scapy** library to intercept traffic between a Windows 11 victim and a pfSense gateway within a virtualized Proxmox environment.

The tool performs the following automated actions:
1.  **IP Forwarding:** Automatically enables Linux kernel IP forwarding to maintain the victim's internet connection.
2.  **ARP Spoofing:** Floods the victim's ARP cache to redirect traffic through the attacker machine.
3.  **Packet Sniffing:** Analyzes TCP traffic in real-time to identify and capture unencrypted credentials (HTTP POST/GET data).

### Repository Structure
The repository is organized as follows:
* `src/`: Contains the source code (`mitm_attack.py`).
* `docs/`: Contains the Final Project Report (PDF).
* `requirements.txt`: List of Python dependencies required to run the tool.
* `README.md`: Project documentation and usage guide.

### Setup & Installation

**Prerequisites**
* **Attacker Machine:** Kali Linux (or any Linux distro with Root privileges)
* **Victim Machine:** Windows 10/11
* **Network:** Both machines must be on the same local subnet.
* **Python:** Python 3.x

**Installation Steps**
1.  Clone the repository to the attacker machine:
    
        git clone https://github.com/NateT738/IT359GroupProject_ForcesOfNature.git
        cd IT359GroupProject_ForcesOfNature

2.  Install the required Python libraries:

        pip3 install -r requirements.txt

### Usage Guide

**1. Configuration**
Before running the tool, you must configure the target parameters. Open `src/mitm_attack.py` in a text editor:

    nano src/mitm_attack.py

Update the following variables at the top of the file to match your specific lab environment:
* `VICTIM_IP` & `VICTIM_MAC`: The IP and MAC address of the target machine.
* `GATEWAY_IP` & `GATEWAY_MAC`: The IP and MAC address of the router/gateway.

> **Note:** We utilize hardcoded MAC addresses in the configuration to ensure reliability within virtualized environments (like Proxmox) where dynamic ARP resolution can occasionally fail or time out.

**2. Execution**
Run the script with `sudo` permissions (required for raw packet injection):

    sudo python3 src/mitm_attack.py

**3. Attack Verification**
* **On the Victim Machine:** Navigate to an HTTP website (e.g., `http://testphp.vulnweb.com/login.php`) and attempt to log in.
* **On the Attacker Machine:** Watch the terminal output. The script will intercept the HTTP POST request and display the captured username and password in plain text.

**4. Stopping the Attack**
Press `CTRL+C` to stop the script. The tool will automatically attempt to "heal" the network by sending correct ARP packets to restore the victim's connection to the router.