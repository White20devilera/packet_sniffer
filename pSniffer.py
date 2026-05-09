import scapy.all as scapy
from scapy.layers import http

def show_banner():
    print(r'''
    =========================================================================
      ____  _   _ ___ _____ _____ _____ ____  
     / ___|| \ | |_ _|  ___|  ___| ____|  _ \ 
     \___ \|  \| || || |_  | |_  |  _| | |_) |
      ___) | |\  || ||  _| |  _| | |___|  _ < 
     |____/|_| \_|___|_|   |_|   |_____|_| \_\
                                               
     [ Cyb-Weapons Lab | Advanced Packet Sniffer ]
     [ Created by White20devilera ]
    =========================================================================
    ''')

def process_packet(packet):
    # checking whether IP layer exists (to obtain IP, Source, Destination)
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        # If HTTP layer exists ( to capture Web requests/Passwords)
        if packet.haslayer(http.HTTPRequest):
            url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
            method = packet[http.HTTPRequest].Method.decode()
            print(f"\n[HTTP] {src_ip} -> {method} Request to: {url}")

            # Raw data (login details/ keylogger data) if exists
            if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load.decode(errors='ignore')
                # usually usernames passwords goes with keywords like this
                keywords = ["username", "user", "password", "pass", "login"]
                for keyword in keywords:
                    if keyword in load.lower():
                        print(f"\n[!!!] Possible Sensitive Data Found: \n{load}\n")
                        break

        # Showing usual tcp/udp packets
        elif packet.haslayer(scapy.TCP):
            print(f"[TCP] {src_ip}:{packet[scapy.TCP].sport} -> {dst_ip}:{packet[scapy.TCP].dport}")
        elif packet.haslayer(scapy.UDP):
            print(f"[UDP] {src_ip}:{packet[scapy.UDP].sport} -> {dst_ip}:{packet[scapy.UDP].dport}")

def start_sniffing(interface):
    print(f"[*] Sniffing started on interface: {interface}")
    print("[*] Press Ctrl+C to stop.\n")
    # count=0 means , until we stop, the script must run
    # store=False means to show data as soon as possible without filling up ram
    scapy.sniff(iface=interface, store=False, prn=process_packet)


show_banner()

try:
    start_sniffing(None) 
except KeyboardInterrupt:
    print("\n[!] Sniffing stopped. Saving results...")