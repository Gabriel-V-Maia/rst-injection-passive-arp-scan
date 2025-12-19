from scapy.all import ARP

discovered_hosts = set()

def process_packet(packet):
    if ARP not in packet:
        return

    for ip in (packet[ARP].psrc, packet[ARP].pdst):
        if ip not in discovered_hosts:
            discovered_hosts.add(ip)
            print(f"[ARP] {ip}")


