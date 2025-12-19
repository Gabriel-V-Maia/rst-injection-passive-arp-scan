from scapy.all import IP, TCP
from modules.rst_model import build_rst

def handle_tcp(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return

    tcp = pkt[TCP]

    if tcp.flags & 0x10:  # ACK
        rst_pkt = build_rst(pkt)

        ip = pkt[IP]
        print(
            "[TCP] RST modelado | "
            f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport} | "
            f"seq={tcp.ack}"
        )


