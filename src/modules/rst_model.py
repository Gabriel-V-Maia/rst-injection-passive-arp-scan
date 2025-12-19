from scapy.all import IP, TCP

def build_rst(pkt):
    ip = pkt[IP]
    tcp = pkt[TCP]

    rst = IP(
        src=ip.dst,
        dst=ip.src
    ) / TCP(
        sport=tcp.dport,
        dport=tcp.sport,
        flags="R",
        seq=tcp.ack
    )

    return rst

