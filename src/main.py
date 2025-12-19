from scapy.all import sniff
from modules.arp_listener import process_packet
from modules.tcp_observer import handle_tcp

def dispatch(pkt):
    process_packet(pkt)
    handle_tcp(pkt)

def main():
    print("[*] Iniciando")
    sniff(
        filter="arp or tcp",
        prn=dispatch,
        store=False
    )

if __name__ == "__main__":
    main()


