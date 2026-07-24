from fastapi import APIRouter
from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from datetime import datetime

router = APIRouter()


@router.get("/capture/interfaces")
def capture_interfaces():
    return {
        "interfaces": get_if_list()
    }


@router.get("/capture/start")
def start_capture():

    packets = sniff(count=10)

    for pkt in packets:

        print("=" * 60)
        print(pkt.summary())

        # ---------------- IPv4 ----------------
        if pkt.haslayer(IP):
            print("IPv4 Packet")
            print("Source IP :", pkt[IP].src)
            print("Destination IP :", pkt[IP].dst)

        # ---------------- IPv6 ----------------
        elif pkt.haslayer(IPv6):
            print("IPv6 Packet")
            print("Source IP :", pkt[IPv6].src)
            print("Destination IP :", pkt[IPv6].dst)

        # ---------------- TCP ----------------
        if pkt.haslayer(TCP):

            print("TCP Packet")
            print("Source Port :", pkt[TCP].sport)
            print("Destination Port :", pkt[TCP].dport)

            print("TCP Flags :", pkt[TCP].flags)

            flags = str(pkt[TCP].flags)

            flag_meanings = {
                "S": "Connection Request (SYN)",
                "SA": "Connection Accepted (SYN-ACK)",
                "A": "Connection Established (ACK)",
                "PA": "Data Transfer (PSH-ACK)",
                "FA": "Connection Closing (FIN-ACK)",
                "R": "Connection Reset (RST)",
                "RA": "Connection Reset + ACK",
                "F": "Connection Closing (FIN)"
            }

            if flags in flag_meanings:
                print(flag_meanings[flags])
            else:
                print("Unknown TCP Flag")

            print("Sequence Number :", pkt[TCP].seq)
            print("Acknowledgement Number :", pkt[TCP].ack)
            print("Window Size :", pkt[TCP].window)

        print("Packet Length :", len(pkt), "Bytes")
        print("Capture Time :", datetime.now())

    return {
        "message": "10 packets captured successfully"
    }