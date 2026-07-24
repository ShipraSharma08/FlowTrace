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
    packet = sniff(count=1)

    print(packet[0].summary())

    if packet[0].haslayer(IP):
        print("IPv4 Packet")
        print("Source IP :", packet[0][IP].src)
        print("Destination IP :", packet[0][IP].dst)

    elif packet[0].haslayer(IPv6):
        print("IPv6 Packet")
        print("Source IP :", packet[0][IPv6].src)
        print("Destination IP :", packet[0][IPv6].dst)

    if packet[0].haslayer(TCP):
        print("TCP Packet")
        print("Source Port :", packet[0][TCP].sport)
        print("Destination Port :", packet[0][TCP].dport)
        print("TCP Flags :", packet[0][TCP].flags)

        flags = str(packet[0][TCP].flags)

        flag_meanings = {
            "S": "Connection Request (SYN)",
            "SA": "Connection Accepted (SYN-ACK)",
            "A": "Connection Established (ACK)",
            "PA": "Data Transfer (PSH-ACK)",
            "FA": "Connection Closing (FIN-ACK)",
            "RA": "Connection Reset (RST-ACK)"
        }

        if flags in flag_meanings:
            print(flag_meanings[flags])
        else:
            print("Unknown TCP Flag")

        print("Sequence Number :", packet[0][TCP].seq)
        print("Acknowledgement Number :", packet[0][TCP].ack)
        print("Window Size :", packet[0][TCP].window)
        print("Packet Length :", len(packet[0]), "Bytes")
        print("Capture Time :", datetime.now())

    return {
        "message": "1 packet captured"
    }