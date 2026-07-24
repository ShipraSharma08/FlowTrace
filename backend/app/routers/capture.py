from fastapi import APIRouter
from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from datetime import datetime

router = APIRouter()

# Session Storage
sessions = {}


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

        source_ip = None
        destination_ip = None

        # ---------------- IPv4 ----------------
        if pkt.haslayer(IP):
            source_ip = pkt[IP].src
            destination_ip = pkt[IP].dst

            print("IPv4 Packet")
            print("Source IP :", source_ip)
            print("Destination IP :", destination_ip)

        # ---------------- IPv6 ----------------
        elif pkt.haslayer(IPv6):
            source_ip = pkt[IPv6].src
            destination_ip = pkt[IPv6].dst

            print("IPv6 Packet")
            print("Source IP :", source_ip)
            print("Destination IP :", destination_ip)

        # ---------------- TCP ----------------
        if pkt.haslayer(TCP) and source_ip and destination_ip:

            print("TCP Packet")
            print("Source Port :", pkt[TCP].sport)
            print("Destination Port :", pkt[TCP].dport)

            session_key = (
                source_ip,
                pkt[TCP].sport,
                destination_ip,
                pkt[TCP].dport
            )

            print("Session Key :", session_key)

            # Create Session if not exists
            if session_key not in sessions:
                sessions[session_key] = {
                    "packet_count": 0,
                    "total_bytes": 0,
                    "start_time": datetime.now(),
                    "last_seen": datetime.now(),
                    "state": "New"
                }

            # Update Flow Statistics
            sessions[session_key]["packet_count"] += 1
            sessions[session_key]["total_bytes"] += len(pkt)
            sessions[session_key]["last_seen"] = datetime.now()

            # Calculate Flow Duration
            duration = (
                sessions[session_key]["last_seen"]
                - sessions[session_key]["start_time"]
            )

            # Print Flow Statistics
            print("Packet Count :", sessions[session_key]["packet_count"])
            print("Total Bytes :", sessions[session_key]["total_bytes"])
            print("Flow Duration :", duration)

            # TCP Information
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
            if flags == "S":
                sessions[session_key]["state"] = "SYN_SENT"
            if flags == "A":
                sessions[session_key]["state"] = "ESTABLISHED"
            if flags == "F" or flags == "FA":
                sessions[session_key]["state"] = "FIN_WAIT"
            if flags == "R" or flags == "RA":
                sessions[session_key]["state"] = "RESET"

            if flags in flag_meanings:
                print(flag_meanings[flags])
            else:
                print("Unknown TCP Flag")
            print("Current State :", sessions[session_key]["state"])

            print("Sequence Number :", pkt[TCP].seq)
            print("Acknowledgement Number :", pkt[TCP].ack)
            print("Window Size :", pkt[TCP].window)

        print("Packet Length :", len(pkt), "Bytes")
        print("Capture Time :", datetime.now())
        print("\n========== FLOW SUMMARY ==========")

    for session_key, data in sessions.items():

        print("\nSession :", session_key)
        print("Packets :", data["packet_count"])
        print("Bytes :", data["total_bytes"])
        print("Duration :", data["last_seen"] - data["start_time"])
        print("State :", data["state"])

        return {
        "message": "10 packets captured successfully"
    }