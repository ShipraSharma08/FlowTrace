from fastapi import APIRouter
from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from datetime import datetime

from app.database.database import save_flow, get_all_flows

router = APIRouter(
    prefix="/capture",
    tags=["Packet Capture"]
)

sessions = {}
def process_packet(packet):

    if TCP not in packet:
        return

    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

    elif IPv6 in packet:
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst

    else:
        return

    source_port = packet[TCP].sport
    destination_port = packet[TCP].dport

    session_key = (
        source_ip,
        source_port,
        destination_ip,
        destination_port
    )

    current_time = datetime.now()

    if session_key not in sessions:

        sessions[session_key] = {
            "packet_count": 0,
            "total_bytes": 0,
            "start_time": current_time,
            "last_seen": current_time,
            flags = packet[TCP].flags

    if flags & 0x04:
        sessions[session_key]["state"] = "RESET"

    elif flags & 0x01:
        sessions[session_key]["state"] = "FIN_WAIT"

    elif flags & 0x02:
        sessions[session_key]["state"] = "SYN_SENT"

    elif flags & 0x10:
        sessions[session_key]["state"] = "ESTABLISHED"

        @router.get("/start")
def start_capture():

    sessions.clear()

    interfaces = get_if_list()

    interface = interfaces[0]

    sniff(
        iface=interface,
        prn=process_packet,
        count=10,
        store=False
    )

    print("\n========== FLOW SUMMARY ==========")

    for session_key, data in sessions.items():

        print("\nSession:", session_key)
        print("Packets:", data["packet_count"])
        print("Bytes:", data["total_bytes"])
        print("State:", data["state"])

        save_flow(
            session_key[0],
            session_key[2],
            session_key[1],
            session_key[3],
            data["packet_count"],
            data["total_bytes"],
            (data["last_seen"] - data["start_time"]).total_seconds(),
            data["state"],
            str(data["last_seen"])
        )

    return {
        "message": "10 packets captured successfully"
    }

    @router.get("/flows")
def get_flows():

    flows = get_all_flows()

    result = []

    for flow in flows:
        result.append({
            "id": flow[0],
            "source_ip": flow[1],
            "destination_ip": flow[2],
            "source_port": flow[3],
            "destination_port": flow[4],
            "packet_count": flow[5],
            "total_bytes": flow[6],
            "duration": flow[7],
            "state": flow[8],
            "capture_time": flow[9]
        })

    return result
            "state": "NEW"
        }

    sessions[session_key]["packet_count"] += 1
    sessions[session_key]["total_bytes"] += len(packet)
    sessions[session_key]["last_seen"] = current_time