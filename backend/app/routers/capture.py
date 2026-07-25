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
    packet_size = len(packet)
    tcp_flags = packet[TCP].sprintf("%TCP.flags%")
    session_key = (
        source_ip,
        source_port,
        destination_ip,
        destination_port
    )
    if session_key not in sessions:
        sessions[session_key] = {
                "packet_count": 1,
                "total_bytes": packet_size,
                "start_time": datetime.now(),
                "last_seen": datetime.now(),
                "state": "NEW",
                "tcp_flags": tcp_flags
        }
    else:

        sessions[session_key]["packet_count"] += 1
        sessions[session_key]["total_bytes"] += packet_size
        sessions[session_key]["last_seen"] = datetime.now()
        sessions[session_key]["tcp_flags"] = tcp_flags
@router.get("/start")
def start_capture():
            sniff(
                prn=process_packet,
                store=False,
                filter="tcp",
                count=20
            )
            return {"message": "Captured 20 TCP packets successfully"}

@router.get("/flows")
def get_flows():
    flows = []
    for key, value in sessions.items():
        src_ip, src_port, dst_ip, dst_port = key
        flows.append({
            "source_ip": src_ip,
            "source_port": src_port,
            "destination_ip": dst_ip,
            "destination_port": dst_port,
            **value
        })
    return flows
 
 
    