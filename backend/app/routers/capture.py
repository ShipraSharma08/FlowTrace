from fastapi import APIRouter
from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from datetime import datetime

from app.database.database import save_flow, get_all_flows
router = APIRouter(
    prefix="/capture",
    tags=["Packet Capture"]
)

sessions = {}
def decode_tcp_flags(flags):

    flag_map = {
        "S": "SYN",
        "SA": "SYN-ACK",
        "A": "ACK",
        "FA": "FIN-ACK",
        "PA": "PSH-ACK",
        "R": "RST"
    }

    return flag_map.get(flags, flags)

def process_packet(packet):
    if IP not in packet and IPv6 not in packet:
        return
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

    elif IPv6 in packet:
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst
    else:
        return
    if ICMP in packet:
        source_port = 0
        destination_port = 0
    elif TCP in packet:
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
    elif UDP in packet:
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
    
    packet_size = len(packet)
    tcp_flags = decode_tcp_flags(packet[TCP].sprintf("%TCP.flags%")) if TCP in packet else []
    endpoints = sorted([
        (source_ip, source_port),
        (destination_ip, destination_port)
    ])

    session_key = (
        endpoints[0][0],
        endpoints[0][1],
        endpoints[1][0],
        endpoints[1][1]
    )
    if session_key not in sessions:
        sessions[session_key] = {
                "packet_count": 1,
                "total_bytes": packet_size,
                "start_time": datetime.now(),
                "last_seen": datetime.now(),
                "state": "NEW",
                "handshake_complete": False,
                "tcp_flags": tcp_flags,
                "flag_history": [tcp_flags],
                "protocol": "ICMP" if ICMP in packet else "TCP" if TCP in packet else "UDP",
        }
    else:

        sessions[session_key]["packet_count"] += 1
        sessions[session_key]["total_bytes"] += packet_size
        sessions[session_key]["last_seen"] = datetime.now()
        sessions[session_key]["tcp_flags"] = tcp_flags
        if sessions[session_key]["flag_history"][-1] != tcp_flags:
            sessions[session_key]["flag_history"].append(tcp_flags)
        history = sessions[session_key]["flag_history"]
        if len(history) >= 3:
            if history[-3:] == ["SYN", "SYN-ACK", "ACK"]:
                sessions[session_key]["handshake_complete"] = True
                sessions[session_key]["state"] = "ESTABLISHED"
@router.get("/start")
def start_capture():
            sniff(
                prn=process_packet,
                store=False,
                filter="tcp or udp or icmp",
                count=20
            )
            return {"message": "Captured 20 packets successfully"}

@router.get("/flows")
def get_flows():
    flows = []
    for key, value in sessions.items():
        src_ip, src_port, dst_ip, dst_port = key
        duration = (value["last_seen"] - value["start_time"]).total_seconds()
        duration = round(duration, 2)
        idle_time = (datetime.now() - value["last_seen"]).total_seconds()
        status = "ACTIVE" if idle_time <= 5 else "IDLE"
        flows.append({
            "source_ip": src_ip,
            "source_port": src_port,
            "destination_ip": dst_ip,
            "destination_port": dst_port,
            "duration_seconds": duration,
            "status": status,
            **value
        })
    return flows

@router.get("/top-talkers")
def get_top_talkers():
    talkers = {}

    for key, value in sessions.items():
        source_ip = key[0]
        destination_ip = key[2]
        if source_ip not in talkers:
            talkers[source_ip] = 0
        talkers[source_ip] += value["packet_count"]
        if destination_ip not in talkers:
            talkers[destination_ip] = 0
        talkers[destination_ip] += value["packet_count"]
    return talkers
@router.get("/protocol-stats")
def get_protocol_stats():
    protocols = {
         "TCP": 0,
         "UDP": 0,
         "ICMP": 0,
         "Others": 0
        }
    for key, value in sessions.items():
        protocol = value["protocol"]
        protocols[protocol] += 1
    return protocols



 
 
    