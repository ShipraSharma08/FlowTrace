from fastapi import APIRouter
import socket
import psutil

router = APIRouter()

@router.get("/interfaces")
def get_interfaces():
    interfaces = []

    for name, addresses in psutil.net_if_addrs().items():
        ip = "No IP"

        for addr in addresses:
            if addr.family == socket.AF_INET:
                ip = addr.address

        interfaces.append({
            "name": name,
            "ip": ip
        })

    return {
        "interfaces": interfaces
    }