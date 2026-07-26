# 🚀 FlowTrace

FlowTrace is a Real-Time TCP Session Visualizer and Network Flow Analyzer built using Python, FastAPI, Scapy, and SQLite.

The project captures live network packets, groups them into communication sessions, analyses TCP behaviour, and provides useful network insights through REST APIs. It is designed as a learning-focused cybersecurity and computer networking project while following software engineering best practices.

## ✨ Current Features

- Live Packet Capture
- TCP Session Tracking
- TCP Handshake Detection
- TCP Flag Decoding
- Flow Duration Calculation
- Active / Idle Session Detection
- Top Talkers Analysis
- Protocol Statistics (TCP, UDP, ICMP)
## 🛠️ Tech Stack

### Backend
- Python
- FastAPI
- Scapy

### Database
- SQLite

### Networking Concepts
- TCP
- UDP
- ICMP
- IPv4
- IPv6
- TCP Flags
- Three-Way Handshake

### Tools
- VS Code
- Kali Linux
- Git
- GitHub
## 📁 Project Structure

```
FlowTrace/
├── app/
│   ├── database/
│   ├── routers/
│   ├── main.py
│   └── ...
├── README.md
├── requirements.txt
└── .gitignore
```
## ⚙️ Installation

1. Clone the repository

```bash
git clone <repository-url>
```

2. Move into the project directory

```bash
cd FlowTrace
```

3. Create a virtual environment

```bash
python -m venv .venv
```

4. Activate the virtual environment

**Linux / Kali**

```bash
source .venv/bin/activate
```

5. Install dependencies

```bash
pip install -r requirements.txt
```

6. Run the FastAPI server

```bash
uvicorn app.main:app --reload
```

---

## 📡 Available API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/capture/start` | Capture live packets |
| GET | `/capture/flows` | View captured sessions |
| GET | `/capture/top-talkers` | Show top communicating hosts |
| GET | `/capture/protocol-stats` | Display protocol statistics |

---

## 🔮 Future Enhancements

- Interactive Dashboard
- Live Packet Monitoring
- Charts and Analytics
- SQLite Flow History
- Export Reports
- DNS & HTTP Analysis
- Threat Detection
- PCAP File Support