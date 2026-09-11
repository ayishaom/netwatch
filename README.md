# NetWatch

NetWatch is a Python-based network monitoring and anomaly detection project.

The goal of the project is to analyze network traffic metadata, generate useful
traffic statistics, and identify potentially unusual network behavior using
simple and explainable detection rules.

## Project Goals

Through this project, I aim to gain practical experience with:

- Network traffic analysis
- TCP/IP networking
- Python
- Packet processing
- Network security monitoring
- Anomaly detection
- Testing and software architecture

## Planned Features

- Packet metadata extraction
- Network traffic statistics
- SQLite storage
- Port activity detection
- Traffic spike detection
- Security alerts
- Web dashboard

## Project Structure

```text
netWatch/
├── src/
│   └── netwatch/
│       ├── collector.py
│       ├── parser.py
│       ├── storage.py
│       ├── analyzer.py
│       └── detector.py
├── tests/
├── data/
├── requirements.txt
└── README.md