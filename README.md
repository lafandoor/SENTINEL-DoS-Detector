# SENTINEL: Real-Time DoS Detection System

SENTINEL is a professional-grade Network Intrusion Detection System (NIDS) designed to identify, analyze, and alert on Denial-of-Service (DoS) attack vectors in real-time. Built using Python and Scapy, this project demonstrates a robust implementation of threshold-based heuristic detection within a Linux environment.

**🔗 [View Live Forensic Dashboard]([https://lafandoor.github.io/sentinel-dos-detection/](https://lafandoor.github.io/SENTINEL-DoS-Detector/))**

## 🚀 Key Features

- **Multi-Vector Detection**: Real-time identification of TCP SYN Floods, UDP Volumetric attacks, and ICMP side-channel signals.
- **Heuristic Port Scan Tracking**: Advanced monitoring of unique port interaction density.
- **Forensic Dashboard**: A high-fidelity, noir-themed interactive dashboard featuring execution traces and a curated evidence registry.
- **Professional Documentation**: Includes a comprehensive formal security audit report detailing the simulation lifecycle and findings.

## 🛠️ Technical Architecture

- **Core Engine**: Python 3.12 with Scapy for asynchronous packet sniffing and protocol dissection.
- **State Management**: Stateless sliding-window logic (5s window) with alert cooldown mechanisms to prevent log saturation.
- **Forensics**: Integrated side-channel analysis (ICMP Port Unreachable) to validate real-world impact.
- **UI/UX**: Custom Vanilla CSS dashboard optimized for technical presentations and security audits.

## 📁 Repository Structure

- `dos_detector.py`: The primary detection engine.
- `index.html`: Interactive forensic dashboard.
- `formal_report.html`: Professional security audit report.
- `style.css`: Modern UI design system.
- `pics/`: A registry of 18 unique forensic screenshots documenting the validation protocol.

## 🚦 Getting Started

### Prerequisites
- Kali Linux (or any Debian-based distribution)
- Python 3.x
- Root/Sudo privileges (required for packet sniffing)

### Installation
1. Clone the repository:
   ```bash
   git clone <repo-url>
   cd sentinel-dos
   ```
2. Set up a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install scapy
   ```

### Running the Detector
```bash
sudo ./venv/bin/python dos_detector.py
```

## 🧪 Simulation Methodology
The system was validated using standard adversary simulation tools like `hping3` to generate synthetic high-rate traffic patterns across multiple protocols.

## ⚖️ Disclaimer
This project was developed for educational and security research purposes only. The tools and techniques described should only be used in authorized, controlled environments.

---
**Author**: Youssef Moataz  
**Goal**: Technical Portfolio Piece for Internship Submission
