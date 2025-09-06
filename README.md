# PacketProbe 🚀

A lightweight Linux-native packet sniffer written in **C++17**, using **raw sockets**, **RAII**, and **STL**.  
Captures Ethernet, IP, TCP, and UDP headers — built with **CMake**, documented with **Doxygen**, and designed with **industry practices**.  
Now supports saving captured packets into **PCAP format** for analysis in **Wireshark** or **tshark**.

---

## ✨ Features
- Captures Ethernet + IP + TCP/UDP headers
- Real-time logs printed to terminal
- **PCAP output support** (`capture.pcap`) for Wireshark
- Built with CMake (cross-platform build system)
- RAII-based class design for safety
- Logging system with log levels
- Graceful shutdown via `Ctrl+C`
- Linux capabilities script (`setcap.sh`) to run without `sudo`

---

## ⚡ Build & Run
```bash
# Install dependencies
./scripts/setup.sh

# Build project
./scripts/build.sh

# Set capabilities (so you can run without sudo)
./scripts/setcap.sh

# Run sniffer
./build/packet_sniffer
```

---

## 📊 Example Output (Terminal)
```
[INFO] Packet Sniffer started... Press Ctrl+C to stop.
[INFO] Ethernet Frame:
   Source MAC: 08:00:27:14:1C:5F
   Destination MAC: 52:54:00:12:35:02
   Protocol: 8
   Source IP: 192.168.1.10
   Destination IP: 142.250.191.206
   TCP Src Port: 54321, Dst Port: 443
```

---

## 🗂 PCAP Capture
- All captured packets are also written to a file:  
  ```
  capture.pcap
  ```
- You can analyze this file using Wireshark or tshark:

### Wireshark (GUI)
```bash
wireshark capture.pcap
```

### tshark (CLI)
```bash
tshark -r capture.pcap
```

Example:
```
1   0.000000 192.168.1.10 → 142.250.191.206 TCP 54321 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460
2   0.002345 142.250.191.206 → 192.168.1.10 TCP 443 → 54321 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0
```

---

## 📜 Scripts
- `scripts/setup.sh` → installs dependencies (CMake, G++, GoogleTest)
- `scripts/build.sh` → clean build with CMake
- `scripts/setcap.sh` → sets Linux capabilities (`cap_net_raw,cap_net_admin`)

---

## 📈 Future Enhancements
- Protocol filtering (only TCP/UDP/ICMP)
- Multi-threaded capture and logging
- pcap-ng format support

---

