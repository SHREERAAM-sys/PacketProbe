#include <iostream>
#include <vector>
#include <cstring>
#include <csignal>
#include <fstream>
#include <chrono>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include "logger.h"

// PCAP Global Header structure
struct PcapFileHeader {
    uint32_t magic_number = 0xa1b2c3d4; // magic number
    uint16_t version_major = 2;        // major version number
    uint16_t version_minor = 4;        // minor version number
    int32_t thiszone = 0;              // GMT to local correction
    uint32_t sigfigs = 0;              // accuracy of timestamps
    uint32_t snaplen = 65535;          // max length of captured packets
    uint32_t network = 1;              // data link type (Ethernet)
};

// PCAP per-packet header
struct PcapPacketHeader {
    uint32_t ts_sec;   // timestamp seconds
    uint32_t ts_usec;  // timestamp microseconds
    uint32_t incl_len; // number of octets of packet saved in file
    uint32_t orig_len; // actual length of packet
};

class PacketSniffer {
private:
    int sock_raw;
    std::vector<uint8_t> buffer;
    bool running;
    std::ofstream pcapFile;

public:
    PacketSniffer(const std::string &outfile = "capture.pcap") 
        : buffer(65536), running(true) {
        sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sock_raw < 0) {
            perror("Socket Error");
            exit(1);
        }
        Logger::info("Packet Sniffer started... Press Ctrl+C to stop.");

        // Open PCAP file
        pcapFile.open(outfile, std::ios::binary);
        if (!pcapFile.is_open()) {
            Logger::error("Failed to open PCAP file for writing.");
            exit(1);
        }
        // Write global header
        PcapFileHeader global_header;
        pcapFile.write(reinterpret_cast<char*>(&global_header), sizeof(global_header));
    }

    ~PacketSniffer() {
        close(sock_raw);
        if (pcapFile.is_open()) {
            pcapFile.close();
        }
        Logger::info("Packet Sniffer stopped.");
    }

    void stop() { running = false; }

    void run() {
        struct sockaddr saddr;
        socklen_t saddr_size = sizeof(saddr);

        while (running) {
            int data_size = recvfrom(sock_raw, buffer.data(), buffer.size(), 0,
                                     &saddr, &saddr_size);
            if (data_size < 0) {
                perror("Recvfrom error");
                exit(1);
            }
            process_packet(buffer.data(), data_size);
            save_to_pcap(buffer.data(), data_size);
        }
    }

private:
    void save_to_pcap(const uint8_t *data, int size) {
        if (!pcapFile.is_open()) return;

        // Get timestamp
        auto now = std::chrono::system_clock::now();
        auto sec = std::chrono::time_point_cast<std::chrono::seconds>(now);
        auto usec = std::chrono::duration_cast<std::chrono::microseconds>(now - sec).count();

        PcapPacketHeader pkt_header;
        pkt_header.ts_sec = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::seconds>(sec.time_since_epoch()).count()
        );
        pkt_header.ts_usec = static_cast<uint32_t>(usec);
        pkt_header.incl_len = size;
        pkt_header.orig_len = size;

        // Write header + data
        pcapFile.write(reinterpret_cast<char*>(&pkt_header), sizeof(pkt_header));
        pcapFile.write(reinterpret_cast<const char*>(data), size);
    }

    void print_mac(const uint8_t *addr) {
        for (int i = 0; i < 6; i++) {
            std::cout << std::hex << std::uppercase << (int)addr[i];
            if (i != 5) std::cout << ":";
        }
        std::cout << std::dec;
    }

    void process_packet(const uint8_t *buffer, int size) {
        struct ethhdr *eth = (struct ethhdr *)buffer;

        Logger::info("Ethernet Frame:");
        std::cout << "   Source MAC: "; print_mac(eth->h_source); std::cout << "\n";
        std::cout << "   Destination MAC: "; print_mac(eth->h_dest); std::cout << "\n";
        std::cout << "   Protocol: " << ntohs(eth->h_proto) << "\n";

        if (ntohs(eth->h_proto) == ETH_P_IP) {
            struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
            struct sockaddr_in src, dest;
            src.sin_addr.s_addr = ip->saddr;
            dest.sin_addr.s_addr = ip->daddr;

            std::cout << "   Source IP: " << inet_ntoa(src.sin_addr) << "\n";
            std::cout << "   Destination IP: " << inet_ntoa(dest.sin_addr) << "\n";

            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = (struct tcphdr *)(buffer + ip->ihl * 4 + sizeof(struct ethhdr));
                std::cout << "   TCP Src Port: " << ntohs(tcp->source)
                          << ", Dst Port: " << ntohs(tcp->dest) << "\n";
            } else if (ip->protocol == IPPROTO_UDP) {
                struct udphdr *udp = (struct udphdr *)(buffer + ip->ihl * 4 + sizeof(struct ethhdr));
                std::cout << "   UDP Src Port: " << ntohs(udp->source)
                          << ", Dst Port: " << ntohs(udp->dest) << "\n";
            }
        }
    }
};

// Global instance for signal handling
PacketSniffer* snifferInstance = nullptr;

void handle_signal(int signal) {
    if (snifferInstance) {
        Logger::warn("Interrupt received, stopping sniffer...");
        snifferInstance->stop();
    }
}

int main() {
    Logger::init("packetprobe.log");   // Initialize logger with file output

    PacketSniffer sniffer("capture.pcap");
    snifferInstance = &sniffer;

    signal(SIGINT, handle_signal);
    sniffer.run();

    Logger::shutdown();                //  Close log file safely
    return 0;
}


