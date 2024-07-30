#include <pcap.h>
#include <iostream>
#include <netinet/in.h>
#include <libnet.h>
#include "headers.h"

void usage() {
    std::cout << "syntax: pcap-test <interface>\n";
    std::cout << "sample: pcap-test wlan0\n";
}

void print_eth(const libnet_ethernet_hdr* eth_hdr) {
    std::cout << "src MAC: ";
    for(int i = 0; i < ETHER_ADDR_LEN; ++i) {
        printf("%02x", eth_hdr->ether_shost[i]);
        if (i != ETHER_ADDR_LEN - 1) printf(":");
    }
    std::cout << "\ndst MAC: ";
    for(int i = 0; i < ETHER_ADDR_LEN; ++i) {
        printf("%02x", eth_hdr->ether_dhost[i]);
        if (i != ETHER_ADDR_LEN - 1) printf(":");
    }
    std::cout << std::endl;
}

void print_ipv4(const libnet_ipv4_hdr* ipv4_hdr) {
    std::cout << "src IP: " << inet_ntoa(ipv4_hdr->ip_src) << "\n";
    std::cout << "dst IP: " << inet_ntoa(ipv4_hdr->ip_dst) << std::endl;
}

void print_tcp(const libnet_tcp_hdr* tcp_hdr, const u_char* payload, int payload_len) {
    std::cout << "src port: " << ntohs(tcp_hdr->th_sport) << "\n";
    std::cout << "dst port: " << ntohs(tcp_hdr->th_dport) << "\n";
    std::cout << "data: ";
    for (int i = 0; i < 20 && i < payload_len; ++i) {
        printf("%02x ", payload[i]);
    }
    std::cout << "\n########################################\n";
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "pcap_open_live(" << dev << ") return nullptr - " << errbuf << std::endl;
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            std::cerr << "pcap_next_ex return " << res << " (" << pcap_geterr(handle) << ")\n";
            break;
        }

        libnet_ethernet_hdr* eth_hdr = (libnet_ethernet_hdr*)packet;
        if (ntohs(eth_hdr->ether_type) != 0x0800) continue; // Not IP

        libnet_ipv4_hdr* ipv4_hdr = (libnet_ipv4_hdr*)(packet + 14);
        if (ipv4_hdr->ip_p != IPPROTO_TCP) continue; // Not TCP

        int ip_hdr_len = ipv4_hdr->ip_hl * 4;
        libnet_tcp_hdr* tcp_hdr = (libnet_tcp_hdr*)(packet + 14 + ip_hdr_len);

        int tcp_hdr_len = tcp_hdr->th_off * 4;
        const u_char* payload = packet + 14 + ip_hdr_len + tcp_hdr_len;
        int payload_len = header->caplen - (14 + ip_hdr_len + tcp_hdr_len);

        std::cout << "----------------------------------------------------\n";
        print_eth(eth_hdr);
        print_ipv4(ipv4_hdr);
        print_tcp(tcp_hdr, payload, payload_len);
    }

    pcap_close(handle);
    return 0;
}

