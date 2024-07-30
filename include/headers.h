#ifndef HEADERS_H
#define HEADERS_H

#include <libnet.h>

void print_eth(const libnet_ethernet_hdr* eth_hdr);
void print_ipv4(const libnet_ipv4_hdr* ipv4_hdr);
void print_tcp(const libnet_tcp_hdr* tcp_hdr, const u_char* payload, int payload_len);

#endif // HEADERS_H

