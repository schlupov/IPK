#ifndef PROJ2_UDP_H
#define PROJ2_UDP_H
#include "argument_parser.h"
#include<cstdio>
#include<cstring>
#include<sys/socket.h>
#include<cstdlib>
#include<cerrno>
#include<netinet/udp.h>
#include<netinet/ip.h>
#include <iostream>
#include <netinet/in.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <error.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/ip_icmp.h>

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

class UDP {
public:

    int CreateRawUdpSocket(const char *interface, std::string name, int port);

    int CatchUdpPacket(const char *interface, std::string name, int &state);

    void PrepareIpHeader(const char *source_ip, const char *datagram, iphdr *iph, const sockaddr_in &sin) const;

    void PrepareUdpHeader(uint16_t port, udphdr *udph) const;

    int PacketUdpHandler(const u_char *packet, char *source_ip, char *receiver_ip);
};

int PrepareForUdpSniffing(const char *interface);

void LoopBreakerUdp(int sig);
#endif //PROJ2_UDP_H
