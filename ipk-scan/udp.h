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

    int CreateRawUdpSocket(Arguments programArguments, int port);

    int CatchUdpPacket(Arguments programArguments, int &state);

    void PrepareIpHeader(char *source_ip, char *datagram, iphdr *iph, sockaddr_in &sin);

    void PrepareUdpHeader(uint16_t port, udphdr *udph);

    int PacketUdpHandler(const u_char *packet, char *source_ip, char *receiver_ip);
};

int PrepareForUdpSniffing(char *interface);

void LoopBreakerUdp(int sig);
#endif //PROJ2_UDP_H
