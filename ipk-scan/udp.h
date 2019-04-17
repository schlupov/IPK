#ifndef PROJ2_UDP_H
#define PROJ2_UDP_H
#include "argument_parser.h"
#include<cstdio>    //for printf
#include<cstring> //memset
#include<sys/socket.h>	//for socket ofcourse
#include<cstdlib> //for exit(0);
#include<cerrno> //For errno - the error number
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include <iostream>
#include <netinet/in.h>
#include <pcap.h>
#include <arpa/inet.h>

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

    int CatchUdpPacket(std::string name, int &state);

    void PrepareIpHeader(const char *source_ip, const char *datagram, iphdr *iph, const sockaddr_in &sin) const;

    void PrepareUdpHeader(uint16_t port, udphdr *udph) const;

    char *
    CalculateUdpChecksum(const char *source_ip, char *pseudogram, udphdr *udph, const sockaddr_in &sin, pseudo_header &psh);

    int PacketUdpHandler(const u_char *packet);
};

int PrepareForUdpSniffing();

void loop_breaker_udp(int sig);
#endif //PROJ2_UDP_H
