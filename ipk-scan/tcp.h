#ifndef PROJ2_TCP_H
#define PROJ2_TCP_H
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
#include <unistd.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <error.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "argument_parser.h"

struct pseudo_header_tcp
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

class TCP {
public:

    int CreateRawSocket(Arguments programArguments, int port);

    int PacketHandler(const u_char *packet);

    int CatchPacket(std::string name, int port, int& state);

    void PrepareTcpHeader(tcphdr *tcph, uint16_t port) const;

    void PrepareIpHeader(char *source_ip, char *datagram, iphdr *iph,  sockaddr_in &sin);

    char *CalculateTcpChecksum(char *source_ip, char *pseudogram, tcphdr *tcph, sockaddr_in &sin,
                               pseudo_header_tcp &psh);
};

#define SIZE_ETHERNET 14

int PrepareForSniffing(char *interface);

unsigned short ComputeCheckSum(unsigned short *ptr, int nbytes);

void LoopBreaker(int sig);

struct sniff_ip {
    u_char ip_vhl;      /* version << 4 | header length >> 2 */
    u_char ip_tos;      /* type of service */
    u_short ip_len;     /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;     /* fragment offset field */
    #define IP_RF 0x8000        /* reserved fragment flag */
    #define IP_DF 0x4000        /* dont fragment flag */
    #define IP_MF 0x2000        /* more fragments flag */
    #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_char ip_ttl;      /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;     /* checksum */
    struct in_addr ip_src;
    struct in_addr ip_dst; /* source and dest address */
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
    #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_PUSH 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20
    #define TH_ECE  0x40
    #define TH_CWR  0x80
    #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};
#endif //PROJ2_TCP_H
