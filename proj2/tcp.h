#ifndef PROJ2_TCP_H
#define PROJ2_TCP_H
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
#include <unistd.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <error.h>
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

    int CreateRawSocket(const char *interface, std::string name, int port);

    unsigned short csum(unsigned short *ptr, int nbytes);

    int PacketHandler(const u_char *packet);

    int CatchPacket(std::string name, int port, pcap_t* descr, bpf_u_int32 netp);

    int hostname_to_ip(std::string hostname , char* ip);

    int PrepareTcpSocket(pcap_t* &handle, bpf_u_int32 &netp);

    int get_ip_from_interface(const char *interface , char* ip);

    void PrepareTcpHeader(tcphdr *tcph, uint16_t port) const;

    void PrepareIpHeader(const char *source_ip, const char *datagram, iphdr *iph, const sockaddr_in &sin);

    char *CalculateTcpChecksum(const char *source_ip, char *pseudogram, tcphdr *tcph, const sockaddr_in &sin,
                               pseudo_header_tcp &psh);
};
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

/* TCP header */
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
