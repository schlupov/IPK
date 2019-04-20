#ifndef IPK_SCAN_TCP6_H
#define IPK_SCAN_TCP6_H
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_TCP, INET6_ADDRSTRLEN
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <netinet/ip6.h>      // struct ip6_hdr
#include <netinet/tcp.h>      // struct tcphdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <errno.h>            // errno, perror()
#include "tcp.h"

#define IP6_HDRLEN 40  // IPv6 header length
#define TCP_HDRLEN 20  // TCP header length, excludes options data
#define UDP_HDRLEN  8         // UDP header length, excludes data

class IPV6 {
public:

    int CreateRawSocket(Arguments programArguments, int port, std::string typeOfPacket);

    uint16_t tcp6_checksum (struct ip6_hdr, struct tcphdr);

    uint16_t udp6_checksum (struct ip6_hdr iphdr, struct udphdr udphdr);

    int PrepareTcp(int port, int *tcp_flags, ip6_hdr &iphdr, tcphdr &tcphdr, uint8_t *ether_frame);

    int PrepareUdp(int port, ip6_hdr &iphdr, udphdr &udphdr, uint8_t *ether_frame);

    char *allocate_strmem (int);

    uint8_t *allocate_ustrmem (int);

    int *allocate_intmem (int);

    uint16_t checksum (uint16_t *, int);
};
#endif //IPK_SCAN_TCP6_H
