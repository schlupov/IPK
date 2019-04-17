/*
*	Raw UDP sockets
*/

#include <netdb.h>
#include "argument_parser.h"
#include <cstdio>
#include <ctime>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <error.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include "udp.h"
#include "tcp.h"

pcap_t* handler;

int UDP::PacketUdpHandler(const u_char *packet)
{
    int size_ip;
    struct sniff_ip *ip;
    const struct icmphdr *icmp;

    ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return 42;
    }

    icmp = (struct icmphdr *)(packet + SIZE_ETHERNET + size_ip);

    if (strcmp(inet_ntoa(ip->ip_dst), "46.28.109.159")==0)
    {
        return 5;
    }

    if ((icmp->type == 3) && (icmp->code == 3))
    {
        return 3;
    }
    return 4;
}

int UDP::CatchUdpPacket(std::string name, int &state)
{
    const u_char *packet;
    bpf_u_int32 netp;
    std::ostringstream oss;
    oss << "host " << name;
    std::string var = oss.str();
    unsigned long n = var.length();
    char char_array[n + 1];
    strcpy(char_array, var.c_str());
    char *filter = char_array;
    struct pcap_pkthdr hdr{};
    struct bpf_program fp{};


    if(pcap_compile(handler,&fp,filter,0,netp) == -1)
    { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

    if(pcap_setfilter(handler,&fp) == -1)
    { fprintf(stderr,"Error setting filter\n"); exit(1); }

    while(true) {

        alarm(3);
        signal(SIGALRM, loop_breaker_udp);
        packet = pcap_next(handler, &hdr);

        if (packet == nullptr) {
            break;
        }

        int code = PacketUdpHandler(packet);

        if (code == 3)
        {
            state = 3;
            break;
        }
        if (code == 4)
        {
            state = 4;
            break;
        }
    }

    pcap_freecode(&fp);
    pcap_close(handler);

    return 42;
}

int UDP::CreateRawUdpSocket(const char *interface, std::string name, int port)
{
    char receiver_ip[100];
    hostname_to_ip(name, receiver_ip);

    char source_ip[100];
    get_ip_from_interface(interface, source_ip);

    char datagram[4096];
    char *pseudogram;
    int one = 1;
    const int *val = &one;
    memset (datagram, 0, 4096);

    auto *iph = (struct iphdr *) datagram;
    auto *udph = (struct udphdr *)(datagram + sizeof (struct iphdr));
    struct sockaddr_in sin{};
    struct pseudo_header psh{};

    int s = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(s == -1)
    {
        perror("Failed to create raw socket");
        exit(1);
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons(1234);
    sin.sin_addr.s_addr = inet_addr (receiver_ip);

    PrepareIpHeader(source_ip, datagram, iph, sin);
    PrepareUdpHeader(static_cast<uint16_t>(port), udph);
    pseudogram = CalculateUdpChecksum(source_ip, pseudogram, udph, sin, psh);

    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        return 1;
    }

    int c=1;
    while (c>0)
    {
        if (sendto (s, datagram, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
        {
            perror("sendto failed");
        }
        c--;
    }

    free(pseudogram);
    close(s);
    return 0;
}

void UDP::PrepareUdpHeader(uint16_t port, udphdr *udph) const {
    udph->source = htons (1234);
    udph->dest = htons (port);
    udph->len = htons(sizeof(struct udphdr));
}

char *UDP::CalculateUdpChecksum(const char *source_ip, char *pseudogram, udphdr *udph, const sockaddr_in &sin,
                                 pseudo_header &psh) {
    psh.source_address = inet_addr(source_ip );
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr);
    pseudogram = (char *)malloc(psize);

    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr));

    udph->check = ComputeCheckSum( (unsigned short*) pseudogram , psize);
    return pseudogram;
}

void UDP::PrepareIpHeader(const char *source_ip, const char *datagram, iphdr *iph, const sockaddr_in &sin) const {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr);
    iph->id = htonl (54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr ( source_ip );
    iph->daddr = sin.sin_addr.s_addr;
    iph->check = ComputeCheckSum((unsigned short *) datagram, (sizeof(struct iphdr) + sizeof(struct udphdr)));
}

int PrepareForUdpSniffing()
{
    char errbuf[PCAP_ERRBUF_SIZE];

    handler = pcap_create("wlp4s0", errbuf);
    if(handler == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    if (pcap_activate(handler) != 0) {
        exit (EXIT_FAILURE);
    }
}

void loop_breaker_udp(int sig)
{
    pcap_breakloop(handler);
}