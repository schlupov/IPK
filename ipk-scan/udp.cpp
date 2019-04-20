/*
*	Raw UDP sockets
*/

#include "udp.h"
#include "tcp.h"
#include "argument_parser.h"

pcap_t* handler;

int UDP::PacketUdpHandler(const u_char *packet, char *source_ip, char *receiver_ip)
{
    int size_ip;
    struct sniff_ip *ip;
    struct icmphdr *icmp;

    ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return 42;
    }

    icmp = (struct icmphdr *)(packet + SIZE_ETHERNET + size_ip);

    if (strcmp(inet_ntoa(ip->ip_dst), receiver_ip)==0 && strcmp(source_ip, receiver_ip)!=0)
    {
        return 5;
    }

    if (ip->ip_p != IPPROTO_ICMP)
    {
        return 5;
    }

    if ((icmp->type == 3) && (icmp->code == 3))
    {
        return 3;
    }
    return 4;
}

int UDP::CatchUdpPacket(Arguments programArguments, int &state)
{
    const u_char *packet;
    bpf_u_int32 netp;
    std::ostringstream oss;
    oss << "host " << programArguments.name;
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

        alarm(2);
        signal(SIGALRM, LoopBreakerUdp);
        packet = pcap_next(handler, &hdr);

        if (packet == nullptr) {
            break;
        }

        int code = PacketUdpHandler(packet, programArguments.interfaceIp, programArguments.ipAddress);

        if (code == 3)
        {
            state = 3;
            break;
        }
        if (code == 4)
        {
            state = 4;
        }
    }

    pcap_freecode(&fp);
    pcap_close(handler);

    return 42;
}

int UDP::CreateRawUdpSocket(Arguments programArguments, int port)
{
    char datagram[4096];
    int one = 1;
    const int *val = &one;
    memset (datagram, 0, 4096);

    auto *iph = (struct iphdr *) datagram;
    auto *udph = (struct udphdr *)(datagram + sizeof (struct iphdr));
    struct sockaddr_in sin{};

    int s = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(s == -1)
    {
        perror("Failed to create raw socket");
        exit(EXIT_FAILURE);
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons(1234);
    sin.sin_addr.s_addr = inet_addr (programArguments.ipAddress);

    PrepareIpHeader(programArguments.interfaceIp, datagram, iph, sin);
    PrepareUdpHeader(static_cast<uint16_t>(port), udph);

    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        exit(EXIT_FAILURE);
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

    close(s);
    return 0;
}

void UDP::PrepareUdpHeader(uint16_t port, udphdr *udph)
{
    udph->source = htons (1234);
    udph->dest = htons (port);
    udph->len = htons(sizeof(struct udphdr));
}

void UDP::PrepareIpHeader(char *source_ip, char *datagram, iphdr *iph, sockaddr_in &sin)
{
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

int PrepareForUdpSniffing(char *interface)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    handler = pcap_create(interface, errbuf);
    if(handler == nullptr)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    if (pcap_activate(handler) != 0) {
        exit (EXIT_FAILURE);
    }
}

void LoopBreakerUdp(int sig)
{
    pcap_breakloop(handler);
}