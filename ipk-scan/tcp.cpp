/*
*	Raw TCP sockets
*/

#include "tcp.h"
#include "ipv6.h"

pcap_t* handle;

int PacketHandlerTcp(const u_char *packet)
{
    int size_ip;
    int size_tcp;
    struct sniff_ip *ip;
    const struct sniff_tcp *tcp;

    ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return 42;
    }


    tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return 42;
    }

    if (ip->ip_p != IPPROTO_TCP)
    {
        return 0;
    }

    if (tcp->th_flags & TH_RST)
    {
        return 1;
    }

    if (tcp->th_flags & TH_ACK)
    {
        return 2;
    }

    return 0;
}

void CatchTcpPacket(std::string name, int port, int &state, std::string typeOfProtocol)
{
    const u_char *packet;
    bpf_u_int32 netp;
    std::ostringstream oss;
    oss << "host " << name << " && tcp src port " << port;
    std::string var = oss.str();
    unsigned long n = var.length();
    char char_array[n + 1];
    strcpy(char_array, var.c_str());
    char *filter = char_array;
    struct pcap_pkthdr hdr{};
    struct bpf_program fp{};


    if(pcap_compile(handle,&fp,filter,0,netp) == -1)
    { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

    if(pcap_setfilter(handle,&fp) == -1)
    { fprintf(stderr,"Error setting filter\n"); exit(1); }

    while(true) {
        alarm(1);
        signal(SIGALRM, TcpLoopBreaker);
        packet = pcap_next(handle, &hdr);

        if (packet == nullptr) {
            break;
        }

        int code;
        if (typeOfProtocol == "ipv4")
        {
            code = PacketHandlerTcp(packet);
        }
        else
        {
            code = PacketHandlerIpv6Tcp(packet);
        }

        if (code == 0)
        {
            state = 0;
        }
        if (code == 1)
        {
            state = 1;
            break;
        }
        if (code == 2)
        {
            state = 2;
            break;
        }
    }

    pcap_freecode(&fp);
    pcap_close(handle);
}

void CreateRawTcpSocket(Arguments programArguments, int port)
{
    char datagram[4096];
    char *pseudogram;
    int one = 1;
    const int *val = &one;
    memset (datagram, 0, 4096);

    auto *iph = (struct iphdr *) datagram;
    auto *tcph = (struct tcphdr *) (datagram + sizeof (struct iphdr));
    struct sockaddr_in sin{};
    struct pseudo_header_tcp psh{};

    int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(s == -1)
    {
        perror("Failed to create socket");
        exit(1);
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons(1234);
    sin.sin_addr.s_addr = inet_addr (programArguments.ipAddress);

    PrepareIpHeaderForTcp(programArguments.interfaceIp, datagram, iph, sin);
    PrepareTcpHeader(tcph, static_cast<uint16_t>(port));
    pseudogram = CalculateTcpChecksum(programArguments.interfaceIp, pseudogram, tcph, sin, psh);

    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        exit(EXIT_FAILURE);
    }

    int c = 1;
    while (c>0) {
        if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
            perror("sendto failed");
        }
        c--;
    }

    free(pseudogram);
    close(s);
}

char *CalculateTcpChecksum(char *source_ip, char *pseudogram, tcphdr *tcph, sockaddr_in &sin,
                                pseudo_header_tcp &psh) {
    psh.source_address = inet_addr(source_ip );
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = 6;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header_tcp) + sizeof(struct tcphdr);
    pseudogram = (char *)malloc(psize);

    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header_tcp));
    memcpy(pseudogram + sizeof(struct pseudo_header_tcp) , tcph , sizeof(struct tcphdr));

    tcph->check = ComputeCheckSum((unsigned short *) pseudogram, psize);
    return pseudogram;
}

void PrepareIpHeaderForTcp(char *source_ip, char *datagram, iphdr *iph, sockaddr_in &sin) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 16;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
    iph->id = htonl (54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr ( source_ip );
    iph->daddr = sin.sin_addr.s_addr;
    iph->check = ComputeCheckSum((unsigned short *) datagram, (sizeof(struct iphdr) + sizeof(struct tcphdr)));
}

void PrepareTcpHeader(tcphdr *tcph, uint16_t port)
{
    tcph->source = htons (1234);
    tcph->dest = htons (port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons (32767);
    tcph->check = 0;
    tcph->urg_ptr = 0;
    tcph->th_urp = 0;
}

void PreparForTcpSniffing(char *interface)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_create(interface, errbuf);
    if(handle == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    if (pcap_activate(handle) != 0) {
        exit (EXIT_FAILURE);
    }
}

void TcpLoopBreaker(int sig)
{
    pcap_breakloop(handle);
}

unsigned short ComputeCheckSum(unsigned short *buffer, int size)
{
    unsigned long cksum=0;
    while(size >1)
    {
        cksum+=*buffer++;
        size -=sizeof(unsigned short);
    }
    if(size)
        cksum += *buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (unsigned short)(~cksum);
}