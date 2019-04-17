/*
*	Raw TCP sockets
*/

#include "tcp.h"

pcap_t* handle;

int TCP::PacketHandler(const u_char *packet)
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

    if (tcp->th_flags & TH_RST) {
        return 1;
    }

    if (tcp->th_flags & TH_ACK) {
        return 2;
    }

    return 0;
}

int TCP::CatchPacket(std::string name, int port, int& state)
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

    int c=1;
    while(c>0) {
        alarm(2);
        signal(SIGALRM, loop_breaker);
        packet = pcap_next(handle, &hdr);

        if (packet == nullptr) {
            break;
        }

        int code = PacketHandler(packet);

        if (code == 0)
        {
            state = 0;
        }
        if (code == 1)
        {
            state = 1;
        }
        if (code == 2)
        {
            state = 2;
        }
        c--;
    }

    pcap_freecode(&fp);
    pcap_close(handle);

    return 42;
}

int TCP::CreateRawSocket(const char *interface, std::string name, int port)
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
    sin.sin_addr.s_addr = inet_addr (receiver_ip);

    PrepareIpHeader(source_ip, datagram, iph, sin);
    PrepareTcpHeader(tcph, static_cast<uint16_t>(port));
    pseudogram = CalculateTcpChecksum(source_ip, pseudogram, tcph, sin, psh);

    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        return 1;
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
    return 0;
}

char *TCP::CalculateTcpChecksum(const char *source_ip, char *pseudogram, tcphdr *tcph, const sockaddr_in &sin,
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

void TCP::PrepareIpHeader(const char *source_ip, const char *datagram, iphdr *iph, const sockaddr_in &sin) {
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

void TCP::PrepareTcpHeader(tcphdr *tcph, uint16_t port) const {
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

int PrepareForSniffing()
{
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_create("wlp4s0", errbuf);
    if(handle == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    if (pcap_activate(handle) != 0) {
        exit (EXIT_FAILURE);
    }
}

void loop_breaker(int sig)
{
    pcap_breakloop(handle);
}

int hostname_to_ip(std::string hostname , char* ip)
{
    unsigned long n = hostname.length();
    char char_array[n + 1];
    strcpy(char_array, hostname.c_str());
    struct hostent *he;
    struct in_addr **addr_list;
    int i;

    if ( (he = gethostbyname( char_array ) ) == nullptr)
    {
        herror("gethostbyname");
        exit(EXIT_FAILURE);
    }

    addr_list = (struct in_addr **) he->h_addr_list;
    for(i = 0; addr_list[i] != nullptr; i++)
    {
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }
    return 1;
}

int get_ip_from_interface(const char *interface , char* ip)
{
    int fd;
    struct ifreq ifr{};

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    strcpy(ip , inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    return 0;
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