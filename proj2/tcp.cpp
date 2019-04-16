#include <netdb.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include "tcp.h"

#define SIZE_ETHERNET 14

int TCP::my_packet_handler(const u_char* packet) {
    int size_ip;
    int size_tcp;
    struct sniff_ip *ip;
    const struct sniff_tcp *tcp;

    ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return 1;
    }

    switch (ip->ip_p) {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return 0;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return 0;
        case IPPROTO_IP:
            printf("   Protocol: IP\n");
            return 0;
        default:
            printf("   Protocol: unknown\n");
            return 0;
    }

    tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return 1;
    }

    if ((tcp->th_flags & TH_ACK) && (tcp->th_flags & TH_SYN)) {
        printf("   Flag: TH_ACK and TH_SYN\n");
        return 1;
    }
    if (tcp->th_flags & TH_RST) {
        printf("   Flag: TH_RST\n");
        return 1;
    }
    if (tcp->th_flags & TH_SYN) {
        printf("   Flag: TH_SYN\n");
        return 0;
    }
}

int TCP::PrepareTcpSocket(pcap_t* &handle, bpf_u_int32 &netp)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_create("wlp4s0", errbuf);
    if(handle == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    if (pcap_set_timeout(handle, 500) != 0) {
        exit (EXIT_FAILURE);
    }

    if (pcap_activate(handle) != 0) {
        exit (EXIT_FAILURE);
    }
}


int TCP::CatchPacket(pcap_t* handle, bpf_u_int32 netp)
{
    const u_char *packet;
    char filter[] = "host www.nemeckay.net && port 1234 && tcp";
    struct pcap_pkthdr hdr;
    struct bpf_program fp;

    if(pcap_compile(handle,&fp,filter,0,netp) == -1)
    { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

    if(pcap_setfilter(handle,&fp) == -1)
    { fprintf(stderr,"Error setting filter\n"); exit(1); }

    while(true) {
        packet = pcap_next(handle, &hdr);

        if (packet == NULL) {
            break;
        }

        int code = my_packet_handler(packet);
        if (code != 0){
            break;
        }
    }

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}

unsigned short TCP::csum(unsigned short *buffer, int size)

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

int TCP::CreateRawSocket(Arguments programArguments)
{
    char receiver_ip[100];
    hostname_to_ip(programArguments.name, receiver_ip);

    char source_ip[100];
    const char *interface = programArguments.interface;
    get_ip_from_interface(interface, source_ip);

    int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);

    if(s == -1)
    {
        perror("Failed to create socket");
        exit(1);
    }

    char datagram[8192];
    char *pseudogram;

    memset (datagram, 0, 8192);

    struct iphdr *iph = (struct iphdr *) datagram;

    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct iphdr));
    struct sockaddr_in sin;
    struct pseudo_header_tcp psh;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(1234);
    sin.sin_addr.s_addr = inet_addr (receiver_ip);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 16;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
    iph->id = htonl (54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = 6;
    iph->check = 0;
    iph->saddr = inet_addr ( source_ip );
    iph->daddr = sin.sin_addr.s_addr;

    //Ip checksum
    iph->check = csum ((unsigned short *) datagram, (sizeof(struct iphdr) + sizeof(struct tcphdr)));

    //TCP Header
    tcph->source = htons (1234);
    tcph->dest = htons (22);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;	//tcp header size
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

    //Now the TCP checksum
    psh.source_address = inet_addr( source_ip );
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = 6;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header_tcp) + sizeof(struct tcphdr);
    pseudogram = (char *)malloc(psize);

    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header_tcp));
    memcpy(pseudogram + sizeof(struct pseudo_header_tcp) , tcph , sizeof(struct tcphdr));

    tcph->check = csum( (unsigned short*) pseudogram , psize);

    int one = 1;
    const int *val = &one;

    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        exit(0);
    }

    int c = 1;
    while (c>0) {
        if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
            perror("sendto failed");
        }
        else
            printf("Packet Send. Length : %d \n", iph->tot_len);
        c--;
    }

    close(s);
    return 0;
}


int TCP::hostname_to_ip(std::string hostname , char* ip)
{
    unsigned long n = hostname.length();
    char char_array[n + 1];
    strcpy(char_array, hostname.c_str());

    struct hostent *he;
    struct in_addr **addr_list;
    int i;

    if ( (he = gethostbyname( char_array ) ) == NULL)
    {
        herror("gethostbyname");
        return 1;
    }

    addr_list = (struct in_addr **) he->h_addr_list;

    for(i = 0; addr_list[i] != NULL; i++)
    {
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }

    return 1;
}

int TCP::get_ip_from_interface(const char *interface , char* ip)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    /* I want to get an IPv4 IP address */
    ifr.ifr_addr.sa_family = AF_INET;

    /* I want IP address attached to "eth0" */
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    strcpy(ip , inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    return 0;
}

