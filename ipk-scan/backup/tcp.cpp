//
// Created by root on 4/14/19.
//

#include <netdb.h>
#include <netinet/if_ether.h>
#include "tcp.h"

#define SIZE_ETHERNET 16


int TCP::my_packet_handler(const struct pcap_pkthdr* header, const u_char* packet)
{
    //const struct tcphdr *tcp;
    u_char *payload;
    int size_payload;
    int size_ip;
    int size_tcp;
    struct sniff_ip *ip;
    const struct sniff_tcp *tcp;

    const struct sniff_ethernet *ethernet;

    //int ip_header_len = (*((char *)ip)) & 0x0F;
    //ip_header_len *= 4;


    ethernet = (struct sniff_ethernet*)(packet);

    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;

    /* determine protocol */
    switch(ip->ip_p) {
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

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return 0;
    }

    if (tcp->th_flags & TH_ACK) {
        printf("   Flag: TH_ACK\n");
    }
    if (tcp->th_flags & TH_RST) {
        printf("   Flag: TH_RST\n");
    }
    return 1;
}

void TCP::my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char *packet)
{

    int size_tcp;
    int size_ip;
    const struct tcphdr *tcp;
    u_char *payload;
    int size_payload;
    const struct sniff_ip *ip;
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));

    switch(ip->ip_p) {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        case IPPROTO_IP:
            printf("   Protocol: IP\n");
            return;
        default:
            printf("   Protocol: unknown\n");
            return;
    }

    struct ether_header *eth_header;

    eth_header = (struct ether_header *) packet;


    tcp = (struct tcphdr *) (packet + SIZE_ETHERNET + sizeof(*ip));

    if (strcmp(inet_ntoa(ip->ip_src),"46.28.109.159")==0) {
        if (tcp->ack) {
            printf("   Flag: TH_ACK\n");
        }
        if (tcp->rst) {
            printf("   Flag: TH_RST\n");
        }
        if (tcp->th_flags & TH_SYN) {
            printf("   Flag: TH_SYN\n");
        }
    }
    static int count = 1;
    count++;
}

int TCP::PrepareTcpSocket(pcap_t* &descr, bpf_u_int32 &netp)
{
    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */
    int size_ip=0;
    struct bpf_program fp;  /* hold compiled program     */
    bpf_u_int32 maskp;          /* subnet mask               */

    u_char *ptr; /* printing out hardware header info */

    /* ask pcap for the network address and mask of the device */
    //pcap_lookupnet("wlp4s0",&netp,&maskp,errbuf);

    descr = pcap_create("wlp4s0", errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    if (pcap_set_immediate_mode(descr, 1) != 0) {
        exit (EXIT_FAILURE);
    }

    if (pcap_set_timeout(descr, 5000) != 0) {
        exit (EXIT_FAILURE);
    }

    if (pcap_activate(descr) != 0) {
        exit (EXIT_FAILURE);
    }
}


int TCP::CatchPacket(pcap_t* descr, bpf_u_int32 netp)
{

    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    char filter[] = "host www.nemeckay.net && tcp";
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */
    int size_ip=0;
    struct bpf_program fp;  /* hold compiled program     */
    bpf_u_int32 maskp;          /* subnet mask               */

    /* Lets try and compile the program.. non-optimized */
    if(pcap_compile(descr,&fp,filter,0,netp) == -1)
    { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }


    /* set the compiled program as the filter */
    if(pcap_setfilter(descr,&fp) == -1)
    { fprintf(stderr,"Error setting filter\n"); exit(1); }

    int total_packet_count = 1;
    /* ... and loop */
    //pcap_loop(descr,-1,my_callback,NULL);
    //pcap_loop(descr, total_packet_count, my_callback, NULL);     */

    while(true) {
        sleep(1);
        packet = pcap_next(descr, &hdr);

        if (packet == NULL) {
            fprintf(stderr, "jsem tu");
            printf("Didn't grab packet\n");
            exit(1);
        }

        //pcap_next_ex(descr, reinterpret_cast<pcap_pkthdr **>(&descr), &packet);
        int code = my_packet_handler(&hdr, packet);
        if (code != 0){
            break;
        }
    }
    

    pcap_freecode(&fp);
    pcap_close(descr);
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
        cksum += *(unsigned short*)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (unsigned short)(~cksum);

}

int TCP::CreateRawSocket(Arguments programArguments)
{
    char buffer[PCKT_LEN];
    char receiver_ip[100];
    const char *domain_name = "www.nemeckay.net";
    hostname_to_ip(domain_name, receiver_ip);

    //Create a raw socket
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);

    if(s == -1)
    {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create socket");
        exit(1);
    }

    //Datagram to represent the packet
    char datagram[4096] , source_ip[32] , *data , *pseudogram;

    //zero out the packet buffer
    memset (datagram, 0, 4096);

    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;

    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in sin, din;
    struct pseudo_header_tcp psh;

    //Data part
    //data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
    //strcpy(data , "");

    //some address resolution
    strcpy(source_ip , "192.168.1.112");
    sin.sin_family = AF_INET;
    sin.sin_port = htons(1234);
    sin.sin_addr.s_addr = inet_addr (receiver_ip);

    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
    iph->id = htonl (54321);	//Id of this packet
    iph->frag_off = 0;
    iph->ttl = 55;
    iph->protocol = 6;
    iph->check = 0;		//Set to 0 before calculating checksum
    iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
    iph->daddr = sin.sin_addr.s_addr;

    //Ip checksum
    iph->check = csum ((unsigned short *) datagram, iph->tot_len);

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
    tcph->window = htons (32767);	/* maximum allowed window size */
    tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
    tcph->urg_ptr = 0;

    //Now the TCP checksum
    psh.source_address = inet_addr( source_ip );
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = 6;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header_tcp) + sizeof(struct tcphdr);
    pseudogram = static_cast<char *>(malloc(psize));

    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header_tcp));
    memcpy(pseudogram + sizeof(struct pseudo_header_tcp) , tcph , sizeof(struct tcphdr));

    tcph->check = csum( (unsigned short*) pseudogram , psize);

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;

    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        exit(0);
    }

    //loop if you want to flood :)
    int c = 1;
    while (c>0) {
        //Send the packet
        if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
            perror("sendto failed");
        }
            //Data send successfully
        else
            printf("Packet Send. Length : %d \n", iph->tot_len);
        c--;
    }

    close(s);
    return 0;
}


int TCP::hostname_to_ip(const char *hostname , char* ip)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;

    if ( (he = gethostbyname( hostname ) ) == NULL)
    {
        // get the host info
        herror("gethostbyname");
        return 1;
    }

    addr_list = (struct in_addr **) he->h_addr_list;

    for(i = 0; addr_list[i] != NULL; i++)
    {
        //Return the first one;
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }

    return 1;
}
