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

#define PCKT_LEN 8192
#define BUFSIZE 1024

int hostname_to_ip(const char *hostname , char* ip);

pcap_handler my_packet_handler(const struct pcap_pkthdr* header, const u_char* packet)
{
    struct ether_header *eth_header;

    eth_header = (struct ether_header *) packet;

    char buf[400];
    struct ip *ip = (struct ip *)buf;
    struct icmphdr *icmp = (struct icmphdr *)(ip + 1);

    icmp->type = ICMP_ECHO;
    icmp->code = 0;

    /* Header checksum */
    icmp->checksum = htons(~(ICMP_ECHO << 8));
    icmp->type = 0;
    icmp->code = 0;
    icmp->checksum = 0;

    std::cout << icmp->type;
}

int UDP::CatchPacket()
{

    char dev[] = "wlp4s0";
    pcap_t *handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    char filter_exp[] = "proto UDP";
    bpf_u_int32 subnet_mask, ip;
    struct pcap_pkthdr packet_header;
    const u_char *packet;
    int snapshot_len = 1028;

    if (pcap_lookupnet(dev, &ip, &subnet_mask, error_buffer) == -1) {
        printf("%s\n", error_buffer);
        ip = 0;
        subnet_mask = 0;
    }
    handle = pcap_open_live(dev, snapshot_len, 0, 1000, error_buffer);
    if (handle == NULL) {
        printf("Could not open %s - %s\n", dev, error_buffer);
        return 2;
    }
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    packet = pcap_next(handle, &packet_header);
    if (packet == NULL) {
        printf("No packet found.\n");
        return 2;
    }

    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);

    my_packet_handler(&packet_header, packet);
    pcap_if_t *interfaces,*temp;
    int i=0;
    if(pcap_findalldevs(&interfaces, reinterpret_cast<char *>(error)) == -1)
    {
        printf("\nerror in pcap findall devs");
        return -1;
    }

    printf("\n the interfaces present on the system are:");
    for(temp=interfaces;temp;temp=temp->next)
    {
        printf("\n%d  :  %s",i++,temp->name);

    }

    pcap_close(handle);
    return(0);
}


unsigned short UDP::csum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}



void UDP::PrepareUdpSocket(Arguments programArguments)
{
    std::list <int> udpPorts;
    bool isDashInUdpPorts = false;
    programArguments.GetUDPPorts(udpPorts, isDashInUdpPorts);
    for (int i: udpPorts) {
        std::cout << "UDP " << i << std::endl;
    }
}

int UDP::CreateRawSocket(Arguments programArguments)
{
    std::list <int> udpPorts;
    bool isDashInUdpPorts = false;
    programArguments.GetUDPPorts(udpPorts, isDashInUdpPorts);
    /*
    for (int i: udpPorts) {
        cout << "UDP " << i << endl;
    }*/

    char src_ip[100];
    const char *domain_name = "www.nemeckay.net";
    hostname_to_ip(domain_name, src_ip);

    //Create a raw socket of type IPPROTO
    //int s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if(s == -1)
    {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create raw socket");
        exit(1);
    }

    //Datagram to represent the packet
    char datagram[4096] , source_ip[32] , *data , *pseudogram;

    //zero out the packet buffer
    memset (datagram, 0, 4096);

    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;

    //UDP header
    struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));

    struct sockaddr_in sin;
    struct pseudo_header psh;

    //Data part
    data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
    strcpy(data , "AAA");

    //some address resolution
    strcpy(source_ip , "192.168.1.112");

    sin.sin_family = AF_INET;
    sin.sin_port = htons(1001);
    sin.sin_addr.s_addr = inet_addr (src_ip);

    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
    iph->id = htonl (54321);	//Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;		//Set to 0 before calculating checksum
    iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
    iph->daddr = sin.sin_addr.s_addr;

    //Ip checksum
    iph->check = csum ((unsigned short *) datagram, iph->tot_len);

    //UDP header
    udph->source = htons (1234);
    udph->dest = htons (1001);
    udph->len = htons(8 + strlen(data));	//tcp header size
    udph->check = 0;	//leave checksum 0 now, filled later by pseudo header

    //Now the UDP checksum using the pseudo header
    psh.source_address = inet_addr( source_ip );
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + strlen(data) );

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
    pseudogram = (char *)malloc(psize);

    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));

    udph->check = csum( (unsigned short*) pseudogram , psize);

    //loop if you want to flood :)
    int c=5;
    while (c>0)
    {
        //Send the packet
        if (sendto (s, datagram, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
        {
            perror("sendto failed");
        }
            //Data send successfully
        else
        {
            printf ("Packet Send. Length : %d \n" , iph->tot_len);
        }
        sleep(2);
        c--;
    }

    close(s);

    return 0;
}

int hostname_to_ip(const char *hostname , char* ip)
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