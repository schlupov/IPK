#include <netinet/ip_icmp.h>
#include "ipv6.h"

int CreateRawIpv6Socket(Arguments programArguments, int port, std::string typeOfPacket)
{
    int i, status, frame_length, sd, *tcp_flags;
    struct ip6_hdr iphdr{};
    struct tcphdr tcphdr{};
    struct udphdr udphdr{};
    uint8_t *pseudogram;
    struct sockaddr_in6 device{};
    int one = 1;
    const int *val = &one;

    pseudogram = allocate_ustrmem (IP_MAXPACKET);

    if (typeOfPacket == "tcp")
    {
        tcp_flags = allocate_intmem (8);
    }

    memset (&device, 0, sizeof (device));

    device.sin6_family = AF_INET6;
    device.sin6_port = htons (0);
    if ((status = inet_pton (AF_INET6, programArguments.ipAddress, &(device.sin6_addr))) != 1)
    {
        fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }

    iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
    if (typeOfPacket == "tcp")
    {
        iphdr.ip6_plen = htons (TCP_HDRLEN);
        iphdr.ip6_nxt = IPPROTO_TCP;
    }
    else
    {
        iphdr.ip6_plen = htons (UDP_HDRLEN);
        iphdr.ip6_nxt = IPPROTO_UDP;
    }
    iphdr.ip6_hops = 255;

    if ((status = inet_pton (AF_INET6, programArguments.interfaceIp, &(iphdr.ip6_src))) != 1)
    {
        fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }

    if ((status = inet_pton (AF_INET6, programArguments.ipAddress, &(iphdr.ip6_dst))) != 1)
    {
        fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }

    if (typeOfPacket == "tcp")
    {
        frame_length = PrepareIpv6Tcp(port, tcp_flags, iphdr, tcphdr, pseudogram);
        if ((sd = socket(PF_INET6, SOCK_RAW, IPPROTO_TCP)) < 0) {
            perror ("socket() failed ");
            exit (EXIT_FAILURE);
        }
    }
    else
    {
        frame_length = PrepareIpv6Udp(port, iphdr, udphdr, pseudogram);
        if ((sd = socket(PF_INET6, SOCK_RAW, IPPROTO_UDP)) < 0) {
            perror ("socket() failed ");
            exit (EXIT_FAILURE);
        }
    }


    if(setsockopt(sd, IPPROTO_IPV6, IPV6_HDRINCL, val, sizeof(one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        return 1;
    }

    if ((sendto (sd, pseudogram, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
        perror ("sendto() failed");
        exit (EXIT_FAILURE);
    }

    close (sd);

    free (pseudogram);

    if (typeOfPacket == "tcp")
    {
        free (tcp_flags);
    }

    return (EXIT_SUCCESS);
}

int PacketHandlerIpv6Tcp(const u_char *packet)
{
    int size_ip;
    int size_tcp;
    struct ip6_hdr *iphdr{};
    const struct sniff_tcp *tcp;

    iphdr = (struct ip6_hdr *) (packet + SIZE_ETHERNET);

    tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + IP6_HDRLEN);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return 42;
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

int PacketHandlerIpv6Udp(const u_char *packet, char *source_ip, char *receiver_ip)
{
    int size_ip;
    struct ip6_hdr *iphdr{};
    struct ip6_hdr *iphdr2{};
    struct icmphdr *icmp;
    int status;

    iphdr = (struct ip6_hdr *) (packet + SIZE_ETHERNET);

    icmp = (struct icmphdr *)(packet + SIZE_ETHERNET + IP6_HDRLEN);

    if ((icmp->type == 1) && (icmp->code == 4))
    {
        return 3;
    }
    return 4;
}

int PrepareIpv6Tcp(int port, int *tcp_flags, ip6_hdr &iphdr, tcphdr &tcphdr, uint8_t *pseudogram) {
    int frame_length;
    tcphdr.th_sport = htons (1234);
    tcphdr.th_dport = htons (static_cast<uint16_t>(port));
    tcphdr.th_seq = htonl (0);
    tcphdr.th_ack = htonl (0);
    tcphdr.th_x2 = 0;
    tcphdr.th_off = TCP_HDRLEN / 4;

    tcp_flags[0] = 0;
    tcp_flags[1] = 1;
    tcp_flags[2] = 0;
    tcp_flags[3] = 0;
    tcp_flags[4] = 0;
    tcp_flags[5] = 0;
    tcp_flags[6] = 0;
    tcp_flags[7] = 0;

    tcphdr.th_flags = 0;
    for (int i=0; i<8; i++) {
        tcphdr.th_flags += (tcp_flags[i] << i);
    }

    tcphdr.th_win = htons (65535);
    tcphdr.th_urp = htons (0);
    tcphdr.th_sum = tcp6_checksum(iphdr, tcphdr);

    frame_length = IP6_HDRLEN + TCP_HDRLEN;
    memcpy (pseudogram, &iphdr, IP6_HDRLEN * sizeof (uint8_t));
    memcpy (pseudogram + IP6_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof (uint8_t));
    return frame_length;
}

int PrepareIpv6Udp(int port, ip6_hdr &iphdr, udphdr &udphdr, uint8_t *pseudogram) {
    int frame_length;
    udphdr.source = htons (1234);
    udphdr.dest = htons (port);
    udphdr.len = htons (UDP_HDRLEN);
    udphdr.check = udp6_checksum(iphdr, udphdr);

    frame_length = IP6_HDRLEN + UDP_HDRLEN;
    memcpy (pseudogram, &iphdr, IP6_HDRLEN * sizeof (uint8_t));
    memcpy (pseudogram + IP6_HDRLEN, &udphdr, UDP_HDRLEN * sizeof (uint8_t));
    return frame_length;
}

uint16_t ComputeIpv6Checksum(uint16_t *addr, int len)
{
    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    while (count > 1) {
        sum += *(addr++);
        count -= 2;
    }

    if (count > 0) {
        sum += *(uint8_t *) addr;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    answer = ~sum;

    return (answer);
}

uint8_t *allocate_ustrmem (int len)
{
    uint8_t *tmp;

    tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (uint8_t));
        return (tmp);
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
        exit (EXIT_FAILURE);
    }
}

int *allocate_intmem (int len)
{
    int *tmp;

    tmp = (int *) malloc (len * sizeof (int));
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (int));
        return (tmp);
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
        exit (EXIT_FAILURE);
    }
}

uint16_t tcp6_checksum (struct ip6_hdr iphdr, struct tcphdr tcphdr)
{
    uint32_t lvalue;
    char buf[IP_MAXPACKET], cvalue;
    char *ptr;
    int chksumlen = 0;

    ptr = &buf[0];

    memcpy (ptr, &iphdr.ip6_src, sizeof (iphdr.ip6_src));
    ptr += sizeof (iphdr.ip6_src);
    chksumlen += sizeof (iphdr.ip6_src);

    memcpy (ptr, &iphdr.ip6_dst, sizeof (iphdr.ip6_dst));
    ptr += sizeof (iphdr.ip6_dst);
    chksumlen += sizeof (iphdr.ip6_dst);

    lvalue = htonl (sizeof (tcphdr));
    memcpy (ptr, &lvalue, sizeof (lvalue));
    ptr += sizeof (lvalue);
    chksumlen += sizeof (lvalue);

    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 3;

    memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
    ptr += sizeof (iphdr.ip6_nxt);
    chksumlen += sizeof (iphdr.ip6_nxt);

    memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
    ptr += sizeof (tcphdr.th_sport);
    chksumlen += sizeof (tcphdr.th_sport);

    memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
    ptr += sizeof (tcphdr.th_dport);
    chksumlen += sizeof (tcphdr.th_dport);

    memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
    ptr += sizeof (tcphdr.th_seq);
    chksumlen += sizeof (tcphdr.th_seq);

    memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
    ptr += sizeof (tcphdr.th_ack);
    chksumlen += sizeof (tcphdr.th_ack);

    cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
    memcpy (ptr, &cvalue, sizeof (cvalue));
    ptr += sizeof (cvalue);
    chksumlen += sizeof (cvalue);

    memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
    ptr += sizeof (tcphdr.th_flags);
    chksumlen += sizeof (tcphdr.th_flags);

    memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
    ptr += sizeof (tcphdr.th_win);
    chksumlen += sizeof (tcphdr.th_win);

    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 2;

    memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
    ptr += sizeof (tcphdr.th_urp);
    chksumlen += sizeof (tcphdr.th_urp);

    return ComputeIpv6Checksum((uint16_t *) buf, chksumlen);
}

uint16_t udp6_checksum (struct ip6_hdr iphdr, struct udphdr udphdr) {
    char buf[IP_MAXPACKET];
    char *ptr;
    int chksumlen = 0;
    int i;

    ptr = &buf[0];  // ptr points to beginning of buffer buf

    // Copy source IP address into buf (128 bits)
    memcpy (ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
    ptr += sizeof (iphdr.ip6_src.s6_addr);
    chksumlen += sizeof (iphdr.ip6_src.s6_addr);

    // Copy destination IP address into buf (128 bits)
    memcpy (ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
    ptr += sizeof (iphdr.ip6_dst.s6_addr);
    chksumlen += sizeof (iphdr.ip6_dst.s6_addr);

    // Copy UDP length into buf (32 bits)
    memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
    ptr += sizeof (udphdr.len);
    chksumlen += sizeof (udphdr.len);

    // Copy zero field to buf (24 bits)
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 3;

    // Copy next header field to buf (8 bits)
    memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
    ptr += sizeof (iphdr.ip6_nxt);
    chksumlen += sizeof (iphdr.ip6_nxt);

    // Copy UDP source port to buf (16 bits)
    memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
    ptr += sizeof (udphdr.source);
    chksumlen += sizeof (udphdr.source);

    // Copy UDP destination port to buf (16 bits)
    memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
    ptr += sizeof (udphdr.dest);
    chksumlen += sizeof (udphdr.dest);

    // Copy UDP length again to buf (16 bits)
    memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
    ptr += sizeof (udphdr.len);
    chksumlen += sizeof (udphdr.len);

    // Copy UDP ComputeIpv6Checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 2;


    return ComputeIpv6Checksum((uint16_t *) buf, chksumlen);
}