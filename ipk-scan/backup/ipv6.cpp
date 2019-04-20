#include "ipv6.h"

int IPV6::CreateRawSocket(Arguments programArguments, int port, std::string typeOfPacket)
{
    int i, status, frame_length, sd, bytes, *tcp_flags;
    struct ip6_hdr iphdr{};
    struct tcphdr tcphdr{};
    struct udphdr udphdr{};
    uint8_t *src_mac, *dst_mac, *ether_frame;
    struct addrinfo hints{};
    struct sockaddr_in6 *ipv6;
    struct sockaddr_ll device{};
    struct ifreq ifr{};
    void *tmp;

    src_mac = allocate_ustrmem (6);
    dst_mac = allocate_ustrmem (6);
    ether_frame = allocate_ustrmem (IP_MAXPACKET);

    if (typeOfPacket == "tcp")
    {
        tcp_flags = allocate_intmem (8);
    }


    if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror ("socket() failed to get socket descriptor for using ioctl() ");
        exit (EXIT_FAILURE);
    }

    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", programArguments.interface);
    if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
        perror ("ioctl() failed to get source MAC address ");
        return (EXIT_FAILURE);
    }
    close (sd);

    memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

    memset (&device, 0, sizeof (device));
    if ((device.sll_ifindex = if_nametoindex (programArguments.interface)) == 0) {
        perror ("if_nametoindex() failed to obtain interface index ");
        exit (EXIT_FAILURE);
    }


    device.sll_family = AF_PACKET;
    device.sll_protocol = htons (ETH_P_IP);
    memcpy (device.sll_addr, dst_mac, 6 * sizeof (uint8_t));
    device.sll_halen = 6;

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
        frame_length = PrepareTcp(port, tcp_flags, iphdr, tcphdr, ether_frame);
    }
    else
    {
        frame_length = PrepareUdp(port, iphdr, udphdr, ether_frame);
    }

    if ((sd = socket (PF_PACKET, SOCK_DGRAM, htons (ETH_P_ALL))) < 0) {
        perror ("socket() failed ");
        exit (EXIT_FAILURE);
    }

    if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
        perror ("sendto() failed");
        exit (EXIT_FAILURE);
    }

    close (sd);

    free (src_mac);
    free (dst_mac);
    free (ether_frame);

    if (typeOfPacket == "tcp")
    {
        free (tcp_flags);
    }

    return (EXIT_SUCCESS);
}

int IPV6::PrepareTcp(int port, int *tcp_flags, ip6_hdr &iphdr, tcphdr &tcphdr, uint8_t *ether_frame) {
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
    memcpy (ether_frame, &iphdr, IP6_HDRLEN * sizeof (uint8_t));
    memcpy (ether_frame + IP6_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof (uint8_t));
    return frame_length;
}

int IPV6::PrepareUdp(int port, ip6_hdr &iphdr, udphdr &udphdr, uint8_t *ether_frame) {
    int frame_length;
    udphdr.source = htons (1234);
    udphdr.dest = htons (port);
    udphdr.len = htons (UDP_HDRLEN);
    udphdr.check = udp6_checksum(iphdr, udphdr);

    frame_length = IP6_HDRLEN + UDP_HDRLEN;
    memcpy (ether_frame, &iphdr, IP6_HDRLEN * sizeof (uint8_t));
    memcpy (ether_frame + IP6_HDRLEN, &udphdr, UDP_HDRLEN * sizeof (uint8_t));
    return frame_length;
}

uint16_t IPV6::checksum (uint16_t *addr, int len)
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

char *IPV6::allocate_strmem (int len)
{
    char *tmp;

    tmp = (char *) malloc (len * sizeof (char));
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (char));
        return (tmp);
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
        exit (EXIT_FAILURE);
    }
}

uint8_t *IPV6::allocate_ustrmem (int len)
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

int *IPV6::allocate_intmem (int len)
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

uint16_t IPV6::tcp6_checksum (struct ip6_hdr iphdr, struct tcphdr tcphdr)
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

    return checksum ((uint16_t *) buf, chksumlen);
}

uint16_t IPV6::udp6_checksum (struct ip6_hdr iphdr, struct udphdr udphdr) {
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

    // Copy UDP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 2;


    return checksum ((uint16_t *) buf, chksumlen);
}