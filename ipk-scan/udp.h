#ifndef PROJ2_UDP_H
#define PROJ2_UDP_H
#include "argument_parser.h"
#include<cstdio>    //for printf
#include<cstring> //memset
#include<sys/socket.h>	//for socket ofcourse
#include<cstdlib> //for exit(0);
#include<cerrno> //For errno - the error number
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include <iostream>
#include <netinet/in.h>
#include <pcap.h>
#include <arpa/inet.h>
    class UDP {
        public:

            int CreateRawSocket(Arguments programArguments);

            void PrepareUdpSocket(Arguments programArguments);

            unsigned short csum(unsigned short *ptr, int nbytes);

            int CatchPacket();
    };
    struct udpheader {
        unsigned short int udph_srcport;
        unsigned short int udph_destport;
        unsigned short int udph_len;
        unsigned short int udph_chksum;
    };
    struct ipheader {
        unsigned char      iph_ihl:5, iph_ver:4;
        unsigned char      iph_tos;
        unsigned short int iph_len;
        unsigned short int iph_ident;
        unsigned char      iph_flag;
        unsigned short int iph_offset;
        unsigned char      iph_ttl;
        unsigned char      iph_protocol;
        unsigned short int iph_chksum;
        unsigned int       iph_sourceip;
        unsigned int       iph_destip;
    };
    struct pseudo_header
    {
        u_int32_t source_address;
        u_int32_t dest_address;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t udp_length;
    };
#endif //PROJ2_UDP_H
