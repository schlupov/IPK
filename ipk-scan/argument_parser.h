#ifndef PROJ2_ARGUMENT_PARSER_H
#define PROJ2_ARGUMENT_PARSER_H
#include <unistd.h>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <getopt.h>
#include <iostream>
#include <list>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sstream>
#include <cstring>
#include <csignal>
#include <pcap.h>

class Arguments
{
    public:
        std::string udpPort;
        std::string tcpPort;
        char ipAddress[100];
        char name[100];
        char interface[50];
        char interfaceIp[100];

        void GetTCPPorts(std::list <int> &tcpPorts, bool &dash);

        void GetUDPPorts(std::list <int> &udpPorts, bool &dash);

        void GetPort(std::list<int> &ports, char delimiter, std::stringstream &ss, std::string &token);
};

Arguments ProcessArguments(int argc, char** argv, Arguments programArguments);

void PrintHelp();

int GetInterface(Arguments &programArguments, std::string type, bool isInterface);

void GetIpv6Interface(Arguments &programArguments, pcap_addr_t *dev_addr);

void GetIpv4Interface(Arguments &programArguments, pcap_addr_t *dev_addr);
#endif //PROJ2_ARGUMENT_PARSER_H
