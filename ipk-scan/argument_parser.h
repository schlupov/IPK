#ifndef PROJ2_ARGUMENT_PARSER_H
#define PROJ2_ARGUMENT_PARSER_H
#include <unistd.h>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <getopt.h>
#include <iostream>
#include <list>
#include <sstream>
#include <cstring>
#include <csignal>
class Arguments
{
    public:
        std::string udpPort;
        std::string tcpPort;
        std::string name;
        const char *interface;

        void PrintArguments();

        void GetTCPPorts(std::list <int> &tcpPorts, bool &dash);

        void GetUDPPorts(std::list <int> &udpPorts, bool &dash);

        void GetPort(std::list<int> &ports, char delimiter, std::stringstream &ss, std::string &token);
};
Arguments ProcessArguments(int argc, char** argv, Arguments programArguments);
void PrintHelp();
void signalHandler(int signum);
#endif //PROJ2_ARGUMENT_PARSER_H
