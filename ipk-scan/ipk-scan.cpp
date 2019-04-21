#include <iostream>
#include <utility>
#include "argument_parser.h"
#include "udp.h"
#include "tcp.h"
#include "ipv6.h"

int SendUdpPacket(int port, Arguments &arguments);
int SendTcpPacket(int port, Arguments &arguments);
void PrintPrinterHeader(Arguments arguments);
void PrintFinalPortState(int port, int state);
void ProcessTcpPackets(Arguments &arguments,int i);
void ProcessUdpPackets(Arguments &arguments, int &i);
int SendIpv6Packet(int port, Arguments &arguments, std::string typeOfPacket);
void ProcessIpv6Packets(Arguments &arguments, int i, std::string typeOfPacket);

int main(int argc, char **argv)
{
    Arguments programArguments;
    Arguments arguments = ProcessArguments(argc, argv, programArguments);
    std::string s(arguments.name);
    std::list <int> tcpPorts;
    bool isDashInTcpPorts = false;
    bool isDashInUdpPorts = false;
    std::list <int> udpPorts;

    arguments.GetUDPPorts(udpPorts, isDashInUdpPorts);
    arguments.GetTCPPorts(tcpPorts, isDashInTcpPorts);

    PrintPrinterHeader(arguments);

    if (strstr(arguments.ipAddress, ".") != NULL)
    {

        if (isDashInTcpPorts)
        {
            int begin = tcpPorts.front();
            int end = tcpPorts.back();
            for (int i=begin;i<end+1;i++)
            {
                ProcessTcpPackets(arguments, i);
            }
        }
        else
        {
            for (int& i : tcpPorts) {
                ProcessTcpPackets(arguments, i);
            }
        }

        if(isDashInUdpPorts)
        {
            int begin = udpPorts.front();
            int end = udpPorts.back();
            for (int i=begin;i<end+1;i++)
            {
                ProcessUdpPackets(arguments, i);
            }
        }
        else
        {
            for (int& i : udpPorts) {
                ProcessUdpPackets(arguments, i);
            }
        }
    }
    else
    {
        if (isDashInTcpPorts)
        {
            int begin = tcpPorts.front();
            int end = tcpPorts.back();
            for (int i=begin;i<end+1;i++)
            {
                ProcessIpv6Packets(arguments, i, "tcp");
            }
        }
        else
        {
            for (int& i : tcpPorts) {
                ProcessIpv6Packets(arguments, i, "tcp");
            }
        }

        if(isDashInUdpPorts)
        {
            int begin = udpPorts.front();
            int end = udpPorts.back();
            for (int i=begin;i<end+1;i++)
            {
                ProcessIpv6Packets(arguments, i, "udp");
            }
        }
        else
        {
            for (int& i : udpPorts) {
                ProcessIpv6Packets(arguments, i, "udp");
            }
        }
    }


    return 0;
}

void ProcessUdpPackets(Arguments &arguments, int &i)
{
    int status;
    status = SendUdpPacket(i, arguments);
    PrintFinalPortState(i, status);
}

void ProcessTcpPackets(Arguments &arguments, int i)
{
    int status = SendTcpPacket(i, arguments);
    if (status == 0) {
        status = SendTcpPacket(i, arguments);
    }
    PrintFinalPortState(i, status);
}

void ProcessIpv6Packets(Arguments &arguments, int i, std::string typeOfPacket)
{
    int status = SendIpv6Packet(i, arguments, typeOfPacket);
    if (status == 0) {
        status = SendIpv6Packet(i, arguments, typeOfPacket);
    }
    PrintFinalPortState(i, status);
}


void PrintPrinterHeader(Arguments arguments)
{
    std::cout <<
              "Interesting ports on " << arguments.name << " (" << arguments.ipAddress << "):\n"
              "PORT         STATE"
    << std::endl;
}

int SendUdpPacket(int port, Arguments &arguments)
{
    int state = 4;
    PrepareForUdpSniffing(arguments.interface);
    CreateRawUdpSocket(arguments, port);
    CatchUdpPacket(arguments, state, "ipv4");

    return state;
}

int SendTcpPacket(int port, Arguments &arguments)
{
    int state = 0;
    PreparForTcpSniffing(arguments.interface);
    CreateRawTcpSocket(arguments, port);
    CatchTcpPacket(arguments.name, port, state, "ipv4");

    return state;
}

int SendIpv6Packet(int port, Arguments &arguments, std::string typeOfPacket)
{
    int state = 0;
    if (typeOfPacket == "tcp")
    {
        PreparForTcpSniffing(arguments.interface);
        CreateRawIpv6Socket(arguments, port, typeOfPacket);
        CatchTcpPacket(arguments.name, port, state, "ipv6");
    }
    else
    {
        PrepareForUdpSniffing(arguments.interface);
        CreateRawIpv6Socket(arguments, port, typeOfPacket);
        CatchUdpPacket(arguments, state, "ipv6");
    }

    return state;
}

void PrintFinalPortState(int port, int state) {
    switch (state)
    {
        case 0:
            std::cout << "" << port << "/" << "tcp       "<< "filtered" << std::endl;
            break;
        case 1:
            std::cout << "" << port << "/" << "tcp     "<< "closed" << std::endl;
            break;
        case 2:
            std::cout << "" << port << "/" << "tcp       "<< "open" << std::endl;
            break;
        case 3:
            std::cout << "" << port << "/" << "udp       "<< "closed" << std::endl;
            break;
        case 4:
            std::cout << "" << port << "/" << "udp       "<< "open" << std::endl;
            break;
        default:
            break;
    }
}
