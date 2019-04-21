#include <iostream>
#include <utility>
#include "argument_parser.h"
#include "udp.h"
#include "tcp.h"
#include "ipv6.h"

int SendUdpPacket(UDP udpSocket, int port, Arguments &arguments);
int SendTcpPacket(TCP tcpSocket, int port, Arguments &arguments);
void PrintPrinterHeader(Arguments arguments);
void PrintFinalPortState(int port, int state);
void ProcessTcpPackets(Arguments &arguments, TCP &tcpSocket, int i);
void ProcessUdpPackets(Arguments &arguments, UDP &udpSocket, int &i);
int SendIpv6Packet(IPV6 ipv6Socket, int port, Arguments &arguments, std::string typeOfPacket);
void ProcessIpv6Packets(Arguments &arguments, IPV6 &ipv6Socket, int i, std::string typeOfPacket);

int main(int argc, char **argv)
{
    Arguments programArguments;
    Arguments arguments = ProcessArguments(argc, argv, programArguments);
    std::string s(arguments.name);
    std::list <int> tcpPorts;
    bool isDashInTcpPorts = false;
    bool isDashInUdpPorts = false;
    TCP tcpSocket;
    IPV6 ipv6Socket;
    UDP udpSocket;
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
                ProcessTcpPackets(arguments, tcpSocket, i);
            }
        }
        else
        {
            for (int& i : tcpPorts) {
                ProcessTcpPackets(arguments, tcpSocket, i);
            }
        }

        if(isDashInUdpPorts)
        {
            int begin = udpPorts.front();
            int end = udpPorts.back();
            for (int i=begin;i<end+1;i++)
            {
                ProcessUdpPackets(arguments, udpSocket, i);
            }
        }
        else
        {
            for (int& i : udpPorts) {
                ProcessUdpPackets(arguments, udpSocket, i);
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
                ProcessIpv6Packets(arguments, ipv6Socket, i, "tcp");
            }
        }
        else
        {
            for (int& i : tcpPorts) {
                ProcessIpv6Packets(arguments, ipv6Socket, i, "tcp");
            }
        }

        if(isDashInUdpPorts)
        {
            int begin = udpPorts.front();
            int end = udpPorts.back();
            for (int i=begin;i<end+1;i++)
            {
                ProcessIpv6Packets(arguments, ipv6Socket, i, "udp");
            }
        }
        else
        {
            for (int& i : udpPorts) {
                ProcessIpv6Packets(arguments, ipv6Socket, i, "udp");
            }
        }
    }


    return 0;
}

void ProcessUdpPackets(Arguments &arguments, UDP &udpSocket, int &i)
{
    int status;
    status = SendUdpPacket(udpSocket, i, arguments);
    PrintFinalPortState(i, status);
}

void ProcessTcpPackets(Arguments &arguments, TCP &tcpSocket, int i)
{
    int status = SendTcpPacket(tcpSocket, i, arguments);
    if (status == 0) {
        status = SendTcpPacket(tcpSocket, i, arguments);
    }
    PrintFinalPortState(i, status);
}

void ProcessIpv6Packets(Arguments &arguments, IPV6 &ipv6Socket, int i, std::string typeOfPacket)
{
    SendIpv6Packet(ipv6Socket, i, arguments, typeOfPacket);
}


void PrintPrinterHeader(Arguments arguments)
{
    std::cout <<
              "Interesting ports on " << arguments.name << " (" << arguments.ipAddress << "):\n"
              "PORT         STATE"
    << std::endl;
}

int SendUdpPacket(UDP udpSocket, int port, Arguments &arguments)
{
    int state = 4;
    PrepareForUdpSniffing(arguments.interface);
    udpSocket.CreateRawUdpSocket(arguments, port);
    udpSocket.CatchUdpPacket(arguments, state);

    return state;
}

int SendTcpPacket(TCP tcpSocket, int port, Arguments &arguments)
{
    int state = 0;
    PrepareForSniffing(arguments.interface);
    tcpSocket.CreateRawSocket(arguments, port);
    tcpSocket.CatchPacket(arguments.name, port, state);

    return state;
}

int SendIpv6Packet(IPV6 ipv6Socket, int port, Arguments &arguments, std::string typeOfPacket)
{
    int state = 0;
    PrepareForSniffing(arguments.interface);
    ipv6Socket.CreateRawSocket(arguments, port, typeOfPacket);


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
