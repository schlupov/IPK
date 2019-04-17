#include <iostream>
#include <utility>
#include "argument_parser.h"
#include "udp.h"
#include "tcp.h"

int CallSocketUdp(UDP udpSocket, int port, const char *interface, std::string name);
int CallSocketTcp(TCP tcpSocket, int port, const char *interface, std::string name);
void PrintPrinterHeader(std::string name);
void PrintFinalPortState(int port, int state);


int main(int argc, char **argv)
{
    Arguments programArguments;
    Arguments arguments = ProcessArguments(argc, argv, programArguments);
    std::list <int> tcpPorts;
    bool isDashInTcpPorts = false;
    bool isDashInUdpPorts = false;
    TCP tcpSocket;
    UDP udpSocket;
    std::list <int> udpPorts;
    arguments.GetUDPPorts(udpPorts, isDashInUdpPorts);
    arguments.GetTCPPorts(tcpPorts, isDashInTcpPorts);
    PrintPrinterHeader(arguments.name);

    for (auto const& i : tcpPorts) {
        int status = CallSocketTcp(tcpSocket, i, arguments.interface, arguments.name);
        if (status == 0) {
            status = CallSocketTcp(tcpSocket, i, arguments.interface, arguments.name);
        }
        PrintFinalPortState(i, status);
    }

    for (auto const& i : udpPorts) {
        int status;
        status = CallSocketUdp(udpSocket, i, arguments.interface, arguments.name);
        PrintFinalPortState(i, status);
    }

    return 0;
}

void PrintPrinterHeader(std::string name)
{
    char receiver_ip[100];
    hostname_to_ip(name, receiver_ip);

    std::cout <<
              "Interesting ports on " << name << " (" << receiver_ip << "):\n"
              "PORT         STATE"
    << std::endl;
}

int CallSocketUdp(UDP udpSocket, int port, const char *interface, std::string name)
{
    int state = 0;
    PrepareForUdpSniffing();
    udpSocket.CreateRawUdpSocket(interface, name, port);
    udpSocket.CatchUdpPacket(name, state);

    return state;
}

int CallSocketTcp(TCP tcpSocket, int port, const char *interface, std::string name)
{
    int state = 0;
    PrepareForSniffing();
    tcpSocket.CreateRawSocket(interface, name, port);
    tcpSocket.CatchPacket(name, port, state);

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
            std::cout << "" << port << "/" << "udp       "<< "open";
            break;
        default:
            break;
    }
}