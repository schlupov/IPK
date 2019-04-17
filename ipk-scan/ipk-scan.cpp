#include <iostream>
#include <utility>
#include "argument_parser.h"
#include "udp.h"
#include "tcp.h"

void CallSocket(Arguments arguments);
int CallSocketTcp(TCP tcpSocket, int port, const char *interface, std::string name);
void PrintPrinterHeader(std::string name);

void PrintFinalPortState(int port, int state);

int main(int argc, char **argv)
{
    Arguments programArguments;
    Arguments arguments = ProcessArguments(argc, argv, programArguments);
    //CallSocket(arguments);
    std::list <int> tcpPorts;
    bool isDashInTcpPorts = false;
    TCP tcpSocket;
    int counter=0;
    arguments.GetTCPPorts(tcpPorts, isDashInTcpPorts);
    PrintPrinterHeader(arguments.name);
    for (auto const& i : tcpPorts) {
        counter++;
        int status = CallSocketTcp(tcpSocket, i, arguments.interface, arguments.name);
        if (status == 0) {
            status = CallSocketTcp(tcpSocket, i, arguments.interface, arguments.name);
        }
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
/*
void CallSocket(Arguments arguments)
{
    UDP udpSocket;
    udpSocket.CreateRawSocket(std::move(arguments));
    udpSocket.CatchPacket();
}*/

int CallSocketTcp(TCP tcpSocket, int port, const char *interface, std::string name)
{
    int state = 0;
    tcpSocket.PrepareTcpSocket();
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
        default:
            break;
    }
}

void PrintPorts(Arguments programArguments)
{
    std::list <int> tcpPorts;
    std::list <int> udpPorts;
    bool isDashInUdpPorts = false;
    bool isDashInTcpPorts = false;
    programArguments.GetUDPPorts(udpPorts, isDashInUdpPorts);
    for (int i: udpPorts) {
        std::cout << "UDP " << i << std::endl;
    }
    programArguments.GetTCPPorts(tcpPorts, isDashInTcpPorts);
    for (int i: tcpPorts) {
        std::cout << "TCP "<< i << std::endl;
    }
}