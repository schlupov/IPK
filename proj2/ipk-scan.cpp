#include <iostream>
#include <utility>
#include "argument_parser.h"
#include "udp.h"
#include "tcp.h"

void CallSocket(Arguments arguments);
int CallSocketTcp(TCP tcpSocket, int port, const char *interface, std::string name);

int main(int argc, char **argv)
{
    Arguments programArguments;
    Arguments arguments = ProcessArguments(argc, argv, programArguments);
    //CallSocket(arguments);
    std::list <int> tcpPorts;
    bool isDashInTcpPorts = false;
    TCP tcpSocket;
    arguments.GetTCPPorts(tcpPorts, isDashInTcpPorts);
    for (auto const& i : tcpPorts) {
        CallSocketTcp(tcpSocket, i, arguments.interface, arguments.name);
    }
    return 0;
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
    pcap_t* handle;
    bpf_u_int32 netp;
    tcpSocket.PrepareTcpSocket(handle, netp);
    tcpSocket.CreateRawSocket(interface, name, port);
    tcpSocket.CatchPacket(name, port, handle, netp);

    return 0;
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