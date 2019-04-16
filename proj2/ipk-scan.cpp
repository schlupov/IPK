#include <iostream>
#include <utility>
#include "argument_parser.h"
#include "udp.h"
#include "tcp.h"

void PrintPorts(Arguments programArguments);

void CallSocket(Arguments arguments);
int CallSocketTcp(Arguments arguments);

int main(int argc, char **argv)
{
    Arguments programArguments;
    Arguments arguments = ProcessArguments(argc, argv, programArguments);
    //PrintPorts(arguments);
    //CallSocket(arguments);
    CallSocketTcp(arguments);
    return 0;
}
/*
void CallSocket(Arguments arguments)
{
    UDP udpSocket;
    udpSocket.CreateRawSocket(std::move(arguments));
    udpSocket.CatchPacket();
}*/

int CallSocketTcp(Arguments arguments)
{
    pcap_t* handle;
    bpf_u_int32 netp;
    TCP tcpSocket;
    tcpSocket.PrepareTcpSocket(handle, netp);
    tcpSocket.CreateRawSocket(std::move(arguments));
    tcpSocket.CatchPacket(handle, netp);
    exit(EXIT_SUCCESS);
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