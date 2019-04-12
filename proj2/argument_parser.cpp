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

using namespace std;

class Arguments
{
    public:
        string udpPort;
        string tcpPort;
        string name;
        string interface;

    void PrintArguments()
    {
        cout << "UDP ports are: " << udpPort << endl;
        cout << "TCP ports are: " << tcpPort << endl;
        cout << "Domain name or IP adress is: " << name << endl;
        if (!interface.empty())
        {
            cout << "Interface is: " << interface;
        }
    }

    void GetTCPPorts(list <int>& tcpPorts)
    {
        char delimiter = ',';
        std::stringstream ss(tcpPort);
        std::string token;
        while (std::getline(ss, token, delimiter)) {
            int port = std::stoi(token);
            tcpPorts.push_back(port);
        }
    }

    void GetUDPPorts(list <int>& udpPorts)
    {
        char delimiter = ',';
        std::stringstream ss(udpPort);
        std::string token;
        while (std::getline(ss, token, delimiter)) {
            int port = std::stoi(token);
            udpPorts.push_back(port);
        }
    }
};

void PrintHelp()
{
    std::cout <<
              "Usage:\n"
              "-pu <port-ranges>: UDP ports to scan\n"
              "-pt <port-ranges> [<domain-name> | <IP-address>]: TCP ports to scan, you have set domain name or IP adress!\n"
              "{-i <interface>}: Optional argument for setting an interface\n"
              "-h: Show help\n";
    exit(1);
}

void PrintPorts(Arguments programArguments)
{
    list <int> tcpPorts;
    list <int> udpPorts;
    programArguments.GetUDPPorts(tcpPorts);
    for (int i: tcpPorts) {
        cout << i << endl;
    }
    programArguments.GetTCPPorts(udpPorts);
    for (int i: udpPorts) {
        cout << i << endl;
    }
}

void signalHandler(int signum) {
    PrintHelp();
    exit(1);
}

void ProcessArguments(int argc, char** argv)
{
    const char* const short_opts = "pu:pt:i:h";
    const  option long_options[] = {
            {"pu", required_argument, nullptr, 'pu'},
            {"pt", required_argument, nullptr, 'pt'},
            {"i", optional_argument, nullptr, 'i'},
            {"h", no_argument, nullptr, 'h'},
            {nullptr, no_argument, nullptr, 0}
    };
    Arguments programArguments{};
    string adress;

    for (int count=0; count < argc; ++count)
    {
        if (strcmp(argv[count], "-pt") == 0)
        {
            signal(SIGSEGV, signalHandler);
            if (strcmp(argv[count+2], "-pu") == 0)
            {
                PrintHelp();
            }
            adress = argv[count + 2];
        }
    }


    while (true)
    {
        const auto opt = getopt_long_only(argc, argv, short_opts, long_options, nullptr);

        if (-1 == opt)
            break;

        switch (opt)
        {
            case 'pu':
                programArguments.udpPort = optarg;
                break;
            case 'pt':
                programArguments.tcpPort = optarg;
                break;
            case 'i':
                programArguments.interface = optarg;
                break;
            case 'h':
            case '?':
            default:
                PrintHelp();
                break;
        }
        programArguments.name = adress;
    }
}