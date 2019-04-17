#include "argument_parser.h"

void Arguments::PrintArguments()
{
    std::cout << "UDP ports are: " << udpPort << std::endl;
    std::cout << "TCP ports are: " << tcpPort << std::endl;
    std::cout << "Domain name or IP adress is: " << name << std::endl;
}

void Arguments::GetTCPPorts(std::list <int> &tcpPorts, bool &dash)
{
    char delimiter;
    if (tcpPort.find('-') != std::string::npos) {
        delimiter = '-';
        dash = true;
    }
    else
    {
        delimiter = ',';
    }
    std::stringstream ss(tcpPort);
    std::string token;
    GetPort(tcpPorts, delimiter, ss, token);
}

void Arguments::GetUDPPorts(std::list <int> &udpPorts, bool &dash)
{
    char delimiter;
    if (udpPort.find('-') != std::string::npos) {
        delimiter = '-';
        dash = true;
    }
    else
    {
        delimiter = ',';
    }
    std::stringstream ss(udpPort);
    std::string token;
    GetPort(udpPorts, delimiter, ss, token);
}

void Arguments::GetPort(std::list<int> &ports, char delimiter, std::stringstream &ss, std::string &token)
{
    while (getline(ss, token, delimiter)) {
        try
        {
            int port = stoi(token);
            ports.push_back(port);
        }
        catch(std::invalid_argument &exception)
        {
            PrintHelp();
        }
    }
}

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

void signalHandler(int signum) {
    PrintHelp();
    exit(1);
}


Arguments ProcessArguments(int argc, char** argv, Arguments programArguments)
{
    const char* const short_opts = "pu:pt:i:h";
    const  option long_options[] = {
            {"pu", required_argument, nullptr, 'u'},
            {"pt", required_argument, nullptr, 't'},
            {"i", optional_argument, nullptr, 'i'},
            {"h", no_argument, nullptr, 'h'},
            {nullptr, no_argument, nullptr, 0}
    };

    if (argc > 8) {
        PrintHelp();
    }

    while (true)
    {
        const auto opt = getopt_long_only(argc, argv, short_opts, long_options, nullptr);

        if (-1 == opt)
            break;

        switch (opt)
        {
            case 'u':
                programArguments.udpPort = optarg;
                break;
            case 't':
                programArguments.tcpPort = optarg;
                break;
            case 'i':
                programArguments.interface = optarg;
                break;
            case '?':
            case 'h':
            default:
                PrintHelp();
                break;
        }
    }

    std::string adress = argv[argc-1];
    programArguments.name = adress;

    return programArguments;
}