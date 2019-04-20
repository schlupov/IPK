#include <netdb.h>
#include <vector>
#include "argument_parser.h"
#include "tcp.h"

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

Arguments ProcessArguments(int argc, char** argv, Arguments programArguments)
{
    bool inter = false;
    bool isAddressIPv6 = false;
    bool pu = false;
    bool pt = false;
    struct addrinfo hints{};
    int status;
    struct addrinfo *destination;
    struct sockaddr_in6 *address_v6;
    struct sockaddr_in *address_v4;

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
                pu = true;
                programArguments.udpPort = optarg;
                break;
            case 't':
                pt = true;
                programArguments.tcpPort = optarg;
                break;
            case 'i':
                strcpy(programArguments.interface, optarg);
                inter = true;
                break;
            case '?':
            case 'h':
            default:
                PrintHelp();
                break;
        }
    }

    if (!pu && !pt)
    {
        fprintf(stderr, "You must set udp or tcp port");
        exit(EXIT_FAILURE);
    }

    strcpy(programArguments.name, argv[argc-1]);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    status = getaddrinfo(programArguments.name, NULL, &hints, &destination);
    if (status)
    {
        fprintf(stderr, "Not an IP address: %s\n", programArguments.name);
        exit(EXIT_FAILURE);
    }

    if (destination->ai_family == PF_INET)
    {
        char *text = (char *)malloc(INET_ADDRSTRLEN);
        address_v4 = (struct sockaddr_in *) destination->ai_addr;
        inet_ntop(AF_INET, &address_v4->sin_addr, text, INET_ADDRSTRLEN);
        strcpy(programArguments.ipAddress, text);
        free(text);
    }
    else
    {
        char *text = (char *)malloc(INET6_ADDRSTRLEN);
        address_v6 = (struct sockaddr_in6 *) destination->ai_addr;
        inet_ntop(AF_INET6, &address_v6->sin6_addr, text, INET6_ADDRSTRLEN);
        strcpy(programArguments.ipAddress, text);
        free(text);
    }


    if (strstr(programArguments.ipAddress, ":") != NULL) { isAddressIPv6 = true; }

    int code = 0;
    if (isAddressIPv6)
    {
        code = GetInterface(programArguments, "ipv6", inter);
    }

    if (!isAddressIPv6)
    {
        code = GetInterface(programArguments, "ipv4", inter);
    }

    if (code == 1)
    {
        fprintf(stderr, "Couldn't get an interface for %d family\n", destination->ai_family);
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(destination);
    return programArguments;
}

int GetInterface(Arguments &programArguments, std::string type, bool isInterface)
{
    pcap_if_t *interfaces,*temp;
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    int rc;
    rc = pcap_findalldevs(&interfaces, errbuf);
    if (rc)
    {
        fprintf(stderr, "Couldn't get interfaces\n");
        exit(EXIT_FAILURE);
    }

    for(temp=interfaces;temp;temp=temp->next)
    {
        if (isInterface)
        {
            pcap_addr_t *dev_addr;
            for (dev_addr = temp->addresses; dev_addr != NULL; dev_addr = dev_addr->next)
            {
                if (temp->addresses == NULL)
                    continue;

                if ((strcmp(temp->name, programArguments.interface) == 0) && (dev_addr->addr->sa_family == AF_INET)
                    && type == "ipv4")
                {
                    GetIpv4Interface(programArguments, dev_addr);
                    return 0;
                }
                if ((strcmp(temp->name, programArguments.interface) == 0) && (dev_addr->addr->sa_family == AF_INET6)
                    && type == "ipv6")
                {
                    GetIpv6Interface(programArguments, dev_addr);
                    return 0;
                }
            }
        }
        else
        {
            pcap_addr_t *dev_addr;
            for (dev_addr = temp->addresses; dev_addr != NULL; dev_addr = dev_addr->next)
            {
                if (temp->addresses == NULL)
                    continue;

                if (!(temp->flags & PCAP_IF_LOOPBACK) && (dev_addr->addr->sa_family == AF_INET)
                    && type == "ipv4")
                {
                    GetIpv4Interface(programArguments, dev_addr);
                    strcpy(programArguments.interface, temp->name);
                    return 0;
                }
                if (!(temp->flags & PCAP_IF_LOOPBACK) && (dev_addr->addr->sa_family == AF_INET6)
                    && type == "ipv6")
                {
                    GetIpv6Interface(programArguments, dev_addr);
                    strcpy(programArguments.interface, temp->name);
                    return 0;
                }
            }
        }
    }
    return 1;
}

void GetIpv4Interface(Arguments &programArguments, pcap_addr_t *dev_addr)
{
    char ipchar[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &(((sockaddr_in *) dev_addr->addr)->sin_addr), ipchar, INET_ADDRSTRLEN);
    strcpy(programArguments.interfaceIp, ipchar);
}

void GetIpv6Interface(Arguments &programArguments, pcap_addr_t *dev_addr)
{
    char ipchar[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(((sockaddr_in6 *) dev_addr->addr)->sin6_addr), ipchar, INET6_ADDRSTRLEN);
    strcpy(programArguments.interfaceIp, ipchar);
}