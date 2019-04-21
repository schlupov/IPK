#ifndef PROJ2_TCP_H
#define PROJ2_TCP_H
#include "argument_parser.h"
#include<cstdio>
#include<cstring>
#include<sys/socket.h>
#include<cstdlib>
#include<cerrno>
#include<netinet/udp.h>
#include<netinet/ip.h>
#include <iostream>
#include <netinet/in.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <error.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "argument_parser.h"

/**
 * Pomocná struktura pro práci s TCP pakety.
 * Před odesláním pakety je tato struktura vyplněna daty a dále se využívá
 * při počítání kontrolního součtu.
 */
struct pseudo_header_tcp
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

#define SIZE_ETHERNET 14 ///< Velikost ethernetové hlavičky


/**
 * Metoda slouží k vytvoření raw soketu a k jeho odeslání.
 *
 * @param programArguments Argumenty programu, jsou potřeba pro vyplění
 *                          ip a tcp hlavičky a soketu.
 * @param port Číslo portu, kam bude soket poslán.
 */
void CreateRawTcpSocket(Arguments programArguments, int port);

/**
 * Metoda slouží ke ze zpracování zachyceného paketu.
 * Metoda si zjistí ip hlavičku a tcp hlavičku. Z ip hlavičky se ověří,
 * že se jedná o TCP paket a pokud ano, tak jsou ověřeny příznaky ACK a RST,
 * které informují, jestli byl port otevřen nebo uzavřen.
 *
 * @param packet Zachycený paket.
 * @return Vrací číslo na základě toho, jestli byly příslušné flagy v paketu nastaveny
 *          nebo nejedná-li se o TCP paket.
 */
int PacketHandlerTcp(const u_char *packet);

/**
 * Metoda nastavuje filtr a zachytává příchozí pakety.
 *
 * @param name Jméno hosta od kterého čekáme příchod paketu.
 * @param port Číslo portu, ze kterého má paket přijít.
 * @param state Proměnná informuje volající funkci, jestli byl zachycen paket a jaké měl
 *              nastavené příznaky.
 */
void CatchTcpPacket(std::string name, int port, int &state, std::string typeOfProtocol);

/**
 * Pomocná metoda nastavující jenodnotlivé části TCP paketu před jeho odesláním.
 *
 * @param tcph Struktura TCP paketu, která bude vyplněna.
 * @param port Číslo portu, kam bude soket poslán.
 */
void PrepareTcpHeader(tcphdr *tcph, uint16_t port);

/**
 * Pomocná metoda nastavující jenodnotlivé části IP hlavičky.
 *
 * @param source_ip Zdrojová IP adresa
 * @param datagram Datagram pro vypočet kontrolního součtu
 * @param iph Struktura IP datagramu, která bude vyplněna.
 * @param sin Struktura pro IP adresu soketu.
 */
void PrepareIpHeaderForTcp(char *source_ip, char *datagram, iphdr *iph, sockaddr_in &sin);

/**
 * Metoda pro vypočet kontrolního součtu pro TCP paket.
 *
 * @param source_ip Zdrojová IP adresa.
 * @param pseudogram Pomocný ukazatel rpo výpočet kontrolního součtu.
 * @param tcph Struktura TCP paketu, která bude vyplněna.
 * @param sin Struktura pro IP adresu soketu.
 * @param psh Pomocná struktrua pro práci s TCP paketemm.
 */
char *CalculateTcpChecksum(char *source_ip, char *pseudogram, tcphdr *tcph, sockaddr_in &sin,
                           pseudo_header_tcp &psh);

/**
 * Funkce připravuje prostředí pro odchytávání paketů.
 *
 * @param interface Rozhraní na kterém se budou pakety odchytávat.
 */
void PreparForTcpSniffing(char *interface);

/**
 * Funkce pro výpočet kontrolního součtu.
 *
 * @param buffer Buffer ke kterému se přičítá kontrolní součet.
 * @param size Počet bytu, pro které se bude počítat kontrolní součet.
 * @return Vrací kontrolní součet
 */
unsigned short ComputeCheckSum(unsigned short *buffer, int size);

/**
 * Funkce po uplynutí 1 sekundy ukončí čekání na příchozí paket.
 *
 * @param sig Signál, který může funkce obdržet.
 */
void TcpLoopBreaker(int sig);

/**
 * Pomocná struktura pro práci se zachycenými pakety.
 * Slouží ke zjištění informací jako je například zdrojová IP adresa paketu.
 */
struct sniff_ip {
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    #define IP_RF 0x8000
    #define IP_DF 0x4000
    #define IP_MF 0x2000
    #define IP_OFFMASK 0x1fff
    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f) ///< Velikost IP hlavičky

typedef u_int tcp_seq;

/**
 * Pomocná struktura pro práci se zachycenými TCP pakety.
 * Slouží ke zjištění informací jako jsou například nastavené flagy u TCP paketu.
 */
struct sniff_tcp {
    u_short th_sport;
    u_short th_dport;
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char  th_offx2;
    #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_PUSH 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20
    #define TH_ECE  0x40
    #define TH_CWR  0x80
    #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};
#endif //PROJ2_TCP_H
