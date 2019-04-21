/***************************************************************************************
*    Title: <title of program/source code>
*    Author: <author(s) names>
*    Date: <date>
*    Code version: <code version>
*    Availability: <where it's located>
*
***************************************************************************************/
 /**
 * argument_parser.h
 * Soubor s prototypy funkcí pro zpracovaní argumentů, které byly zadány při spuštění programu.
 */
#ifndef PROJ2_ARGUMENT_PARSER_H
#define PROJ2_ARGUMENT_PARSER_H
#include <unistd.h>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <getopt.h>
#include <iostream>
#include <list>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sstream>
#include <cstring>
#include <csignal>
#include <pcap.h>

/**
 * Třída uchovávájící argumenty zadané při spuštění programu.
 */
class Arguments
{
    public:
        std::string udpPort;
        std::string tcpPort;
        char ipAddress[100];
        char name[100];
        char interface[50];
        char interfaceIp[100];

        /**
        * Metoda sloužící pro získání portu z načtených argumentů programu,
        * na které se budou zasílát tcp pakety.
        *
        * @param tcpPorts List, který bude naplněn čísly portů pro tcp skenování.
        * @param dash Informuje o tom, jestli byly porty zadány s polmčkou.
        *             V případě, kdy je dash true, tak se berou jen jednotlivá čísla portů. V opačném případě
        *             se prochází postupně čísla portů od určitého čísla do určitého čísla.
        */
        void GetTCPPorts(std::list <int> &tcpPorts, bool &dash);

        /**
        * Metoda sloužící pro získání portu z načtených argumentů programu,
        * na které se budou zasílát udp pakety.
        *
        * @param udpPorts List, který bude naplněn čísly portů pro udp skenování.
        * @param dash Informuje o tom, jestli byly porty zadány s polmčkou.
        *             V případě, kdy je dash true, tak se berou jen jednotlivá čísla portů. V opačném případě
        *             se prochází postupně čísla portů od určitého čísla do určitého čísla.
        */
        void GetUDPPorts(std::list <int> &udpPorts, bool &dash);

        /**
        * Pomocná metoda, která metodám pomáhá ukládat porty v listu portů
        *
        * @param ports List, který bude naplněn čísly portů pro udp skenování.
        * @param delimiter Informuje o tom, jestli byly porty zadány s polmčkou nebo čárkou.
        * @param ss Pomocná proměnná umožňující lepší čtení řetězce portů.
        * @return token Pomocná proměnná držící aktuální token před tím než je vložen do listu ports
        */
        void GetPort(std::list<int> &ports, char delimiter, std::stringstream &ss, std::string &token);
};

/**
* Funkce načítá argumenty programu a postupně je zpracovává a plní tak atributy třídy Arguments.
*
* @param argc Počet argumentů načtených při spuštění programu.
* @param argv Ukazatel na argumenty programu.
* @param programArguments Objekt třídy Arguments jehož atributy se plní argumenty programu.
* @return Objekt třídy Arguments jehož atributy se plní argumenty programu.
*/
Arguments ProcessArguments(int argc, char** argv, Arguments programArguments);

/**
* Funkce tiskne napovědu programu v případě použití přepínače -h.
*/
void PrintHelp();

/**
* Funkce pro získání rozhraní na daném operačním systému.
*
* @param programArguments Objekt třídy Arguments jehož atributy interface a interfaceIp budou naplněny
*                         získanými daty.
* @param type Řetězec určuruje, jestli se bude hledat rozhraní s IPv4 adresou nebo IPv6 adresou.
* @param isInterface Proměnná určuje, jestli byl při spuštění programu zadán přepínač -i.
* @return Návratová hodnota 0 značí, že bylo nalezeno vhodné rozhraní, 1 značí neúspěch a program bude ukončen s chybou.
*/
int GetInterface(Arguments &programArguments, std::string type, bool isInterface);

/**
* Pomocná adresa na uložení IPv6 adresy portu do objektu třídy Arguments.
*
* @param programArguments Objekt třídy Arguments jehož atribut interfaceIp bude naplněn ip adresou rozhraní.
* @param dev_addr Ukazatel na aktuální adresu.
*/
void GetIpv6Interface(Arguments &programArguments, pcap_addr_t *dev_addr);

/**
* Pomocná adresa na uložení IPv4 adresy portu do objektu třídy Arguments.
*
* @param programArguments Objekt třídy Arguments jehož atribut interfaceIp bude naplněn ip adresou rozhraní.
* @param dev_addr Ukazatel na aktuální adresu.
*/
void GetIpv4Interface(Arguments &programArguments, pcap_addr_t *dev_addr);
#endif //PROJ2_ARGUMENT_PARSER_H
