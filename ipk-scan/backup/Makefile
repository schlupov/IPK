all: ipk-scan clean

ipk-scan: ipk-scan.o udp.o tcp.o argument_parser.o ipv6.o
	g++ -g -o ipk-scan ipk-scan.o udp.o tcp.o argument_parser.o ipv6.o -lpcap
	
ipk-scan.o: ipk-scan.cpp
	g++ -g -std=c++11 -c ipk-scan.cpp

tcp.o: tcp.cpp
	g++ -g -std=c++11 -c tcp.cpp

udp.o: udp.cpp
	g++ -g -std=c++11 -c udp.cpp
	
argument_parser.o: argument_parser.cpp
	g++ -g -std=c++11 -c argument_parser.cpp
	
ipv6.o: ipv6.cpp
	g++ -g -std=c++11 -c ipv6.cpp
	
clean:
	rm -f *.o

