COMPILER := g++

#COMPILEFLAGS := -std=c++11 -Wall --pedantic -I/usr/local/include/yaml-cpp -I/usr/local/include/pcapplusplus
COMPILEFLAGS := -std=c++11 -I/usr/local/include/yaml-cpp -I/usr/local/include/pcapplusplus

LINKERFLAGS := -lPcap++ -lPacket++ -lCommon++ -lpcap -lpthread -lyaml-cpp

OBJECTS := src/pcap_generator/configuration.o src/pcap_generator/simulator.o src/pcap_generator/main.o src/covert_channel_integrator/main_2.o

.PHONY: all

all: pcap_generator

pcap_generator: configuration.o simulator.o main.o
	$(COMPILER) $(COMPILEFLAGS) src/pcap_generator/configuration.o src/pcap_generator/simulator.o src/pcap_generator/main.o $(LINKERFLAGS) -o pcap_generator

main.o: src/pcap_generator/main.cpp
	$(COMPILER) -c $(COMPILEFLAGS) src/pcap_generator/main.cpp -o src/pcap_generator/main.o

simulator.o: src/pcap_generator/simulator.hpp src/pcap_generator/simulator.cpp src/pcap_generator/traffic.hpp
	$(COMPILER) -c $(COMPILEFLAGS) src/pcap_generator/simulator.cpp -o src/pcap_generator/simulator.o

configuration.o: src/pcap_generator/configuration.hpp src/pcap_generator/configuration.cpp src/pcap_generator/traffic.hpp
	$(COMPILER) -c $(COMPILEFLAGS) src/pcap_generator/configuration.cpp -o src/pcap_generator/configuration.o

clean:
	rm $(OBJECTS)
