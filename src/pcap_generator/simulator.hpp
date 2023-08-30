#pragma once
#include <algorithm>
#include <stdlib.h>     /* srand, rand */
#include <random>
#include <functional>
#include <sstream>
#include <queue>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/DnsLayer.h>
#include <vector>
#include <iterator>
#include "configuration.hpp"

struct Event{
  uint64_t time;
  uint8_t type;
  std::string link_name;
  std::string node_name;
  std::string traffic_name;
  pcpp::Packet packet;
  bool operator >(const Event& rhs) const{
    return time > rhs.time;
  }
};

class Simulator{
public:
  Simulator(const Configuration& config, const char* output_file);

  void start();
private:
  void initialization();
  void loop();
  void event_handling();
  void write_packet_list();
//  uint32_t calculate_index_after_distribution(uint8_t distribution_type, uint32_t number_indeces);
  uint32_t calculate_index_after_self_specified_distribution(uint32_t number_indeces, std::vector<float>& cumulative_probabilities);
  void packet_construction(pcpp::Packet& my_packet, User_defined_traffic& my_traffic);
  void eth_layer_construction(pcpp::Packet& my_packet, User_defined_layer& my_layer);
  void arp_layer_construction(pcpp::Packet& my_packet, User_defined_layer& my_layer);
  void ipv4_layer_construction(pcpp::Packet& my_packet, User_defined_layer& my_layer);
  void ipv6_layer_construction(pcpp::Packet& my_packet, User_defined_layer& my_layer);
  void udp_layer_construction(pcpp::Packet& my_packet, User_defined_layer& my_layer);
  void tcp_layer_construction(pcpp::Packet& my_packet, User_defined_layer& my_layer);
  void dhcp_layer_construction(pcpp::Packet& my_packet, User_defined_layer& my_layer);
  void dns_layer_construction(pcpp::Packet& my_packet, User_defined_layer& my_layer);
  std::string get_protocol_type_as_string(pcpp::ProtocolType protocolType);
  timespec convert_ns_to_timespec(uint64_t ns);
  uint64_t convert_timespec_to_ns(timespec my_timespec);

  Configuration config;
  const char* output_file;
  uint64_t timer;
  uint64_t number_packets_captured;
  std::priority_queue<int,std::vector<Event>,std::greater<Event>> fel;
  std::vector<uint64_t> time_list;
  std::vector<pcpp::Packet> packet_list;
//  std::map<std::string, uint8_t> event_types = {"a}
  const uint8_t packet_arrives_at_node = 0;
  const uint8_t packet_arrives_at_link = 1;
  std::mt19937 engine; // Mersenne twister MT19937
};
