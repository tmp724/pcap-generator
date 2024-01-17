#pragma once
#include "traffic.hpp"
#include <yaml.h>
#include <iostream>

class Node{
public:
  std::string name;
  std::string ip_address;
  std::string mac_address;
  bool pcap_file_specified;
  std::string pcap_file_path;
  std::string pcap_interface;
  std::vector<std::string> application_layer_roles;
  std::vector<uint8_t> role_specific_delay_distribution_types;
  std::vector<std::vector<uint64_t>> role_specific_delays; //TODO: should then be vector of another class <delay_distribution> or something (see traffic)

  std::map<std::string, User_defined_traffic> user_specified_traffic;

  uint32_t serialization_delay;
};

class Link{
public:
  std::string name;
  std::string node1_name;
  std::string node2_name;

  uint8_t delay_distribution_type;
  uint8_t packet_loss_distribution_type;
  uint8_t packet_corruption_distribution_type;

  std::vector<uint64_t> delay_distribution_values;
  std::vector<uint64_t> packet_loss_distribution_values;
  std::vector<uint64_t> packet_corruption_distribution_values;
};

class Configuration{
public:
  Configuration(const std::string& filepath);
  void print_configuration();

  // distribution macros (0 = none)
  static const uint8_t loop = 1;
  static const uint8_t self_specified = 2;
  static const uint8_t static_d = 3;
  static const uint8_t uniform = 4;
  static const uint8_t triangular = 5;
  static const uint8_t index_loop = 6;
  static const uint8_t index_uniform = 7;
  static const uint8_t index_triangular = 8;
  /// nodes in the topology
  std::map<std::string, Node> nodes;
  /// links in the topology
  /**
   *
  */
  std::map<std::string, Link> links;
  /// link to capture traffic at
  std::string interface_link;
  /// link "side" (node name) to capture traffic at
  std::string interface_link_side;
  /// simulation ends either after
  std::string duration_type;
  /// number of captured packets or number of nanoseconds after which the simulation ends
  uint64_t duration;
private:
  void load_configuration(std::string filepath);
  void load_nodes_configuration(YAML::Node& config);
  void load_links_configuration(YAML::Node& config);
  void load_pcap_generation_configuration(YAML::Node& config);
  void load_eth_layer_config(User_defined_traffic& my_user_defined_traffic, User_defined_layer& my_user_defined_layer, YAML::Node& config);
  void load_arp_layer_config(User_defined_traffic& my_user_defined_traffic, User_defined_layer& my_user_defined_layer, YAML::Node& config);
  void load_ipv4_layer_config(User_defined_traffic& my_user_defined_traffic, User_defined_layer& my_user_defined_layer, YAML::Node& config);
  void load_ipv6_layer_config(User_defined_traffic& my_user_defined_traffic, User_defined_layer& my_user_defined_layer, YAML::Node& config);
  void load_icmpv6_layer_config(User_defined_traffic& my_user_defined_traffic, User_defined_layer& my_user_defined_layer, YAML::Node& config);
  void load_udp_layer_config(User_defined_traffic& my_user_defined_traffic, User_defined_layer& my_user_defined_layer, YAML::Node& config);
  void load_tcp_layer_config(User_defined_traffic& my_user_defined_traffic, User_defined_layer& my_user_defined_layer, YAML::Node& config);
  void load_dhcp_layer_config(User_defined_traffic& my_user_defined_traffic, User_defined_layer& my_user_defined_layer, YAML::Node& config);
  void load_dns_layer_config(User_defined_traffic& my_user_defined_traffic, User_defined_layer& my_user_defined_layer, YAML::Node& config);
};
