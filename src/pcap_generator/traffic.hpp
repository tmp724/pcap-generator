#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include <pcapplusplus/MacAddress.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/ArpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <memory>
#include <map>

class Header_field{
public:
  std::string name;
  uint8_t distribution_type;
  std::vector<std::string> values;
  std::vector<float> cumulative_probabilities;
};

class User_defined_layer{
public:
   std::string name;
   uint8_t number_header_fields;
   std::vector<uint8_t> header_field_distribution_types;
   std::map<std::string, Header_field> header_fields;
};

class User_defined_traffic{
public:
  std::string link_name;
  std::string traffic_name;
  uint8_t delay_distribution_type;
  std::vector<std::string> delay_distribution_options;
  std::vector<uint64_t> delay_values;
  std::vector<float> delay_self_specified_cumulative_probabilities;
  uint8_t number_layers;
  std::vector<std::string> layer_names;
  std::map<std::string, User_defined_layer> layers;
};
