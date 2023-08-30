#include "configuration.hpp"

Configuration::Configuration(const std::string& filepath){
  load_configuration(filepath);
}

// TODO: catch errors
void Configuration::load_configuration(std::string filepath){
  YAML::Node config = YAML::LoadFile(filepath);

  std::cout << "Loading nodes config...\n";
  load_nodes_configuration(config);
  std::cout << "Loading links config...\n";
  load_links_configuration(config);
  std::cout << "Loading pcap generation config...\n";
  load_pcap_generation_configuration(config);
}

void Configuration::load_nodes_configuration(YAML::Node& config){
  // *** load nodes ***
  for(YAML::const_iterator node_name=config["nodes"].begin(); node_name != config["nodes"].end(); ++node_name){
    Node node;
    node.pcap_file_specified = 0;
    // load node names
    node.name = node_name->as<std::string>();
    // load ip address
    node.ip_address = config[node.name]["ip_address"].as<std::string>();
    // load mac address
    node.mac_address = config[node.name]["mac_address"].as<std::string>();
    // load application layer roles
    node.application_layer_roles = config[node.name]["application_layer_roles"].as<std::vector<std::string>>();
    //TODO: load delay distribution types and adjust delay input
    std::vector<std::string> tmp_delay_types = config[node.name]["role_specific_delay_distribution_types"].as<std::vector<std::string>>();
    for(uint16_t i = 0; i < tmp_delay_types.size(); i++){
       uint8_t tmp = 0;
       if(tmp_delay_types[i] == "self_specified"){
          tmp = self_specified;
          node.role_specific_delay_distribution_types.push_back(tmp);
          /*for(uint32_t i = 0; i < delay_distribution_options[my_user_defined_traffic_counter].size(); i++){ TODO
            node.delay_self_specified_cumulative_probabilities.push_back(atof(delay_distribution_options[my_user_defined_traffic_counter][i].c_str()));
          }*/
        }else if(tmp_delay_types[i] == "loop"){
          tmp = loop;
          node.role_specific_delay_distribution_types.push_back(tmp);
        }else if(tmp_delay_types[i] == "static"){
          tmp = static_d;
          node.role_specific_delay_distribution_types.push_back(tmp);
        }else if(tmp_delay_types[i] == "uniform"){
          tmp = uniform;
          node.role_specific_delay_distribution_types.push_back(tmp);
        }else if(tmp_delay_types[i] == "triangular"){
          tmp = triangular;
          node.role_specific_delay_distribution_types.push_back(tmp);
        }else if(tmp_delay_types[i] == "index_loop"){
          tmp = index_loop;
          node.role_specific_delay_distribution_types.push_back(tmp);
        }else if(tmp_delay_types[i] == "index_uniform"){
          tmp = index_uniform;
          node.role_specific_delay_distribution_types.push_back(tmp);
        }else{
          node.role_specific_delay_distribution_types.push_back(0);
        }
    }
    // load application role specific delays
    for(YAML::const_iterator delay_values=config[node.name]["role_specific_delay_distribution_values"].begin(); delay_values != config[node.name]["role_specific_delay_distribution_values"].end(); ++delay_values){
     node.role_specific_delays.push_back(delay_values->as<std::vector<uint64_t>>());
    }
    for(YAML::const_iterator link_name=config[node.name]["user_specified_traffic"].begin(); link_name != config[node.name]["user_specified_traffic"].end(); ++link_name){
      // load pcap files
      node.pcap_interface = link_name->first.as<std::string>();
      node.pcap_file_specified = config[node.name]["user_specified_traffic"][link_name->first.as<std::string>()]["pcap_file_specified"].as<bool>();
      if(node.pcap_file_specified){
        node.pcap_file_path = config[node.name]["user_specified_traffic"][link_name->first.as<std::string>()]["pcap_file_path"].as<std::string>();
      }
      // load user specified traffic
      std::map<std::string, User_defined_traffic> my_traffic;
      std::vector<std::string> delay_distribution_types = config[node.name]["user_specified_traffic"][link_name->first.as<std::string>()]["delay_distribution_types"].as<std::vector<std::string>>();
      std::vector<std::vector<std::string>> delay_distribution_options;
      std::vector<std::vector<uint64_t>> delay_distribution_values;
      for(YAML::const_iterator delay_options=config[node.name]["user_specified_traffic"][link_name->first.as<std::string>()]["delay_distribution_options"].begin(); delay_options != config[node.name]["user_specified_traffic"][link_name->first.as<std::string>()]["delay_distribution_options"].end(); ++delay_options){
        delay_distribution_options.push_back(delay_options->as<std::vector<std::string>>());
      }
      for(YAML::const_iterator delay_values=config[node.name]["user_specified_traffic"][link_name->first.as<std::string>()]["delay_distribution_values"].begin(); delay_values != config[node.name]["user_specified_traffic"][link_name->first.as<std::string>()]["delay_distribution_values"].end(); ++delay_values){
        delay_distribution_values.push_back(delay_values->as<std::vector<uint64_t>>());
      }
      uint64_t my_user_defined_traffic_counter = 0;
      for(YAML::const_iterator link_traffic_name=config[node.name]["user_specified_traffic"][link_name->first.as<std::string>()]["messages"].begin(); link_traffic_name != config[node.name]["user_specified_traffic"][link_name->first.as<std::string>()]["messages"].end(); ++link_traffic_name){
        User_defined_traffic my_user_defined_traffic;
        // load link name of user defined traffic
        my_user_defined_traffic.link_name = link_name->first.as<std::string>();
        // load traffic name of user specified traffic
        my_user_defined_traffic.traffic_name = link_traffic_name->as<std::string>();
        // load delay distribution type
        // TODO: load distribution options for other distributions
        if(delay_distribution_types[my_user_defined_traffic_counter] == "self_specified"){
          my_user_defined_traffic.delay_distribution_type = self_specified;
          for(uint32_t i = 0; i < delay_distribution_options[my_user_defined_traffic_counter].size(); i++){
            my_user_defined_traffic.delay_self_specified_cumulative_probabilities.push_back(atof(delay_distribution_options[my_user_defined_traffic_counter][i].c_str()));
          }
        }else if(delay_distribution_types[my_user_defined_traffic_counter] == "loop"){
          my_user_defined_traffic.delay_distribution_type = loop;
        }else if(delay_distribution_types[my_user_defined_traffic_counter] == "static"){
          my_user_defined_traffic.delay_distribution_type = static_d;
        }else if(delay_distribution_types[my_user_defined_traffic_counter] == "uniform"){
          my_user_defined_traffic.delay_distribution_type = uniform;
        }else if(delay_distribution_types[my_user_defined_traffic_counter] == "triangular"){
          my_user_defined_traffic.delay_distribution_type = triangular;
        }else if(delay_distribution_types[my_user_defined_traffic_counter] == "index_loop"){
          my_user_defined_traffic.delay_distribution_type = index_loop;
        }else if(delay_distribution_types[my_user_defined_traffic_counter] == "index_uniform"){
          my_user_defined_traffic.delay_distribution_type = index_uniform;
        }else{
          my_user_defined_traffic.delay_distribution_type = 0;
        }
        // load delay distribution values
        my_user_defined_traffic.delay_values = delay_distribution_values[my_user_defined_traffic_counter];
        // load number layers
        std::vector<std::string> layers = config[my_user_defined_traffic.traffic_name]["layers"].as<std::vector<std::string>>();
        my_user_defined_traffic.number_layers = layers.size();
        my_user_defined_traffic.layer_names = layers;
        // load layers
        for(uint8_t i = 0; i < layers.size(); i++){
          User_defined_layer my_user_defined_layer;
          if(layers[i] == "eth"){
            load_eth_layer_config(my_user_defined_traffic, my_user_defined_layer, config);
          }else if(layers[i] == "arp"){
            load_arp_layer_config(my_user_defined_traffic, my_user_defined_layer, config);
          }else if(layers[i] == "ipv4"){
            load_ipv4_layer_config(my_user_defined_traffic, my_user_defined_layer, config);
          }else if(layers[i] == "ipv6"){
            load_ipv6_layer_config(my_user_defined_traffic, my_user_defined_layer, config);
          }else if(layers[i] == "udp"){
            load_udp_layer_config(my_user_defined_traffic, my_user_defined_layer, config);
          }else if(layers[i] == "tcp"){
            load_tcp_layer_config(my_user_defined_traffic, my_user_defined_layer, config);
          }else if(layers[i] == "dhcp"){
            load_dhcp_layer_config(my_user_defined_traffic, my_user_defined_layer, config);
          }else if(layers[i] == "dns"){
            load_dns_layer_config(my_user_defined_traffic, my_user_defined_layer, config);
          }else{
            std::cout << "Layer " << layers[i] << "not defined!\n";
          }
          for(auto& header_field : my_user_defined_layer.header_fields){
            // load header field distribution type and options
            std::string tmp = config[my_user_defined_traffic.traffic_name][my_user_defined_layer.name][header_field.second.name]["distribution_type"].as<std::string>();
            if(tmp == "self_specified"){
              header_field.second.distribution_type = self_specified;
              header_field.second.cumulative_probabilities = config[my_user_defined_traffic.traffic_name][my_user_defined_layer.name ][header_field.second.name]["cumulative_probabilities"].as<std::vector<float>>();
            }else if(tmp == "loop"){
              header_field.second.distribution_type = loop;
            }else if(tmp == "static"){
              header_field.second.distribution_type = static_d;
            }else if(tmp == "uniform"){
              header_field.second.distribution_type = uniform;
            }else if(tmp == "triangular"){
              header_field.second.distribution_type = triangular;
            }else if(tmp == "index_uniform"){
              header_field.second.distribution_type = index_uniform;
            }else if(tmp == "index_loop"){
              header_field.second.distribution_type = index_loop;
            }else{
              header_field.second.distribution_type = 0;
            }
            // load header field values
            header_field.second.values = config[my_user_defined_traffic.traffic_name][my_user_defined_layer.name][header_field.second.name]["values"].as<std::vector<std::string>>();
          }
          my_user_defined_traffic.layers.insert({my_user_defined_layer.name, my_user_defined_layer});
        }
        my_traffic.insert({my_user_defined_traffic.traffic_name, my_user_defined_traffic});
        my_user_defined_traffic_counter++;
      }
      node.user_specified_traffic = my_traffic;
    }
    // load serialization delay
    node.serialization_delay = config[node.name]["serialization_delay"].as<uint32_t>();
    nodes.insert({node.name, node});
  }
}

void Configuration::load_links_configuration(YAML::Node& config){
  // *** load links ***
  for(YAML::const_iterator link_it=config["links"].begin(); link_it != config["links"].end(); ++link_it){
    Link link;
    // load link name
    link.name = link_it->as<std::vector<std::string>>()[0];
    // load node 1 name
    link.node1_name = link_it->as<std::vector<std::string>>()[1];
    // load node 2 name
    link.node2_name = link_it->as<std::vector<std::string>>()[2];
    // load link delay distribution type
    std::string tmp = config[link.name]["delay_distribution_type"].as<std::string>();
    if (tmp == "loop"){
      link.delay_distribution_type = loop;
    }else if (tmp == "self_specified"){
      link.delay_distribution_type = self_specified;
    }else if (tmp == "static"){
      link.delay_distribution_type = static_d;
    }else if (tmp == "uniform"){
      link.delay_distribution_type = uniform;
    }else if (tmp == "triangular"){
      link.delay_distribution_type = triangular;
    }else if (tmp == "index_uniform"){
      link.delay_distribution_type = index_uniform;
    }else if (tmp == "index_loop"){
      link.delay_distribution_type = index_loop;
    }else{
      link.delay_distribution_type = 0;
    }
    // load link packet loss distribution type
    tmp = config[link.name]["packet_loss_distribution_type"].as<std::string>();
    if (tmp == "loop"){
      link.packet_loss_distribution_type = loop;
    }else if (tmp == "self_specified"){
      link.packet_loss_distribution_type = self_specified;
    }else if (tmp == "static"){
      link.packet_loss_distribution_type = static_d;
    }else if (tmp == "uniform"){
      link.packet_loss_distribution_type = uniform;
    }else if (tmp == "triangular"){
      link.packet_loss_distribution_type = triangular;
    }else if (tmp == "index_loop"){
      link.packet_loss_distribution_type = index_loop;
    }else if (tmp == "index_uniform"){
      link.packet_loss_distribution_type = index_uniform;
    }else{
      link.packet_loss_distribution_type = 0;
    }
    // load link packet delay distribution type
    tmp = config[link.name]["packet_corruption_distribution_type"].as<std::string>();
    if (tmp == "loop"){
      link.packet_corruption_distribution_type = loop;
    }else if (tmp == "self_specified"){
      link.packet_corruption_distribution_type = self_specified;
    }else if (tmp == "static"){
      link.packet_corruption_distribution_type = static_d;
    }else if (tmp == "uniform"){
      link.packet_corruption_distribution_type = uniform;
    }else if (tmp == "triangular"){
      link.packet_corruption_distribution_type = triangular;
    }else if (tmp == "index_loop"){
      link.packet_corruption_distribution_type = index_loop;
    }else if (tmp == "index_uniform"){
      link.packet_corruption_distribution_type = index_uniform;
    }else{
      link.packet_corruption_distribution_type = 0;
    }
    // load link delay values
    link.delay_distribution_values = config[link.name]["delay_values"].as<std::vector<uint64_t>>();
    // load link packet loss values
    link.packet_loss_distribution_values = config[link.name]["packet_loss_values"].as<std::vector<uint64_t>>();
    // load link packet corruption values
    link.packet_corruption_distribution_values = config[link.name]["packet_corruption_values"].as<std::vector<uint64_t>>();

    links.insert({link.name, link});
  }
}

void Configuration::load_pcap_generation_configuration(YAML::Node& config){
  // *** load pcap generation config ***
  // load link to capture traffic at
  interface_link = config["interface_link"].as<std::string>();
  // load link "side" (node name) to capture traffic at
  interface_link_side = config["interface_link_side"].as<std::string>();
  // load duration type
  duration_type = config["duration_type"].as<std::string>();
  // load number of captured packets or number of nanoseconds after which the simulation ends
  duration = config["duration"].as<uint64_t>();
}

void Configuration::load_eth_layer_config(User_defined_traffic& my_user_defined_traffic, User_defined_layer& my_user_defined_layer, YAML::Node& config){
  // load layer name
  my_user_defined_layer.name = "eth";
  std::vector<std::string> field_names {"src_mac", "dst_mac", "eth_type"};
  my_user_defined_layer.number_header_fields = field_names.size();
  Header_field my_header_field;

  for(uint16_t i = 0; i < my_user_defined_layer.number_header_fields; i++){
    my_user_defined_layer.header_fields.insert({field_names[i], my_header_field});
    my_user_defined_layer.header_fields[field_names[i]].name = field_names[i];
  }
}

void Configuration::load_arp_layer_config(User_defined_traffic& my_user_defined_traffic, User_defined_layer& my_user_defined_layer, YAML::Node& config){
  // load layer name
  my_user_defined_layer.name = "arp";
  std::vector<std::string> field_names {"hardware_type", "protocol_type", "hardware_size", "protocol_size", "opcode", "sender_mac", "sender_ip", "target_mac", "target_ip"};
  my_user_defined_layer.number_header_fields = field_names.size();
  Header_field my_header_field;

  for(uint16_t i = 0; i < my_user_defined_layer.number_header_fields; i++){
    my_user_defined_layer.header_fields.insert({field_names[i], my_header_field});
    my_user_defined_layer.header_fields[field_names[i]].name = field_names[i];
  }
}

void Configuration::load_ipv4_layer_config(User_defined_traffic& my_user_defined_traffic, User_defined_layer& my_user_defined_layer, YAML::Node& config){
  // load layer name
  my_user_defined_layer.name = "ipv4";
  std::vector<std::string> field_names {"version", "header_length", "type_of_service", "total_length", "identification", "fragment_offset", "ttl", "protocol", "header_checksum", "ip_src", "ip_dst"};
  my_user_defined_layer.number_header_fields = field_names.size();
  Header_field my_header_field;

  for(uint16_t i = 0; i < my_user_defined_layer.number_header_fields; i++){
    my_user_defined_layer.header_fields.insert({field_names[i], my_header_field});
    my_user_defined_layer.header_fields[field_names[i]].name = field_names[i];
  }
}

void Configuration::load_ipv6_layer_config(User_defined_traffic& my_user_defined_traffic, User_defined_layer& my_user_defined_layer, YAML::Node& config){
  // load layer name
  my_user_defined_layer.name = "ipv6";
  std::vector<std::string> field_names {"version", "traffic_class", "flow_label", "payload_length", "next_header", "hop_limit", "ip_src", "ip_dst"};
  my_user_defined_layer.number_header_fields = field_names.size();
  Header_field my_header_field;

  for(uint16_t i = 0; i < my_user_defined_layer.number_header_fields; i++){
    my_user_defined_layer.header_fields.insert({field_names[i], my_header_field});
    my_user_defined_layer.header_fields[field_names[i]].name = field_names[i];
  }
}

void Configuration::load_udp_layer_config(User_defined_traffic& my_user_defined_traffic, User_defined_layer& my_user_defined_layer, YAML::Node& config){
  // load layer name
  my_user_defined_layer.name = "udp";
  std::vector<std::string> field_names {"src_port", "dst_port", "length", "header_checksum"};
  my_user_defined_layer.number_header_fields = field_names.size();
  Header_field my_header_field;

  for(uint16_t i = 0; i < my_user_defined_layer.number_header_fields; i++){
    my_user_defined_layer.header_fields.insert({field_names[i], my_header_field});
    my_user_defined_layer.header_fields[field_names[i]].name = field_names[i];
  }
}

void Configuration::load_tcp_layer_config(User_defined_traffic& my_user_defined_traffic, User_defined_layer& my_user_defined_layer, YAML::Node& config){
  // load layer name
  my_user_defined_layer.name = "tcp";
  std::vector<std::string> field_names {"src_port", "dst_port", "sequence_number", "ack_number", "reserved", "cwr_flag", "ece_flag", "urg_flag", "ack_flag", "psh_flag", "rst_flag", "syn_flag", "fin_flag"};
  my_user_defined_layer.number_header_fields = field_names.size();
  Header_field my_header_field;

  for(uint16_t i = 0; i < my_user_defined_layer.number_header_fields; i++){
    my_user_defined_layer.header_fields.insert({field_names[i], my_header_field});
    my_user_defined_layer.header_fields[field_names[i]].name = field_names[i];
  }
}

void Configuration::load_dhcp_layer_config(User_defined_traffic& my_user_defined_traffic, User_defined_layer& my_user_defined_layer, YAML::Node& config){
  // load layer name
  my_user_defined_layer.name = "dhcp";
  std::vector<std::string> field_names {"opcode", "hardware_type", "hardware_address_length", "hops", "transaction_id", "seconds_elapsed", "flags", "client_ip_address", "your_ip_address", 
"server_ip_address", "gateway_ip_address", "client_hardware_address", "server_name", "boot_file_name", "magic_number"};
  my_user_defined_layer.number_header_fields = field_names.size();
  Header_field my_header_field;

  for(uint16_t i = 0; i < my_user_defined_layer.number_header_fields; i++){
    my_user_defined_layer.header_fields.insert({field_names[i], my_header_field});
    my_user_defined_layer.header_fields[field_names[i]].name = field_names[i];
  }
}

void Configuration::load_dns_layer_config(User_defined_traffic& my_user_defined_traffic, User_defined_layer& my_user_defined_layer, YAML::Node& config){
  // load layer name
  my_user_defined_layer.name = "dns";
  std::vector<std::string> field_names {"transaction_id", "query_or_response", "opcode", "authoritative_answer", "truncation", "recursion_desired", "recursion_available", "zero", 
"authentic_data", "checking_disabled", "response_code", "number_of_questions", "number_of_answers", "number_of_authority", "number_of_additional"};
  my_user_defined_layer.number_header_fields = field_names.size();
  Header_field my_header_field;

  for(uint16_t i = 0; i < my_user_defined_layer.number_header_fields; i++){
    my_user_defined_layer.header_fields.insert({field_names[i], my_header_field});
    my_user_defined_layer.header_fields[field_names[i]].name = field_names[i];
  }
}

void Configuration::print_configuration(){ //TODO: print as yaml
  std::cout << "***CONFIGURATION***\n";

  // print nodes
  std::cout << "# Topology\n";
  std::cout << "  ## Nodes\n";
  for(auto n : nodes){
    std::cout << "    " << n.second.name << "\n";
  }

  // print links
  std::cout << "  ## Links\n";
  for(auto l : links){
    std::cout << "    " << l.second.name << ": " << l.second.node1_name << " - " << l.second.node2_name << "\n";
  }
  std::cout << "\n";

  // print pcap generation config
  std::cout << "# Pcap generation config\n";
  std::cout << "  Interface link: " << interface_link << "\n";
  std::cout << "  Interface link side (interface): " << interface_link_side << "\n";
  std::cout << "  Duration type: " << duration_type << "\n";
  std::cout << "  Duration: " << duration << "\n";
  std::cout << "\n";

  // print configuration of nodes
  std::cout << "# Configuration of nodes";
  for(auto& n : nodes){
    // print node name
    std::cout << "\n  ## " << n.second.name;
    // print application layer roles
    std::cout << "\n    ### Application layer roles\n      ";
    for(uint16_t i = 0; i < n.second.application_layer_roles.size(); i++){
      std::cout << n.second.application_layer_roles[i] << " ";
    }
    // print role specific delay distribution types
    std::cout << "\n    ### Role-specific delay distribution types\n";
    for(uint16_t i = 0; i < n.second.role_specific_delay_distribution_types.size(); i++){
      std::cout << "      " << n.second.role_specific_delay_distribution_types[i] << " ";
    }
    std::cout << "\n";
    // print role specific delays
    std::cout << "    ### Role-specific delays\n      ";
    for(uint16_t i = 0; i < n.second.role_specific_delays.size(); i++){
      std::cout << " [";
      for(uint16_t j = 0; j < n.second.role_specific_delays[i].size(); j++){
        std::cout << n.second.role_specific_delays[i][j] << " ";
      }
      std::cout << "] ";
    }
    // print role specific delay distribution types
    std::cout << "\n    ### User-specified traffic";
    for(auto& udt : n.second.user_specified_traffic){
      std::cout << "\n      #### " << udt.second.traffic_name << "\n";
      std::cout << "        Interface: " << udt.second.link_name << "\n";
      std::cout << "        Delay distribution type: " << (unsigned)udt.second.delay_distribution_type << "\n";
      // print delay values
      std::cout << "        Delay distribution values: ";
      for(uint16_t j = 0; j < udt.second.delay_values.size(); j++){
        std::cout << unsigned(udt.second.delay_values[j]) << " ";
      }
      std::cout << "\n";
      // TODO: for self_specified, print cumulative probabilities (and for others the needful)
      // print number of layers
      std::cout << "        Number layers: " << (unsigned)udt.second.number_layers << "\n";
      // print layers
      std::cout << "        Layers: ";
      for(auto& l : udt.second.layers){
        std::cout << "\n      #### " << l.second.name << "\n";
        std::cout << "        Number header fields: " << (unsigned)l.second.number_header_fields << "\n";
        // print header field distribution types
/*        std::cout << "Header field distribution types: ";
        for(uint16_t k = 0; k < udt.layers[j].header_field_distribution_types.size(); k++){
          std::cout << (unsigned)udt.layers[j].header_field_distribution_types[k] << " ";
        }*/
//        std::cout << "\n";
        // print header fields
        std::cout << "        Header fields: ";
        for(auto& hf : l.second.header_fields){
          std::cout << hf.second.name << " ";
        }
        for(auto& hf : l.second.header_fields){
          std::cout << "\n        ##### " << hf.second.name << "\n";
          // print header field distribution type
          std::cout << "          distribution type: " << (unsigned)hf.second.distribution_type << "\n";
          if(hf.second.distribution_type == self_specified){
            std::cout << "          cumulative distribution probabilities: ";
            for(uint16_t l = 0; l < hf.second.cumulative_probabilities.size(); l++){
              std::cout << hf.second.cumulative_probabilities[l] << " ";
            }
            std::cout << "\n";
          }
          std::cout << "          values: ";
          for(uint16_t l = 0; l < hf.second.values.size(); l++){
           // print header field values
            std::cout << hf.second.values[l] << " ";
          }
        }
      }
    }
    // print serialization delay
    std::cout << "\n    ### Serialization delay\n";
    std::cout << "      " << n.second.serialization_delay << "\n";
  }

  std::cout << "\n";
  // print configuration of links
  std::cout << "# Configuration of links\n";
  for(auto l : links){
    // print node name
    std::cout << "  ## " << l.second.name << "\n";
    // print link delay distribution type
    std::cout << "    Delay distribution type: " << unsigned(l.second.delay_distribution_type) << "\n";
    // print link delay distribution values
    std::cout << "    Delay distribution values: ";
    for(uint8_t i = 0; i < l.second.delay_distribution_values.size(); i++){
      std::cout << l.second.delay_distribution_values[i] << " ";
    }
    std::cout << "\n";
    // print link packet loss distribution type
    std::cout << "    Packet loss distribution type: " << unsigned(l.second.packet_loss_distribution_type) << "\n";
    // print link packet loss distribution values
    std::cout << "    Packet loss distribution values: ";
    for(uint8_t i = 0; i < l.second.packet_loss_distribution_values.size(); i++){
      std::cout << l.second.packet_loss_distribution_values[i] << " ";
    }
    std::cout << "\n";
    // print link packet corruption distribution type
    std::cout << "    Packet corruption distribution type: " << unsigned(l.second.packet_corruption_distribution_type) << "\n";
    // print link packet corruption distribution values
    std::cout << "    Packet corruption distribution values: ";
    for(uint8_t i = 0; i < l.second.packet_corruption_distribution_values.size(); i++){
      std::cout << l.second.packet_corruption_distribution_values[i] << " ";
    }
    std::cout << "\n";
  }
}
