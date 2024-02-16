#include "simulator.hpp"

Simulator::Simulator(const Configuration& my_config, const char* my_output_file):config(my_config), output_file(my_output_file){}

void Simulator::start(){
  std::cout << "Initializing simulation...\n";
  initialization();
  std::cout << "Entering the loop...\n\n";
  loop();
  std::cout << "\nWriting to pcap file...\n\n";
  write_packet_list();
  std::cout << "Done!\n";
}

void Simulator::initialization(){
  timer = 0;

  // iterate through nodes and initialize traffic-generating events where necessary
  for(auto& n : config.nodes){
    // user-specified traffic
    for(auto& my_traffic : n.second.user_specified_traffic){
      uint64_t delay = 0;
      if(my_traffic.second.delay_distribution_type == Configuration::loop){ //TODO
      }else if(my_traffic.second.delay_distribution_type == Configuration::self_specified){ //TODO
      }else if(my_traffic.second.delay_distribution_type == Configuration::static_d){
        delay = my_traffic.second.delay_values[0];
      }else if(my_traffic.second.delay_distribution_type == Configuration::uniform){
      }else if(my_traffic.second.delay_distribution_type == Configuration::index_uniform){
        delay = my_traffic.second.delay_values[std::rand() % my_traffic.second.delay_values.size()];
      }else if(my_traffic.second.delay_distribution_type == Configuration::index_loop){
      }else if(my_traffic.second.delay_distribution_type == Configuration::triangular){//TODO
      }else if(my_traffic.second.delay_distribution_type == Configuration::index_triangular){//TODO
      }

      Event my_event;
      my_event.time = timer + delay;
      my_event.type = packet_arrives_at_link;
      my_event.link_name = my_traffic.second.link_name;
      my_event.node_name = n.second.name;
      my_event.traffic_name = my_traffic.second.traffic_name;
      pcpp::Packet my_packet;
      packet_construction(my_packet, my_traffic.second);
      my_event.packet = my_packet;
      // push event to future event list
      fel.push(my_event);
    }

    // TODO: role-specific traffic
    // TODO: input pcap traffic
    if(n.second.pcap_file_specified){
      // read pcap file
      pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(n.second.pcap_file_path.c_str());
      pcpp::RawPacket rawPacket;

      // verify that a reader interface was indeed created
      if (reader == NULL){
        printf("Cannot determine reader for file type\n");
        exit(1);
      }
      // open the reader for reading
      if(!reader->open()){
        printf("Cannot open pcap file for reading\n");
        exit(1);
      }

      while(reader->getNextPacket(rawPacket)){
        pcpp::Packet parsedPacket(&rawPacket);
        // generate events
        Event my_event;
        my_event.time = convert_timespec_to_ns(rawPacket.getPacketTimeStamp());
        // if dst mac or equals node mac, event type is that the packet arrives at node
        // else if src mac equals node mac, event type is that the packet arrives at node
        // look at what layers the packet contains
        for (pcpp::Layer* curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer()){
          std::string layer = get_protocol_type_as_string(curLayer->getProtocol());
          if(layer == "eth" ){
            pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
            if(ethLayer->getSourceMac().toString() == n.second.mac_address){
              my_event.type = packet_arrives_at_link;
            }else if(ethLayer->getDestMac().toString() == n.second.mac_address){
              my_event.type = packet_arrives_at_node;
            }
          }
        }
        my_event.link_name = n.second.pcap_interface;
        my_event.node_name = n.second.name;
        my_event.traffic_name = "pcap_input";
        my_event.packet = parsedPacket;
        fel.push(my_event);
      }
      reader->close();
      delete reader;
    }
  }
}

void Simulator::loop(){
  while(!((config.duration_type == "number_packets" && number_packets_captured >= config.duration)||(config.duration_type == "number_nanoseconds" && timer >= config.duration)||(fel.size() <= 0))){
    event_handling();
  }
  if(config.duration_type == "number_packets" && number_packets_captured >= config.duration){
    std::cout << "Configured number of " << config.duration << " packets reached!\nDone!" << std::endl;
  }else if(config.duration_type == "number_nanoseconds" && timer >= config.duration){
    std::cout << "Configured number of " << config.duration << " nanoseconds reached!\nDone!" << std::endl;
  }else if(fel.size() <= 0 && config.duration_type == "number_packets"){
    std::cout << "Simulation finished before the configured number of " << config.duration << " packets could be reached! Packets created: " << number_packets_captured << "\nDone!\n";
  }else if(fel.size() <= 0 && config.duration_type == "number_nanoseconds"){
    std::cout << "Simulation finished before the configured number of " << config.duration << " nanoseconds could be reached!\n Duration was " << timer << " nanoseconds.\nDone!\n";
  }
}

void Simulator::event_handling(){
  Event eve = fel.top();
  fel.pop();
  timer = eve.time;

  // some logging
  std::cout << "new Event!\n";
  if(eve.type == packet_arrives_at_link){
    std::cout << "type: packet_arrives_at_link\n";
  }else if(eve.type == packet_arrives_at_node){
    std::cout << "type: packet_arrives_at_node\n";
  }
  std::cout << "time: " << eve.time << "\n";
  std::cout << "link: " << eve.link_name << "\n";
  std::cout << "node: " << eve.node_name << "\n";
  std::cout << "traffic: " << eve.traffic_name << "\n";
  std::cout << "packet: " << eve.packet.toString() << "\n";
  std::cout << "\n\n";

  // if traffic arrives at interface that we listen to, add packet to packet list that gets shown in the output pcap file
  if(eve.link_name == config.interface_link && eve.node_name == config.interface_link_side){
    packet_list.push_back(eve.packet);
    time_list.push_back(eve.time);
    number_packets_captured++;
  }

  // handle events as per event type
  if(eve.type == packet_arrives_at_link){
    // TODO: will packet be dropped on link?
    /*if(config.links[eve.link_name].packet_loss_distribution_type == config.loop){

    }else if(){
    }*/
    Event new_event;
    // set time
    uint64_t delay = 0;
    if(config.links[eve.link_name].delay_distribution_type == config.loop){//TODO: add link delay distributions
    }else if(config.links[eve.link_name].delay_distribution_type == Configuration::index_uniform){
      delay = config.links[eve.link_name].delay_distribution_values[std::rand() % config.links[eve.link_name].delay_distribution_values.size()];
    }else if(config.links[eve.link_name].delay_distribution_type == Configuration::static_d){
      delay = config.links[eve.link_name].delay_distribution_values[0];
    }
    new_event.time = timer + delay;
    // set type
    new_event.type = packet_arrives_at_node;
    // set link name
    new_event.link_name = eve.link_name;
    // set traffic name
    new_event.traffic_name = eve.traffic_name;
    // set node name
    if(config.links[eve.link_name].node1_name == eve.node_name){
      new_event.node_name = config.links[eve.link_name].node2_name;
    }else{
      new_event.node_name = config.links[eve.link_name].node1_name;
    }
    // set packet
    new_event.packet = eve.packet;
    // TODO: will packet be corrupted?
    // push new event to future event list
    fel.push(new_event);

    // TODO: if traffic is configured to occur more then once, create next event accordingly
   // if(config.nodes[eve.node_name].user_specified_traffic[eve.link_name]){

    //}
    if(config.nodes[eve.node_name].user_specified_traffic[eve.traffic_name].delay_distribution_type == Configuration::index_uniform){ //TODO other distributions
      Event new_event_2;
      new_event_2.link_name = eve.link_name;
      new_event_2.node_name = eve.node_name;
      new_event_2.traffic_name = eve.traffic_name;
      new_event_2.type = eve.type;

      uint64_t delay_2 = config.nodes[eve.node_name].user_specified_traffic[eve.traffic_name].delay_values[std::rand() % config.nodes[eve.node_name].user_specified_traffic[eve.traffic_name].delay_values.size()];
      new_event_2.time = eve.time + delay_2;
      pcpp::Packet my_packet_2;
      packet_construction(my_packet_2, config.nodes[eve.node_name].user_specified_traffic[eve.traffic_name]);
      new_event_2.packet = my_packet_2;
      fel.push(new_event_2);
    }
  }else if (eve.type == packet_arrives_at_node){//TODO: process role functionality, e.g. bridge, router, server, client TODO: add serialization delay
    for(uint16_t i = 0; i < config.nodes[eve.node_name].application_layer_roles.size(); i++){
      if(config.nodes[eve.node_name].application_layer_roles[i] == "bridge"){
        for(auto& link : config.links){
          if(link.second.name != eve.link_name && (link.second.node1_name == eve.node_name || link.second.node2_name == eve.node_name)){
            Event new_event;
            uint64_t delay;
            if(config.nodes[eve.node_name].role_specific_delay_distribution_types[i] == Configuration::index_uniform){
              delay = config.nodes[eve.node_name].role_specific_delays[i][std::rand() % config.nodes[eve.node_name].role_specific_delays[i].size()];
            }
            new_event.time = eve.time + delay;
            new_event.type = packet_arrives_at_link;
            new_event.node_name = eve.node_name;
            new_event.link_name = link.second.name;
            new_event.traffic_name = eve.traffic_name;
            new_event.packet = eve.packet;
/*std::cout <<"new special event!\n";
  if(new_event.type == packet_arrives_at_link){
    std::cout << "type: packet_arrives_at_link\n";
  }else if(new_event.type == packet_arrives_at_node){
    std::cout << "type: packet_arrives_at_node\n";
  }
  std::cout << "time: " << new_event.time << "\n";
  std::cout << "link: " << new_event.link_name << "\n";
  std::cout << "node: " << new_event.node_name << "\n";
  std::cout << "traffic: " << new_event.traffic_name << "\n";
  std::cout << "\n\n";
*/
            fel.push(new_event);
          }
        }
      }
    }
  }/*else if (eve.type == ){ TODO: other events?
  }else if (eve.type == ){
  }else if (eve.type == ){
  }else if (eve.type == ){
  }*/
}

void Simulator::write_packet_list(){
//  pcpp::PcapNgFileWriterDevice writer(output_file);
  pcpp::PcapFileWriterDevice writer(output_file);
  writer.open();
  for(uint64_t i = 0; i < packet_list.size(); i++){
    pcpp::RawPacket* my_packet = packet_list[i].getRawPacket();
    timespec my_time = convert_ns_to_timespec(time_list[i]);
    my_packet->setPacketTimeStamp(my_time);
    writer.writePacket(*(my_packet));
  }
  writer.close();
}

timespec Simulator::convert_ns_to_timespec(uint64_t ns){
  timespec time;
  time.tv_sec = 0;
  time.tv_nsec = 0;
  while(ns > 999999999){
    ns -= 1000000000;
    time.tv_sec++;
  }
  time.tv_nsec = ns;
  return time;
}

uint64_t Simulator::convert_timespec_to_ns(timespec my_timespec){
  uint64_t time = my_timespec.tv_sec * 1000000000 + my_timespec.tv_nsec;
  return time;
}

uint32_t Simulator::calculate_index_after_self_specified_distribution(uint32_t number_indeces, std::vector<float>& cumulative_probabilities){//TODO: make this more precise
  /* generates random number between 0 and 99 */
  int random = rand() % 100;
  /* chooses the corresponding value */
  for(size_t i = 0; i < number_indeces; i ++){
    if(cumulative_probabilities[i] * 100 >= random){
      return i;
    }
  }
  return 0;
}

//TODO: work on RawPackets, not Packets!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Packets can add Layers ONLY as a pointer (not even a smart pointer)
// Moreover, they just point to the first layer, and each layer then points to the next one.
// This means that a Layer object can only ever be used for one packet and trying to use it for others will result in unforseeable memory issues.
// Totally ridiculous design choice.
// They do warn about it though in their tutorial. They argue with performance, but that does make little in my mind.
//TODO: create abstraction so you don't have to manually iterate over layers/header fields
//TODO: create function(s) for distributions and call them
void Simulator::packet_construction(pcpp::Packet& my_packet, User_defined_traffic& my_traffic){
  // iterate over layers
  for(uint16_t i = 0; i < my_traffic.number_layers; i++){
    auto& my_layer = my_traffic.layers[my_traffic.layer_names[i]];
    if(my_layer.name == "eth"){
      eth_layer_construction(my_packet, my_layer);
      std::cout << "after eth:\n" << my_packet.toString();
    }else if(my_layer.name == "arp"){
      arp_layer_construction(my_packet, my_layer);
      std::cout << my_packet.toString();
    }else if(my_layer.name == "ipv4"){
      ipv4_layer_construction(my_packet, my_layer);
      std::cout << "after ipv4:\n" << my_packet.toString();
    }else if(my_layer.name == "ipv6"){
      ipv6_layer_construction(my_packet, my_layer);
      std::cout << "after ipv6:\n" << my_packet.toString();
    }else if(my_layer.name == "icmpv6"){
      icmpv6_layer_construction(my_packet, my_layer);
      std::cout << "after icmpv6:\n" << my_packet.toString();
    }else if(my_layer.name == "udp"){
      udp_layer_construction(my_packet, my_layer);
//      pcpp::RawPacket udp_packet = udp_layer_construction(my_packet, my_layer);
//      my_packet = pcpp::Packet(&udp_packet);
      std::cout << "after udp:\n" << my_packet.toString();
    }else if(my_layer.name == "tcp"){
      tcp_layer_construction(my_packet, my_layer);
      std::cout << "after tcp:\n" << my_packet.toString();
    }else if(my_layer.name == "dhcp"){
      dhcp_layer_construction(my_packet, my_layer);
      std::cout << "after dhcp:\n" << my_packet.toString();
    }else if(my_layer.name == "dns"){
      dns_layer_construction(my_packet, my_layer);
      std::cout << "after dns:\n" << my_packet.toString();
    }
  }
  std::cout << "final packet:\n" << my_packet.toString();
  my_packet.computeCalculateFields();
}

void Simulator::eth_layer_construction(pcpp::Packet& my_packet, User_defined_layer& my_layer){
  pcpp::MacAddress my_src_mac_address, my_dst_mac_address;
  std::string my_eth_type;
  // iterate over header fields
  for(auto& my_header_field : my_layer.header_fields){
    if(my_header_field.second.name == "src_mac"){
      // check for distribution type
      if(my_header_field.second.distribution_type == config.static_d){
        my_src_mac_address = pcpp::MacAddress(my_header_field.second.values[0]);
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        my_src_mac_address = pcpp::MacAddress(my_header_field.second.values[index]);
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
        /*std::uniform_int_distribution<uint32_t> distribution(0, my_header_field.second.values.size());
        auto generator = std::bind(distribution, engine);
        my_src_mac_address = pcpp::MacAddress(my_header_field.second.values[generator()]);*/
        my_src_mac_address = pcpp::MacAddress(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]);
      }/*TODO: triangular distribution
       else if(my_header_field.second.distribution_type == triangular){
        std::vector<double> i{double(my_header_field.second.distribution_[0]), double(my_header_field.second.values[1]), double(my_header_field.second.values[2]))};
        std::vector<double> w{0, 1, 0};
        std::piecewise_linear_distribution<> d(i.begin(), i.end(), w.begin());
        my_src_mac_address = pcpp::MacAddress(my_header_field.second.values[""]
      }*/
    }else if(my_header_field.second.name == "dst_mac"){
      // check for distribution type
      if(my_header_field.second.distribution_type == Configuration::static_d){
        my_dst_mac_address = pcpp::MacAddress(my_header_field.second.values[0]);
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        my_dst_mac_address = pcpp::MacAddress(my_header_field.second.values[index]);
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
        my_dst_mac_address = pcpp::MacAddress(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]);
      }
    }else if(my_header_field.second.name == "eth_type"){
      // check for distribution type
      if(my_header_field.second.distribution_type == Configuration::static_d){
        my_eth_type = my_header_field.second.values[0];
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        my_eth_type = my_header_field.second.values[index];
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
        my_eth_type = my_header_field.second.values[std::rand() % my_header_field.second.values.size()];
      }
    }
  }
//      int my_eth_type_int = std::stoi(my_eth_type);
  uint32_t my_eth_type_int;
  std::stringstream etherstream;
  etherstream << std::hex << my_eth_type;
  etherstream >> my_eth_type_int;
//  pcpp::EthLayer my_eth_layer(my_src_mac_address, my_dst_mac_address, my_eth_type_int);
  pcpp::EthLayer my_eth_layer(my_src_mac_address, my_dst_mac_address, my_eth_type_int);
//  std::cout << "ethertype: " << my_eth_type_int << "\n";
//  my_eth_layer.getEthHeader()->etherType = pcpp::hostToNet16(my_eth_type_int);
  pcpp::Packet tmp_packet(my_packet);
  tmp_packet.addLayer(&my_eth_layer);
//  pcpp::RawPacket* ret = my_packet.getRawPacket();
//  return *ret;
  my_packet = tmp_packet;
}

void Simulator::arp_layer_construction(pcpp::Packet& my_packet, User_defined_layer& my_layer){
//  uint8_t hardwareSize, protocolSize;
//  uint16_t hardwareType, protocolType;// opcode;
  pcpp::ArpOpcode opcode;
  pcpp::MacAddress senderMacAddr, targetMacAddr;
  pcpp::IPv4Address senderIpAddr, targetIpAddr;
  for(auto& my_header_field : my_layer.header_fields){
    if(my_header_field.second.name == "hardware_type"){ //TODO: add or remove these fields
    }else if(my_header_field.second.name == "protocol_type"){
    }else if(my_header_field.second.name == "hardware_size"){
    }else if(my_header_field.second.name == "protocol_size"){
    }else if(my_header_field.second.name == "opcode"){ //TODO: just save in a string and do checking later
      // check for distribution type
      if(my_header_field.second.distribution_type == Configuration::static_d){
        if(my_header_field.second.values[0] == "1"){
          opcode = pcpp::ARP_REQUEST;
        }else if(my_header_field.second.values[0] == "2"){
          opcode = pcpp::ARP_REPLY;
        }
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        if(my_header_field.second.values[index] == "1"){
          opcode = pcpp::ARP_REQUEST;
        }else if(my_header_field.second.values[index] == "2"){
          opcode = pcpp::ARP_REPLY;
        }
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
        uint32_t index = std::rand() % my_header_field.second.values.size();
        if(my_header_field.second.values[index] == "1"){
          opcode = pcpp::ARP_REQUEST;
        }else if(my_header_field.second.values[index] == "2"){
          opcode = pcpp::ARP_REPLY;
        }
      }
    }else if(my_header_field.second.name == "sender_mac"){
      // check for distribution type
      if(my_header_field.second.distribution_type == Configuration::static_d){
        senderMacAddr = pcpp::MacAddress(my_header_field.second.values[0]);
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        senderMacAddr = pcpp::MacAddress(my_header_field.second.values[index]);
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
        senderMacAddr = pcpp::MacAddress(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]);
      }

    }else if(my_header_field.second.name == "sender_ip"){
      // check for distribution type
      if(my_header_field.second.distribution_type == Configuration::static_d){
        senderIpAddr = pcpp::IPv4Address(my_header_field.second.values[0]);
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        senderIpAddr = pcpp::IPv4Address(my_header_field.second.values[index]);
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
        senderIpAddr = pcpp::IPv4Address(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]);
      }
    }else if(my_header_field.second.name == "target_mac"){
      // check for distribution type
      if(my_header_field.second.distribution_type == Configuration::static_d){
        targetMacAddr = pcpp::MacAddress(my_header_field.second.values[0]);
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        targetMacAddr = pcpp::MacAddress(my_header_field.second.values[index]);
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
        targetMacAddr = pcpp::MacAddress(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]);
      }
    }else if(my_header_field.second.name == "target_ip"){
      // check for distribution type
      if(my_header_field.second.distribution_type == Configuration::static_d){
        targetIpAddr = pcpp::IPv4Address(my_header_field.second.values[0]);
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        targetIpAddr = pcpp::IPv4Address(my_header_field.second.values[index]);
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
        targetIpAddr = pcpp::IPv4Address(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]);
      }
    }
  }
  pcpp::ArpLayer my_arp_layer(opcode, senderMacAddr, targetMacAddr, senderIpAddr, targetIpAddr);
  pcpp::Packet tmp_packet(my_packet);
  tmp_packet.addLayer(&my_arp_layer);
  my_packet = tmp_packet;
}

void Simulator::ipv4_layer_construction(pcpp::Packet& my_packet, User_defined_layer& my_layer){
  pcpp::IPv4Address src, dst;
  uint8_t version, header_length, type_of_service, ttl, protocol;
  uint16_t total_length, identification, fragment, header_checksum;
  for(auto& my_header_field : my_layer.header_fields){
    if(my_header_field.second.name == "ip_src"){
      if(my_header_field.second.distribution_type == Configuration::loop){
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        src = pcpp::IPv4Address(my_header_field.second.values[index]);
      }else if(my_header_field.second.distribution_type == Configuration::static_d){
        src = pcpp::IPv4Address(my_header_field.second.values[0]);
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
      }else if(my_header_field.second.distribution_type == Configuration::triangular){
      }else if(my_header_field.second.distribution_type == Configuration::index_loop){
      }else if(my_header_field.second.distribution_type == Configuration::index_uniform){
        src = pcpp::IPv4Address(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]);
      }
    }else if(my_header_field.second.name == "ip_dst"){
      if(my_header_field.second.distribution_type == Configuration::loop){
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        dst = pcpp::IPv4Address(my_header_field.second.values[index]);
      }else if(my_header_field.second.distribution_type == Configuration::static_d){
        dst = pcpp::IPv4Address(my_header_field.second.values[0]);
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
      }else if(my_header_field.second.distribution_type == Configuration::triangular){
      }else if(my_header_field.second.distribution_type == Configuration::index_loop){
      }else if(my_header_field.second.distribution_type == Configuration::index_uniform){
        dst = pcpp::IPv4Address(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]);
      }
    }else if(my_header_field.second.name == "version"){
      if(my_header_field.second.distribution_type == Configuration::loop){
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        version = uint8_t(std::stoi(my_header_field.second.values[index]));
      }else if(my_header_field.second.distribution_type == Configuration::static_d){
        version = uint8_t(std::stoi(my_header_field.second.values[0]));
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
      }else if(my_header_field.second.distribution_type == Configuration::triangular){
      }else if(my_header_field.second.distribution_type == Configuration::index_loop){
      }else if(my_header_field.second.distribution_type == Configuration::index_uniform){
        version = uint8_t(std::stoi(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]));
      }
    }else if(my_header_field.second.name == "total_length"){
      if(my_header_field.second.distribution_type == Configuration::loop){
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
      }else if(my_header_field.second.distribution_type == Configuration::static_d){
        total_length = uint16_t(std::stoi(my_header_field.second.values[0]));
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
      }else if(my_header_field.second.distribution_type == Configuration::triangular){
      }else if(my_header_field.second.distribution_type == Configuration::index_loop){
      }else if(my_header_field.second.distribution_type == Configuration::index_uniform){
      }
    }
  }
  pcpp::IPv4Layer my_ipv4_layer(src, dst);
  my_ipv4_layer.getIPv4Header()->ipVersion = 4;
//  my_ipv4_layer.getIPv4Header()->internetHeaderLength = 20;
//  my_ipv4_layer.getIPv4Header()->typeOfService = 17;
//  my_ipv4_layer.getIPv4Header()->totalLength = total_length;
//  my_ipv4_layer.getIPv4Header()->ipId = 17;
//  my_ipv4_layer.getIPv4Header()->fragmentOffset = 17;
//  my_ipv4_layer.getIPv4Header()->timeToLive = 17;
  my_ipv4_layer.getIPv4Header()->protocol = 17;
//  my_ipv4_layer.getIPv4Header()->headerChecksum = 17;

  pcpp::Packet tmp_packet(my_packet);
//my_ipv4_layer.getIPv4Header()->timeToLive = 64;
  tmp_packet.addLayer(&my_ipv4_layer);
//  pcpp::RawPacket* ret = my_packet.getRawPacket();
//  return *ret;
  my_packet = tmp_packet;
}

void Simulator::ipv6_layer_construction(pcpp::Packet& my_packet, User_defined_layer& my_layer){
  pcpp::IPv6Address src, dst;
  uint8_t next_header;
  for(auto& my_header_field : my_layer.header_fields){
    if(my_header_field.second.name == "ip_src"){
      if(my_header_field.second.distribution_type == Configuration::loop){
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        src = pcpp::IPv6Address(my_header_field.second.values[index]);
      }else if(my_header_field.second.distribution_type == Configuration::static_d){
        src = pcpp::IPv6Address(my_header_field.second.values[0]);
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
      }else if(my_header_field.second.distribution_type == Configuration::triangular){
      }else if(my_header_field.second.distribution_type == Configuration::index_loop){
      }else if(my_header_field.second.distribution_type == Configuration::index_uniform){
        src = pcpp::IPv6Address(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]);
      }
    }else if(my_header_field.second.name == "ip_dst"){
      if(my_header_field.second.distribution_type == Configuration::loop){
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        dst = pcpp::IPv6Address(my_header_field.second.values[index]);
      }else if(my_header_field.second.distribution_type == Configuration::static_d){
        dst = pcpp::IPv6Address(my_header_field.second.values[0]);
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
      }else if(my_header_field.second.distribution_type == Configuration::triangular){
      }else if(my_header_field.second.distribution_type == Configuration::index_loop){
      }else if(my_header_field.second.distribution_type == Configuration::index_uniform){
        dst = pcpp::IPv6Address(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]);
      }
    }else if(my_header_field.second.name == "next_header"){
      if(my_header_field.second.distribution_type == Configuration::loop){
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        next_header = uint8_t(std::stoi(my_header_field.second.values[index]));
      }else if(my_header_field.second.distribution_type == Configuration::static_d){
        next_header = uint8_t(std::stoi(my_header_field.second.values[0]));
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
      }else if(my_header_field.second.distribution_type == Configuration::triangular){
      }else if(my_header_field.second.distribution_type == Configuration::index_loop){
      }else if(my_header_field.second.distribution_type == Configuration::index_uniform){
        next_header = uint8_t(std::stoi(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]));
      }
    }
  }
  pcpp::IPv6Layer my_ipv6_layer(src, dst);
  my_ipv6_layer.getIPv6Header()->nextHeader=next_header;
  my_ipv6_layer.getIPv6Header()->hopLimit=64;
  pcpp::Packet tmp_packet(my_packet);
  tmp_packet.addLayer(&my_ipv6_layer);
  my_packet = tmp_packet;
}

void Simulator::icmpv6_layer_construction(pcpp::Packet& my_packet, User_defined_layer& my_layer){
/*  uint8_t type, code;
  for(auto& my_header_field : my_layer.header_fields){
    if(my_header_field.second.name == "type"){
      if(my_header_field.second.distribution_type == Configuration::loop){
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        type = uint8_t(std::stoi(my_header_field.second.values[index]));
      }else if(my_header_field.second.distribution_type == Configuration::static_d){
        type = uint8_t(std::stoi(my_header_field.second.values[0]));
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
      }else if(my_header_field.second.distribution_type == Configuration::triangular){
      }else if(my_header_field.second.distribution_type == Configuration::index_loop){
      }else if(my_header_field.second.distribution_type == Configuration::index_uniform){
        type = uint8_t(std::stoi(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]));
      }
    }else if(my_header_field.second.name == "code"){
      if(my_header_field.second.distribution_type == Configuration::loop){
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        code = uint8_t(std::stoi(my_header_field.second.values[index]));
      }else if(my_header_field.second.distribution_type == Configuration::static_d){
        code = uint8_t(std::stoi(my_header_field.second.values[0]));
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
      }else if(my_header_field.second.distribution_type == Configuration::triangular){
      }else if(my_header_field.second.distribution_type == Configuration::index_loop){
      }else if(my_header_field.second.distribution_type == Configuration::index_uniform){
        code = uint8_t(std::stoi(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]));
      }
    }
  }
//  pcpp::ICMPv6EchoLayer my_icmpv6_layer();
  pcpp::IcmpV6Layer my_icmpv6_layer();
//  my_icmpv6_layer.getEchoHeader();
  pcpp::Packet tmp_packet(my_packet);
  tmp_packet.addLayer(&my_icmpv6_layer);
  my_packet = tmp_packet;*/
}

void Simulator::udp_layer_construction(pcpp::Packet& my_packet, User_defined_layer& my_layer){
//void Simulator::udp_layer_construction(pcpp::Packet& my_packet, User_defined_layer& my_layer){
  uint16_t src_port, dst_port;
  for(auto& my_header_field : my_layer.header_fields){
    if(my_header_field.second.name == "src_port"){
      if(my_header_field.second.distribution_type == Configuration::loop){
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        src_port = uint16_t(std::stoi(my_header_field.second.values[index]));
      }else if(my_header_field.second.distribution_type == Configuration::static_d){
        src_port = uint16_t(std::stoi(my_header_field.second.values[0]));
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
      }else if(my_header_field.second.distribution_type == Configuration::triangular){
      }else if(my_header_field.second.distribution_type == Configuration::index_loop){
      }else if(my_header_field.second.distribution_type == Configuration::index_uniform){
        src_port = uint16_t(std::stoi(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]));
      }
    }else if(my_header_field.second.name == "dst_port"){
      if(my_header_field.second.distribution_type == Configuration::loop){
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        dst_port = uint16_t(std::stoi(my_header_field.second.values[index]));
      }else if(my_header_field.second.distribution_type == Configuration::static_d){
        dst_port = uint16_t(std::stoi(my_header_field.second.values[0]));
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
      }else if(my_header_field.second.distribution_type == Configuration::triangular){
      }else if(my_header_field.second.distribution_type == Configuration::index_loop){
      }else if(my_header_field.second.distribution_type == Configuration::index_uniform){
        dst_port = uint16_t(std::stoi(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]));
      }
    }
  }
//std::auto_ptr<pcpp::Layer> my_udp_layer(new pcpp::UdpLayer(src_port, dst_port));
  pcpp::UdpLayer my_udp_layer(src_port, dst_port);
//  my_packet.addLayer(&my_udp_layer);
//std::cout << my_packet.toString();
//my_packet.addLayer(my_udp_layer);
  pcpp::Packet tmp_packet(my_packet);
  tmp_packet.addLayer(&my_udp_layer);
//  pcpp::RawPacket* ret = my_packet.getRawPacket();
//  return *ret;
//std::cout << tmp_packet.toString();
  my_packet = tmp_packet;
//std::cout << my_packet.toString();
}

void Simulator::tcp_layer_construction(pcpp::Packet& my_packet, User_defined_layer& my_layer){
  pcpp::IPv4Address src, dst;
  for(auto& my_header_field : my_layer.header_fields){
    if(my_header_field.second.name == "ip_src"){
      if(my_header_field.second.distribution_type == Configuration::loop){
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        src = pcpp::IPv4Address(my_header_field.second.values[index]);
      }else if(my_header_field.second.distribution_type == Configuration::static_d){
        src = pcpp::IPv4Address(my_header_field.second.values[0]);
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
      }else if(my_header_field.second.distribution_type == Configuration::triangular){
      }else if(my_header_field.second.distribution_type == Configuration::index_loop){
      }else if(my_header_field.second.distribution_type == Configuration::index_uniform){
        src = pcpp::IPv4Address(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]);
      }
    }else if(my_header_field.second.name == "ip_dst"){
      if(my_header_field.second.distribution_type == Configuration::loop){
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        src = pcpp::IPv4Address(my_header_field.second.values[index]);
      }else if(my_header_field.second.distribution_type == Configuration::static_d){
        src = pcpp::IPv4Address(my_header_field.second.values[0]);
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
      }else if(my_header_field.second.distribution_type == Configuration::triangular){
      }else if(my_header_field.second.distribution_type == Configuration::index_loop){
      }else if(my_header_field.second.distribution_type == Configuration::index_uniform){
        src = pcpp::IPv4Address(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]);
      }
    }
  }
/*  pcpp::TcpLayer my_tcp_layer(src, dst);
  pcpp::Packet tmp_packet(my_packet);
  tmp_packet.addLayer(&my_tcp_layer);
  my_packet = tmp_packet;*/
}

void Simulator::dhcp_layer_construction(pcpp::Packet& my_packet, User_defined_layer& my_layer){
  uint8_t opcode, hardware_type;
  pcpp::MacAddress client_hardware_address;
  for(auto& my_header_field : my_layer.header_fields){
    if(my_header_field.second.name == "opcode"){
      if(my_header_field.second.distribution_type == Configuration::loop){
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        opcode = uint8_t(std::stoi(my_header_field.second.values[index]));
      }else if(my_header_field.second.distribution_type == Configuration::static_d){
        opcode = uint8_t(std::stoi(my_header_field.second.values[0]));
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
      }else if(my_header_field.second.distribution_type == Configuration::triangular){
      }else if(my_header_field.second.distribution_type == Configuration::index_loop){
      }else if(my_header_field.second.distribution_type == Configuration::index_uniform){
        opcode = uint8_t(std::stoi(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]));
      }
    }else if(my_header_field.second.name == "hardware_type"){
      if(my_header_field.second.distribution_type == Configuration::loop){
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        hardware_type = uint8_t(std::stoi(my_header_field.second.values[index]));
      }else if(my_header_field.second.distribution_type == Configuration::static_d){
        hardware_type = uint8_t(std::stoi(my_header_field.second.values[0]));
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
      }else if(my_header_field.second.distribution_type == Configuration::triangular){
      }else if(my_header_field.second.distribution_type == Configuration::index_loop){
      }else if(my_header_field.second.distribution_type == Configuration::index_uniform){
        hardware_type = uint8_t(std::stoi(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]));
      }
    }else if(my_header_field.second.name == "client_hardware_address"){
      if(my_header_field.second.distribution_type == Configuration::loop){
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        client_hardware_address = pcpp::MacAddress(my_header_field.second.values[index]);
      }else if(my_header_field.second.distribution_type == Configuration::static_d){
        client_hardware_address = pcpp::MacAddress(my_header_field.second.values[0]);
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
      }else if(my_header_field.second.distribution_type == Configuration::triangular){
      }else if(my_header_field.second.distribution_type == Configuration::index_loop){
      }else if(my_header_field.second.distribution_type == Configuration::index_uniform){
        client_hardware_address = pcpp::MacAddress(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]);
      }
    }
  }
  pcpp::DhcpLayer my_dhcp_layer(pcpp::DHCP_REQUEST, client_hardware_address);
  pcpp::Packet tmp_packet(my_packet);
  tmp_packet.addLayer(&my_dhcp_layer);
  my_packet = tmp_packet;
}

void Simulator::dns_layer_construction(pcpp::Packet& my_packet, User_defined_layer& my_layer){
  pcpp::IPv4Address src, dst;
  for(auto& my_header_field : my_layer.header_fields){
    if(my_header_field.second.name == "ip_src"){
      if(my_header_field.second.distribution_type == Configuration::loop){
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        src = pcpp::IPv4Address(my_header_field.second.values[index]);
      }else if(my_header_field.second.distribution_type == Configuration::static_d){
        src = pcpp::IPv4Address(my_header_field.second.values[0]);
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
      }else if(my_header_field.second.distribution_type == Configuration::triangular){
      }else if(my_header_field.second.distribution_type == Configuration::index_loop){
      }else if(my_header_field.second.distribution_type == Configuration::index_uniform){
        src = pcpp::IPv4Address(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]);
      }
    }else if(my_header_field.second.name == "ip_dst"){
      if(my_header_field.second.distribution_type == Configuration::loop){
      }else if(my_header_field.second.distribution_type == Configuration::self_specified){
        uint32_t index = calculate_index_after_self_specified_distribution(my_header_field.second.values.size(), my_header_field.second.cumulative_probabilities);
        src = pcpp::IPv4Address(my_header_field.second.values[index]);
      }else if(my_header_field.second.distribution_type == Configuration::static_d){
        src = pcpp::IPv4Address(my_header_field.second.values[0]);
      }else if(my_header_field.second.distribution_type == Configuration::uniform){
      }else if(my_header_field.second.distribution_type == Configuration::triangular){
      }else if(my_header_field.second.distribution_type == Configuration::index_loop){
      }else if(my_header_field.second.distribution_type == Configuration::index_uniform){
        src = pcpp::IPv4Address(my_header_field.second.values[std::rand() % my_header_field.second.values.size()]);
      }
    }
  }
  pcpp::IPv4Layer my_ipv4_layer(src, dst);
  pcpp::Packet tmp_packet(my_packet);
  tmp_packet.addLayer(&my_ipv4_layer);
  my_packet = tmp_packet;
}

std::string Simulator::get_protocol_type_as_string(pcpp::ProtocolType protocolType){
    switch (protocolType){
    case pcpp::Ethernet:
        return "eth";
    case pcpp::ARP:
        return "arp";
    case pcpp::IPv4:
        return "ipv4";
    case pcpp::IPv6:
        return "ipv6";
    case pcpp::UDP:
        return "udp";
    case pcpp::TCP:
        return "TCP";
    case pcpp::DHCP:
        return "dhcp";
    case pcpp::DNS:
        return "dns";
    default:
        return "unknown";
    }
}

