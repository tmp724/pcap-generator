//#include "simulator.hpp"
#include "configuration.hpp"
#include "simulator.hpp"
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>

//std::map<std::string, std::string> default_topologies = {{"simple_arp", "config/default_arp.yaml"},{"simple_dhcp", "config/default_dhcp.yaml"},{"simple_dns", "config/default_dns.yaml"}};
struct stat info;

int main(int argc, char **argv){
  try{
    if(argc < 3 || argc > 4){
      throw "Bad number of arguments. Please see the README file for usage instructions.";
    }
    if(stat(argv[1], &info)){
      throw "Could not access input file.";
    }
    if(argc == 4 && stat(argv[3], &info) && (!(info.st_mode & S_IFDIR))){
      throw "Could not open roles directory.";
    }

    Configuration my_configuration(argv[1]);
//    my_configuration.print_configuration();
    Simulator my_simulator(my_configuration, argv[2]);
    my_simulator.start();
  }catch(const std::exception& e){
    std::cerr << e.what() << std::endl;
  }catch(const char* e){
    std::cerr << e << std::endl;
  }
  return 0;
}

