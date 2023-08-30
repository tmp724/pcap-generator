# pcap-generator
## Overview
Pcapplusplus-based tool to generate traffic through simulation of configurable network topology. 
Packet contents and delays are configurable as distributions through an input yaml file. Output is a pcap/pcapng file.

## Stableness/Supported features
Roles are not fully implemented yet. Protocols are supported as marked further below, although not all distributions may be supported 
for all header fields yet. I will at some point come up with a versioning system to get this in order. 

## Repository structure
|-config: contains configuration yaml files, including those defining a role and those used for testing \
|-Makefile: makefile to build program from source \
|-output: directory that may be utilized to store output pcaps \
|-README.md: this file \
|-pcap_generator: pcap-generator executable \
|-src: contains source code 

## Installation
Tested on Fedora 30 and Ubuntu 18.04. Should run on most Linux platforms. \
Install [yaml-cpp 0.6.3](https://github.com/jbeder/yaml-cpp) and the latest [pcapplusplus](https://pcapplusplus.github.io/docs/install). 
Make sure the header files get installed into /usr/local/include (should be the default) or change the pcap-generator Makefile later accordingly. \
Download this repository, go into this folder and run `make`.

## Usage
### Getting started
`./pcap_generator config/default_arp.yaml pcaps/default_arp.pcap` will execute a simple example. \
`config/default_arp.yaml` specifies the input config file. If you wish to execute over another configuration, just change the path. \
`pcaps/default_arp.pcap` specifies the file to store the resulting packet capture in. Again, if you wish for it to be stored elsewhere, 
you may modify the command accordingly. \
One can give a third option that specifies a directory where the roles are configured. It defaults to config/roles. 
For more information on roles, see further below. 

### Overview configuration fields
For quickly getting an understanding of how a configuration file should look like, we recommend you look at the examples in the config folder. 
Errors in the configuration file will lead to errors in the simulation. At this point (this is a first prototype), we don't guarantee proper error handling with meaningful error messages. 
The following tables contain a detailled description of possible input for each field. 

| Field/Subfield      | Input example                                | Input description              | Possible values                         |
| :------------------ | :------------------------------------------: | -----------------------------: | --------------------------------------: |
| nodes               | [host1, host2]                               | node names                     | list of strings                         |
| links               | [[link1, host1, host2],[link2, host1, host2] | link names and nodes they link | list of 3-field-list of strings         |
| interface_link      | link2                                        | link to capture traffic at     | link name                               |
| interface_link_side | host2                                        | node to capture traffic at     | node name                               |
| duration_type       | number_packets                               | traffic capture duration type  | number_packets or number_nanoseconds    |
| duration            | 1230                                         | traffic capture duration       | value 0 to 2^64-1 (ca. 1.8 x 10^19)     |

For each defined link:
| Field/Subfield                      | Input example | Input description                                            | Possible values                          |
| :---------------------------------- | :-----------: | -----------------------------------------------------------: | ---------------------------------------: |
| delay_distribution_type             | loop          | distribution type of delays to go over the link              | static, loop, self_specified, triangular |
| delay_values                        | [2000, 30000] | delay values in nanoseconds                                  | list of values 0 to 2^64-1               |
| packet_loss_distribution_type       | static        | distribution type of packet losses occuring on the link      | static                                   |
| packet_loss_values                  | [150]         | packet loss values (every n packets)                         | list of values 0 to 2^64-1               |
| packet_corruption_distribution_type | static        | distribution type of packet corruptions occuring on the link | static                                   |
| packet_corruption_values            | [0]           | packet corruption values (every n packets)                   | list of values 0 to 2^64-1               |

For each defined node:
| Field/Subfield                                              | Input example                  | Input description                               | Possible values                                      |
| :---------------------------------------------------------- | :----------------------------: | ----------------------------------------------: | ---------------------------------------------------: |
| application_layer_roles                                     | [bridge]                       | roles active on the node                        | list of role names                                   |
| user_specified_traffic/<link_name>/messages                 | [my_packet_1, my_packet_2]     | traffic generated at the interface (node, link) | list of traffic names                                |
| user_specified_traffic/<link_name>/delay_distribution_types | [loop, static]                 | distribution type of user specified traffic     | list of € (loop, static, self_specified, triangular) |
| user_specified_traffic/<link_name>/delay_values             | [[5, 300], [1270000005000000]] | distribution values                             | list of lists of 0 to 2^64-1                         |
| serialization_delay                                         | [5000]                         | fixed serialization delay                       | value 0 to 2^64-1                                    |

For each defined user_specified_traffic in any node:
| Field/Subfield                                                    | Input example          | Input description                         | Possible values                     |
| :---------------------------------------------------------------- | :--------------------: | ----------------------------------------: | ----------------------------------: |
| <traffic_name>/layers                                             | [eth, arp]             | list of layer names                       | eth, arp, ipv4 (,ipv6, udp, dhcp, dns) |
| <traffic_name>/<layer_name>/<header_field_name>/distribution_type | static                 | distribution type for header field values | loop, self_specified, static        |
| <traffic_name>/<layer_name>/<header_field_name>/values            | [00:00:00:00:00:01]    | list of header field specific values      | header field specific               |

Header fields within an Ethernet layer: src_mac, dst_mac, eth_type

Header fields within an ARP layer: hardware_type, protocol_type, hardware_size, protocol_size, opcode, sender_mac, sender_ip, target_mac, target_ip

tbd: ipv4, ipv6, tcp, udp, dhcp, dns

### Distribution types
(tbd) \
As outlined above, for various configuration fields, one may specify the distribution type and values. 
We use two types of distributions: Those that relate to a sequence of explicitely stated values and those that relate to the whole range of possible input values, optionally limited by 
stating a minimum and maximum value. While the former type (we will just call it index distribution here) yields no problems in implementation, the latter only works on some configuration 
fields, as it is lavish to implement it on all header fields for all layers, or (in case of variables not exhibiting field characteristics, e.g. arbitrary strings in a header fields), simply 
not senseful to implement. When deemed useful, it may however be implemented in some cases, as per the tables above. \
Here, we explain the behaviour of each distribution type. \
static: Only one value has to be specified and will be used once. example:
```
my_packet_1:
  layers: [eth, arp]
  eth:
    src_mac:
      distribution_type: static
      values: [00:00:00:00:00:01]
  ...
```
self_specified: The value will be randomly generated after a given list of cumulative distribution values. example: \
`my_packet_1: \
  layers: [eth, arp] \
  eth: \
    src_mac: \
      distribution_type: self_specified \
      cumulative_probabilities: [0.2, 0.4, 0.9, 1] \
      values: [00:00:00:00:00:01, 00:00:00:00:00:02, 00:00:00:00:00:03, 00:00:00:00:00:04] \
  ...` \
index_loop: The values in the specified values list will be used in turn from left to right and then start again at the left. example: \
`my_packet_1: \
  layers: [eth, arp] \
  eth: \
    src_mac: \
      distribution_type: loop \
      values: [00:00:00:00:00:01, 00:00:00:00:00:02, 00:00:00:00:00:03, 00:00:00:00:00:04] \
  ...` \
index_uniform: The value will be randomly generated after a uniform distribution over the list of given values example:\
`my_packet_1: \
  layers: [eth, arp] \
  eth: \
    src_mac: \
      distribution_type: uniform \
      values: [00:00:00:00:00:01, 00:00:00:00:00:02, 00:00:00:00:00:03, 00:00:00:00:00:04] \
  ...` \
loop: \
uniform: \
triangular: This is only implemented for the various delay configurations\

### Adding new roles
(tbd) \
Every node can be assigned to exercise roles. A node may then forward, drop, modify or generate traffic based on ingress port, existing layer, or any header 
field value of the packet. 
A role can be specified from a stand-alone configuration file. All roles used in the simulation process must be in the specified role folder (default is config/roles as mentioned above). \
Basic existing roles are: bridge, switch, static_router 

## Performance
I generated 1000 packets in a simple configuration within 0.017 seconds and 1000000 packets in 9.657 seconds. 
For measurement, i used the GNU time command on a Notebook with an Intel(R) Core(TM) i7-4600U CPU and 8GB RAM running Fedora 30.
