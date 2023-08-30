#/bin/bash

# simple_<protocol>.yaml: tests <protocol>; simple topology, only one user defined traffic, all header field distributions static, no special delay distributions
# simple_all_protocols.yaml: tests all available protocols (eth, arp, ipv4, ipv6, udp, tcp, dhcp, dns) with simple configuration as above
# tbd: test all distribution types for all delays/header fields
# tbd: test all available roles (bridge, in future: switch, router, arp-node, dhcp-/dns-client and -server, eBPF-based configurable roles)

for f in ./*.yaml; do
  ../../stegorator $f ../../pcaps/$f.pcap
done
