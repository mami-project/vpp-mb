#!/bin/bash
#
#
# medium Topology
#
# server addr: 10.0.0.10

# enable kernel forwarding
sudo sysctl -w net.ipv4.ip_forward=1
sysctl -p

# VPP Nodes
sudo vpp unix { log /tmp/vpp1.log cli-listen /run/vpp/cli-vpp1.sock } api-segment { prefix vpp1 }
sudo vpp unix { log /tmp/vpp2.log cli-listen /run/vpp/cli-vpp2.sock } api-segment { prefix vpp2 } plugins { plugin nat_plugin.so { disable } }
sudo vpp unix { log /tmp/vpp3.log cli-listen /run/vpp/cli-vpp3.sock } api-segment { prefix vpp3 } plugins { plugin nat_plugin.so { disable } }
sudo vpp unix { log /tmp/vpp4.log cli-listen /run/vpp/cli-vpp4.sock } api-segment { prefix vpp4 } plugins { plugin nat_plugin.so { disable } }
sudo vpp unix { log /tmp/vpp5.log cli-listen /run/vpp/cli-vpp5.sock } api-segment { prefix vpp5 } plugins { plugin nat_plugin.so { disable } }
sudo vpp unix { log /tmp/vpp6.log cli-listen /run/vpp/cli-vpp6.sock } api-segment { prefix vpp6 } plugins { plugin nat_plugin.so { disable } }
sleep 1

# veth interface between host and vpp1
sudo ip link add name vpp1out type veth peer name vpp1host
sudo ip link set dev vpp1out up
sudo ip link set dev vpp1host up
sudo ethtool -K vpp1host rx off tx off
sudo ip addr add 10.100.100.1/24 dev vpp1host
sudo ip route add 10.0.0.0/24 via 10.100.100.2
sudo ip route add 20.0.0.0/8 via 10.100.100.2
sudo ip route add 30.0.0.0/8 via 10.100.100.2

# host interface between host and vpp1
sudo vppctl -s /run/vpp/cli-vpp1.sock create host-interface name vpp1out
sudo vppctl -s /run/vpp/cli-vpp1.sock set int state host-vpp1out up
sudo vppctl -s /run/vpp/cli-vpp1.sock set int ip address host-vpp1out 10.100.100.2/24

# connect vpp instances
sudo vppctl -s /run/vpp/cli-vpp1.sock create memif socket /run/vpp/memif-vpp1vpp2 master
sudo vppctl -s /run/vpp/cli-vpp1.sock set int state memif0/0 up
sudo vppctl -s /run/vpp/cli-vpp1.sock set int ip address memif0/0 20.100.2.10/24

sudo vppctl -s /run/vpp/cli-vpp1.sock ip route add 10.0.0.0/24 via 20.100.2.12
sudo vppctl -s /run/vpp/cli-vpp1.sock ip route add 20.0.0.0/16 via 20.100.2.12
sudo vppctl -s /run/vpp/cli-vpp1.sock ip route add 30.0.0.0/16 via 20.100.2.12
sudo vppctl -s /run/vpp/cli-vpp1.sock mmb enable host-vpp1out
sudo vppctl -s /run/vpp/cli-vpp1.sock mmb enable memif0/0

sudo vppctl -s /run/vpp/cli-vpp2.sock create memif socket /run/vpp/memif-vpp1vpp2 slave
sudo vppctl -s /run/vpp/cli-vpp2.sock set int state memif0/0 up
sudo vppctl -s /run/vpp/cli-vpp2.sock set int ip address memif0/0 20.100.2.12/24
sudo vppctl -s /run/vpp/cli-vpp2.sock create memif socket /run/vpp/memif-vpp2vpp3 master
sudo vppctl -s /run/vpp/cli-vpp2.sock set int state memif1/0 up
sudo vppctl -s /run/vpp/cli-vpp2.sock set int ip address memif1/0 20.0.3.13/24

sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 10.100.100.1/24 via 20.100.2.10
sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 20.100.2.0/24 via 20.100.2.10
sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 10.0.0.0/24 via 20.0.3.10
sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 30.0.0.0/16 via 20.0.3.10
sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 20.0.2.0/24 via 20.0.3.10

sudo vppctl -s /run/vpp/cli-vpp3.sock create memif socket /run/vpp/memif-vpp2vpp3 slave
sudo vppctl -s /run/vpp/cli-vpp3.sock set int state memif0/0 up
sudo vppctl -s /run/vpp/cli-vpp3.sock set int ip address memif0/0 20.0.3.10/24
sudo vppctl -s /run/vpp/cli-vpp3.sock create memif socket /run/vpp/memif-vpp3vpp4 master
sudo vppctl -s /run/vpp/cli-vpp3.sock set int state memif1/0 up
sudo vppctl -s /run/vpp/cli-vpp3.sock set int ip address memif1/0 20.0.2.1/24

sudo vppctl -s /run/vpp/cli-vpp3.sock ip route add 10.100.100.1/24 via 20.0.3.13
sudo vppctl -s /run/vpp/cli-vpp3.sock ip route add 20.100.2.0/24 via 20.0.3.13
sudo vppctl -s /run/vpp/cli-vpp3.sock ip route add 10.0.0.0/24 via 20.0.2.2
sudo vppctl -s /run/vpp/cli-vpp3.sock ip route add 30.0.0.0/16 via 20.0.2.2

sudo vppctl -s /run/vpp/cli-vpp4.sock create memif socket /run/vpp/memif-vpp3vpp4 slave
sudo vppctl -s /run/vpp/cli-vpp4.sock set int state memif0/0 up
sudo vppctl -s /run/vpp/cli-vpp4.sock set int ip address memif0/0 20.0.2.2/24
sudo vppctl -s /run/vpp/cli-vpp4.sock create memif socket /run/vpp/memif-vpp4vpp5 master
sudo vppctl -s /run/vpp/cli-vpp4.sock set int state memif1/0 up
sudo vppctl -s /run/vpp/cli-vpp4.sock set int ip address memif1/0 30.0.0.5/24

sudo vppctl -s /run/vpp/cli-vpp4.sock ip route add 10.100.100.1/24 via 20.0.2.1
sudo vppctl -s /run/vpp/cli-vpp4.sock ip route add 20.0.3.0/24 via 20.0.2.1
sudo vppctl -s /run/vpp/cli-vpp4.sock ip route add 20.100.2.0/24 via 20.0.2.1
sudo vppctl -s /run/vpp/cli-vpp4.sock ip route add 10.0.0.0/24 via 30.0.0.6
sudo vppctl -s /run/vpp/cli-vpp4.sock ip route add 30.100.2.0/24 via 30.0.0.6

sudo vppctl -s /run/vpp/cli-vpp5.sock create memif socket /run/vpp/memif-vpp4vpp5 slave
sudo vppctl -s /run/vpp/cli-vpp5.sock set int state memif0/0 up
sudo vppctl -s /run/vpp/cli-vpp5.sock set int ip address memif0/0 30.0.0.6/24
sudo vppctl -s /run/vpp/cli-vpp5.sock create memif socket /run/vpp/memif-vpp5vpp6 master
sudo vppctl -s /run/vpp/cli-vpp5.sock set int state memif1/0 up
sudo vppctl -s /run/vpp/cli-vpp5.sock set int ip address memif1/0 30.100.2.3/24

sudo vppctl -s /run/vpp/cli-vpp5.sock ip route add 10.100.100.1/24 via 30.0.0.5
sudo vppctl -s /run/vpp/cli-vpp5.sock ip route add 20.0.0.0/16 via 30.0.0.5
sudo vppctl -s /run/vpp/cli-vpp5.sock ip route add 20.100.2.0/24 via 30.0.0.5
sudo vppctl -s /run/vpp/cli-vpp5.sock ip route add 10.0.0.0/24 via 30.100.2.2

sudo vppctl -s /run/vpp/cli-vpp6.sock create memif socket /run/vpp/memif-vpp5vpp6 slave
sudo vppctl -s /run/vpp/cli-vpp6.sock set int state memif0/0 up
sudo vppctl -s /run/vpp/cli-vpp6.sock set int ip address memif0/0 30.100.2.2/24

sudo vppctl -s /run/vpp/cli-vpp6.sock ip route add 10.100.100.1/24 via 30.100.2.3
sudo vppctl -s /run/vpp/cli-vpp6.sock ip route add 20.0.0.0/16 via 30.100.2.3
sudo vppctl -s /run/vpp/cli-vpp6.sock ip route add 20.100.2.0/24 via 30.100.2.3
sudo vppctl -s /run/vpp/cli-vpp6.sock ip route add 30.0.0.0/24 via 30.100.2.3

#create namespace for endpoint 
sudo ip netns add ns0 
# connect to VPP6
sudo ip link add name vpp6host type veth peer name vpp6
sudo ip link set dev vpp6 up
sudo ip link set dev vpp6host up netns ns0

sudo ip netns exec ns0 \
  bash -c "
    ip link set dev lo up
    ip addr add 10.0.0.10/24 dev vpp6host
    ip route add default via 10.0.0.11
    ethtool -K vpp6host rx off tx off
"
# veth interface between s and vpp6
sudo vppctl -s /run/vpp/cli-vpp6.sock create host-interface name vpp6
sudo vppctl -s /run/vpp/cli-vpp6.sock set interface state host-vpp6 up
sudo vppctl -s /run/vpp/cli-vpp6.sock set interface ip address host-vpp6 10.0.0.11/24

