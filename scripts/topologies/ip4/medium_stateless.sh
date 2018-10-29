#!/bin/bash
#
#
# Topology 1
#
# server addr: 10.0.0.10

# VPP Nodes
sudo vpp unix { cli-listen /run/vpp/cli-vpp1.sock } api-segment { prefix vpp1 } plugins { plugin mmb_plugin.so { disable } }
sudo vpp unix { cli-listen /run/vpp/cli-vpp2.sock } api-segment { prefix vpp2 } 
sudo vpp unix { cli-listen /run/vpp/cli-vpp3.sock } api-segment { prefix vpp3 } plugins { plugin mmb_plugin.so { disable } }
sudo vpp unix { cli-listen /run/vpp/cli-vpp4.sock } api-segment { prefix vpp4 } 
sudo vpp unix { cli-listen /run/vpp/cli-vpp5.sock } api-segment { prefix vpp5 } plugins { plugin mmb_plugin.so { disable } }
sudo vpp unix { cli-listen /run/vpp/cli-vpp6.sock } api-segment { prefix vpp6 } 
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
sudo vppctl -s /run/vpp/cli-vpp1.sock create memif socket id 1 filename /run/vpp/memif1.sock
sudo vppctl -s /run/vpp/cli-vpp1.sock create interface memif id 0 socket-id 1 master 
sudo vppctl -s /run/vpp/cli-vpp1.sock set int state memif1/0 up
sudo vppctl -s /run/vpp/cli-vpp1.sock set int ip address memif1/0 20.100.2.10/24

sudo vppctl -s /run/vpp/cli-vpp1.sock ip route add 10.0.0.0/24 via 20.100.2.12
sudo vppctl -s /run/vpp/cli-vpp1.sock ip route add 20.0.0.0/16 via 20.100.2.12
sudo vppctl -s /run/vpp/cli-vpp1.sock ip route add 30.0.0.0/16 via 20.100.2.12

sudo vppctl -s /run/vpp/cli-vpp2.sock create memif socket id 1 filename /run/vpp/memif1.sock
sudo vppctl -s /run/vpp/cli-vpp2.sock create memif socket id 2 filename /run/vpp/memif2.sock
sudo vppctl -s /run/vpp/cli-vpp2.sock create interface memif id 0 socket-id 1 slave
sudo vppctl -s /run/vpp/cli-vpp2.sock set int state memif1/0 up
sudo vppctl -s /run/vpp/cli-vpp2.sock set int ip address memif1/0 20.100.2.12/24
sudo vppctl -s /run/vpp/cli-vpp2.sock create interface memif id 0 socket-id 2 master
sudo vppctl -s /run/vpp/cli-vpp2.sock set int state memif2/0 up
sudo vppctl -s /run/vpp/cli-vpp2.sock set int ip address memif2/0 20.0.3.13/24

sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 10.100.100.1/24 via 20.100.2.10
sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 20.100.2.0/24 via 20.100.2.10
sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 10.0.0.0/24 via 20.0.3.10
sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 30.0.0.0/16 via 20.0.3.10
sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 20.0.2.0/24 via 20.0.3.10
sudo vppctl -s /run/vpp/cli-vpp2.sock mmb enable memif1/0
sudo vppctl -s /run/vpp/cli-vpp2.sock mmb enable memif2/0
sudo vppctl -s /run/vpp/cli-vpp2.sock mmb add tcp-syn tcp-opt-mss strip tcp-opt-mss add tcp-opt-mss 1452

sudo vppctl -s /run/vpp/cli-vpp3.sock create memif socket id 2 filename /run/vpp/memif2.sock
sudo vppctl -s /run/vpp/cli-vpp3.sock create memif socket id 3 filename /run/vpp/memif3.sock
sudo vppctl -s /run/vpp/cli-vpp3.sock create interface memif id 0 socket-id 2 slave
sudo vppctl -s /run/vpp/cli-vpp3.sock set int state memif2/0 up
sudo vppctl -s /run/vpp/cli-vpp3.sock set int ip address memif2/0 20.0.3.10/24
sudo vppctl -s /run/vpp/cli-vpp3.sock create interface memif id 0 socket-id 3 master
sudo vppctl -s /run/vpp/cli-vpp3.sock set int state memif3/0 up
sudo vppctl -s /run/vpp/cli-vpp3.sock set int ip address memif3/0 20.0.2.1/24

sudo vppctl -s /run/vpp/cli-vpp3.sock ip route add 10.100.100.1/24 via 20.0.3.13
sudo vppctl -s /run/vpp/cli-vpp3.sock ip route add 20.100.2.0/24 via 20.0.3.13
sudo vppctl -s /run/vpp/cli-vpp3.sock ip route add 10.0.0.0/24 via 20.0.2.2
sudo vppctl -s /run/vpp/cli-vpp3.sock ip route add 30.0.0.0/16 via 20.0.2.2

sudo vppctl -s /run/vpp/cli-vpp4.sock create memif socket id 3 filename /run/vpp/memif3.sock
sudo vppctl -s /run/vpp/cli-vpp4.sock create memif socket id 4 filename /run/vpp/memif4.sock
sudo vppctl -s /run/vpp/cli-vpp4.sock create interface memif id 0 socket-id 3 slave
sudo vppctl -s /run/vpp/cli-vpp4.sock set int state memif3/0 up
sudo vppctl -s /run/vpp/cli-vpp4.sock set int ip address memif3/0 20.0.2.2/24
sudo vppctl -s /run/vpp/cli-vpp4.sock create interface memif id 0 socket-id 4 master
sudo vppctl -s /run/vpp/cli-vpp4.sock set int state memif4/0 up
sudo vppctl -s /run/vpp/cli-vpp4.sock set int ip address memif4/0 30.0.0.5/24
sudo vppctl -s /run/vpp/cli-vpp4.sock mmb enable memif3/0
sudo vppctl -s /run/vpp/cli-vpp4.sock mmb enable memif4/0
sudo vppctl -s /run/vpp/cli-vpp4.sock mmb add ip-ecn 1 mod ip-ecn 3 mod ip-dscp 2
sudo vppctl -s /run/vpp/cli-vpp4.sock mmb add ip-ecn 2 mod ip-ecn 3 mod ip-dscp 2

sudo vppctl -s /run/vpp/cli-vpp4.sock ip route add 10.100.100.1/24 via 20.0.2.1
sudo vppctl -s /run/vpp/cli-vpp4.sock ip route add 20.0.3.0/24 via 20.0.2.1
sudo vppctl -s /run/vpp/cli-vpp4.sock ip route add 20.100.2.0/24 via 20.0.2.1
sudo vppctl -s /run/vpp/cli-vpp4.sock ip route add 10.0.0.0/24 via 30.0.0.6
sudo vppctl -s /run/vpp/cli-vpp4.sock ip route add 30.100.2.0/24 via 30.0.0.6

sudo vppctl -s /run/vpp/cli-vpp5.sock create memif socket id 4 filename /run/vpp/memif4.sock
sudo vppctl -s /run/vpp/cli-vpp5.sock create memif socket id 5 filename /run/vpp/memif5.sock
sudo vppctl -s /run/vpp/cli-vpp5.sock create interface memif id 0 socket-id 4 slave
sudo vppctl -s /run/vpp/cli-vpp5.sock set int state memif4/0 up
sudo vppctl -s /run/vpp/cli-vpp5.sock set int ip address memif4/0 30.0.0.6/24
sudo vppctl -s /run/vpp/cli-vpp5.sock create interface memif id 0 socket-id 5 master
sudo vppctl -s /run/vpp/cli-vpp5.sock set int state memif5/0 up
sudo vppctl -s /run/vpp/cli-vpp5.sock set int ip address memif5/0 30.100.2.3/24

sudo vppctl -s /run/vpp/cli-vpp5.sock ip route add 10.100.100.1/24 via 30.0.0.5
sudo vppctl -s /run/vpp/cli-vpp5.sock ip route add 20.0.0.0/16 via 30.0.0.5
sudo vppctl -s /run/vpp/cli-vpp5.sock ip route add 20.100.2.0/24 via 30.0.0.5
sudo vppctl -s /run/vpp/cli-vpp5.sock ip route add 10.0.0.0/24 via 30.100.2.2

sudo vppctl -s /run/vpp/cli-vpp6.sock create memif socket id 5 filename /run/vpp/memif5.sock
sudo vppctl -s /run/vpp/cli-vpp6.sock create interface memif id 0 socket-id 5 slave
sudo vppctl -s /run/vpp/cli-vpp6.sock set int state memif5/0 up
sudo vppctl -s /run/vpp/cli-vpp6.sock set int ip address memif5/0 30.100.2.2/24

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

sudo vppctl -s /run/vpp/cli-vpp6.sock mmb enable host-vpp6
sudo vppctl -s /run/vpp/cli-vpp6.sock mmb enable memif5/0

sudo vppctl -s /run/vpp/cli-vpp6.sock mmb add udp-dport 80 drop
sudo vppctl -s /run/vpp/cli-vpp6.sock mmb add udp-dport 8000 drop
sudo vppctl -s /run/vpp/cli-vpp6.sock mmb add udp-dport 8080 drop
sudo vppctl -s /run/vpp/cli-vpp6.sock mmb add udp-dport 443 drop
sudo vppctl -s /run/vpp/cli-vpp6.sock mmb add udp-dport 135 drop
sudo vppctl -s /run/vpp/cli-vpp6.sock mmb add udp-dport 139 drop
sudo vppctl -s /run/vpp/cli-vpp6.sock mmb add udp-dport 161 drop
sudo vppctl -s /run/vpp/cli-vpp6.sock mmb add udp-dport 162 drop

sudo vppctl -s /run/vpp/cli-vpp6.sock mmb add tcp-dport 53 drop
sudo vppctl -s /run/vpp/cli-vpp6.sock mmb add tcp-dport 25 drop
sudo vppctl -s /run/vpp/cli-vpp6.sock mmb add tcp-dport 135 drop
sudo vppctl -s /run/vpp/cli-vpp6.sock mmb add tcp-dport 139 drop
sudo vppctl -s /run/vpp/cli-vpp6.sock mmb add tcp-dport 445 drop
sudo vppctl -s /run/vpp/cli-vpp6.sock mmb add tcp-dport 161 drop
sudo vppctl -s /run/vpp/cli-vpp6.sock mmb add tcp-dport 162 drop

sudo server/run.sh &


