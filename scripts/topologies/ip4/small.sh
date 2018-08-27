#!/bin/bash
#
#
# Topology 1
#
# server addr: 10.0.0.10

# VPP Nodes
sudo vpp unix { cli-listen /run/vpp/cli-vpp1.sock } api-segment { prefix vpp1 } 
sleep 1

# veth interface between host and vpp1
sudo ip link add name vpp1out type veth peer name hostvpp1
sudo ip link set dev vpp1out up
sudo ip link set dev hostvpp1 up
sudo ethtool -K hostvpp1 rx off tx off
sudo ip addr add 10.100.100.1/24 dev hostvpp1
sudo ip route add 10.0.0.0/24 via 10.100.100.2
sudo ip route add 20.0.0.0/8 via 10.100.100.2

# host interface between host and vpp1
sudo vppctl -s /run/vpp/cli-vpp1.sock create host-interface name vpp1out
sudo vppctl -s /run/vpp/cli-vpp1.sock set int state host-vpp1out up
sudo vppctl -s /run/vpp/cli-vpp1.sock set int ip address host-vpp1out 10.100.100.2/24

# connect vpp instances
sudo vppctl -s /run/vpp/cli-vpp1.sock create memif socket /run/vpp/memif-vpp1vpp2 master
sudo vppctl -s /run/vpp/cli-vpp1.sock set int state memif0/0 up
sudo vppctl -s /run/vpp/cli-vpp1.sock set int ip address memif0/0 10.0.0.15/24

sudo vppctl -s /run/vpp/cli-vpp1.sock ip route add 10.0.0.0/24 via 20.100.2.12
sudo vppctl -s /run/vpp/cli-vpp1.sock ip route add 10.100.100.1/24 via 10.100.100.2


#create namespace for endpoint 
sudo ip netns add ns0 
# connect to VPP6
sudo ip link add name vpp1host type veth peer name vpp1
sudo ip link set dev vpp1 up
sudo ip link set dev vpp1host up netns ns0

sudo ip netns exec ns0 \
  bash -c "
    ip link set dev lo up
    ip addr add 10.0.0.10/24 dev vpp1host
    ip route add default via 10.0.0.11
    ethtool -K vpp1host rx off tx off
"
# veth interface between s and vpp6
sudo vppctl -s /run/vpp/cli-vpp1.sock create host-interface name vpp1
sudo vppctl -s /run/vpp/cli-vpp1.sock set interface state host-vpp1 up
sudo vppctl -s /run/vpp/cli-vpp1.sock set interface ip address host-vpp1 10.0.0.11/24

sudo vppctl -s /run/vpp/cli-vpp1.sock mmb enable host-vpp1
sudo vppctl -s /run/vpp/cli-vpp1.sock mmb enable memif0/0

sudo server/run.sh &


