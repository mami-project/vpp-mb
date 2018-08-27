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

# host interface between host and vpp1
sudo vppctl -s /run/vpp/cli-vpp1.sock create host-interface name vpp1out
sudo vppctl -s /run/vpp/cli-vpp1.sock set int state host-vpp1out up
sudo vppctl -s /run/vpp/cli-vpp1.sock set int ip address host-vpp1out 10.100.100.2/24

#create namespace for endpoint 
sudo ip netns add ns0 
sudo ip link add name outvpp1 type veth peer name vpp1host
sudo ip link set dev vpp1host up 
sudo ip link set dev outvpp1 netns ns0

sudo ip netns exec ns0 \
  bash -c "
    ip link set dev lo up
    ip link set dev outvpp1 up
    ip addr add 10.0.0.10/24 dev outvpp1
    ip route add default via 10.0.0.11
    ethtool -K outvpp1 rx off tx off
"
# veth interface between s and vpp1
sudo vppctl -s /run/vpp/cli-vpp1.sock create host-interface name vpp1host
sudo vppctl -s /run/vpp/cli-vpp1.sock set interface state host-vpp1host up
sudo vppctl -s /run/vpp/cli-vpp1.sock set interface ip address host-vpp1host 10.0.0.11/24

sudo vppctl -s /run/vpp/cli-vpp1.sock mmb enable host-vpp1out
sudo vppctl -s /run/vpp/cli-vpp1.sock mmb enable host-vpp1host

sudo server/run.sh &


