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
sudo ip addr add 2001::1/64 dev hostvpp1
sudo ip -6 route add 5555::/16 via 2001::5

# host interface between host and vpp1
sudo vppctl -s /run/vpp/cli-vpp1.sock create host-interface name vpp1out
sudo vppctl -s /run/vpp/cli-vpp1.sock set int state host-vpp1out up
sudo vppctl -s /run/vpp/cli-vpp1.sock set int ip address host-vpp1out 2001::5/64

#create namespace for endpoint
sudo ip netns add ns0
sudo ip link add name vpp1host type veth peer name vpp1
sudo ip link set dev vpp1 up
sudo ip link set dev vpp1host up netns ns0

sudo ip netns exec ns0 \
  bash -c "
    ip link set dev lo up
    ip addr add 5555::5/64 dev vpp1host
    ip -6 route add default via 5555::1
    ethtool -K vpp1host rx off tx off
"
# veth interface between s and vpp6
sudo vppctl -s /run/vpp/cli-vpp1.sock create host-interface name vpp1
sudo vppctl -s /run/vpp/cli-vpp1.sock set interface state host-vpp1 up
sudo vppctl -s /run/vpp/cli-vpp1.sock set interface ip address host-vpp1 5555::1/64

sudo vppctl -s /run/vpp/cli-vpp1.sock mmb enable host-vpp1
sudo vppctl -s /run/vpp/cli-vpp1.sock mmb enable host-vpp1out

sudo server/run.sh &


