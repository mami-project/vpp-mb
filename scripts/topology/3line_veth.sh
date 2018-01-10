#!/bin/bash
#
# Set up a 3 lined up nodes topology with
# - two namespaces (ns0, ns1), two veth interface pairs, the endpoints
#   addresses are 10.0.0.1, 10.0.1.1
# - one middle vpp instance with mmb enabled
#

echo
echo "Topology initialization & configuration..."

# enable kernel forwarding
sudo sysctl -w net.ipv4.ip_forward=1
sysctl -p

# create vpp instance
sudo vpp unix { log /tmp/vpp.log cli-listen /run/vpp/cli-vpp.sock } api-segment { prefix vpp } plugins { plugin dpdk_plugin.so { disable } }
sleep 1

# delete previous incarnations if they exist
sudo ip link del dev veth_vpp1
sudo ip link del dev veth_vpp2
sudo ip netns del ns0
sudo ip netns del ns1

#create namespaces
sudo ip netns add ns0
sudo ip netns add ns1

# create and configure 1st veth pair
sudo ip link add name veth_vpp1 type veth peer name vpp1
sudo ip link set dev vpp1 up
sudo ip link set dev veth_vpp1 up netns ns0

sudo ip netns exec ns0 \
  bash -c "
    ip link set dev lo up
    ip addr add 10.0.0.1/24 dev veth_vpp1
    ip route add 10.0.1.0/24 via 10.0.0.10
    ethtool -K veth_vpp1 rx off tx off
"

# create and configure 2st veth pair
sudo ip link add name veth_vpp2 type veth peer name vpp2
sudo ip link set dev vpp2 up
sudo ip link set dev veth_vpp2 up netns ns1

sudo ip netns exec ns1 \
  bash -c "
    ip link set dev lo up
    ip addr add 10.0.1.1/24 dev veth_vpp2
    ip route add 10.0.0.0/24 via 10.0.1.10
    ethtool -K veth_vpp2 rx off tx off
"

# switching
sudo vppctl -s /run/vpp/cli-vpp.sock create host-interface name vpp1
sudo vppctl -s /run/vpp/cli-vpp.sock create host-interface name vpp2
sudo vppctl -s /run/vpp/cli-vpp.sock set interface state host-vpp1 up
sudo vppctl -s /run/vpp/cli-vpp.sock set interface state host-vpp2 up
sudo vppctl -s /run/vpp/cli-vpp.sock set interface ip address host-vpp1 10.0.0.10/24
sudo vppctl -s /run/vpp/cli-vpp.sock set interface ip address host-vpp2 10.0.1.10/24

# fill ARP cache
sudo ip netns exec ns0 ping 10.0.1.1 -c 5
sudo ip netns exec ns1 ping 10.0.0.1 -c 5

# enable MMB
sudo vppctl -s /run/vpp/cli-vpp.sock mmb enable host-vpp1
sudo vppctl -s /run/vpp/cli-vpp.sock mmb enable host-vpp2
