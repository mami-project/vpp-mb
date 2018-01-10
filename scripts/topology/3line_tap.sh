#!/bin/bash
#
# Set up a 3 lined up nodes topology with
# - two namespaces (ns0, ns1), two TAP interfaces, the endpoints
#   addresses are 10.0.0.1, 10.0.1.1
# - one middle vpp instance with mmb enabled
#

echo
echo "Topology initialization & configuration..."

# delete existing namespaces
sudo ip link del dev tap0
sudo ip link del dev tap1
sudo ip netns del ns0
sudo ip netns del ns1

# enable kernel forwarding
sudo sysctl -w net.ipv4.ip_forward=1
sysctl -p

# create vpp instance
sudo vpp unix { log /tmp/vpp.log cli-listen /run/vpp/cli-vpp.sock } api-segment { prefix vpp } plugins { plugin dpdk_plugin.so { disable } }
sleep 1

# create tap interfaces
sudo vppctl -s /run/vpp/cli-vpp.sock tap connect tap0
sudo vppctl -s /run/vpp/cli-vpp.sock tap connect tap1
sudo vppctl -s /run/vpp/cli-vpp.sock set interface ip address tap-0 10.0.0.10/24
sudo vppctl -s /run/vpp/cli-vpp.sock set interface ip address tap-1 10.0.1.10/24
sudo vppctl -s /run/vpp/cli-vpp.sock set interface state tap-0 up
sudo vppctl -s /run/vpp/cli-vpp.sock set interface state tap-1 up

# create namespaces
sudo ip netns add ns0
sudo ip netns add ns1

# move tap ifs to namespaces
sudo ip link set tap0 netns ns0
sudo ip link set tap1 netns ns1

# configure ifs
sudo ip netns exec ns0 ip addr add 10.0.0.1/24 dev tap0
sudo ip netns exec ns0 ip link set tap0 up
sudo ip netns exec ns0 ip route add 10.0.1.0/24 via 10.0.0.10
sudo ip netns exec ns1 ip addr add 10.0.1.1/24 dev tap1
sudo ip netns exec ns1 ip link set tap1 up
sudo ip netns exec ns1 ip route add 10.0.0.0/24 via 10.0.1.10

# switching
#sudo vppctl -s /run/vpp/cli-vpp.sock set interface l2 bridge host-vpp0 1
#sudo vppctl -s /run/vpp/cli-vpp.sock create loopback interface
#sudo vppctl -s /run/vpp/cli-vpp.sock set interface l2 bridge loop0 1 bvi
#sudo vppctl -s /run/vpp/cli-vpp.sock set interface state loop0 up
#sudo vppctl -s /run/vpp/cli-vpp.sock set interface ip address loop0 10.0.0.10/24


# fill ARP cache
sudo ip netns exec ns0 ping 10.0.1.1 -c 5
sudo ip netns exec ns1 ping 10.0.0.1 -c 5

# enable MMB
sudo vppctl -s /run/vpp/cli-vpp.sock mmb enable tap-0
sudo vppctl -s /run/vpp/cli-vpp.sock mmb enable tap-1
