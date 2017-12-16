#!/bin/bash

# enable kernel forwarding
sudo sysctl -w net.ipv4.ip_forward=1
sysctl -p

# create vpp instance
sudo vpp unix { log /tmp/vpp.log cli-listen /run/vpp/cli-vpp.sock } api-segment { prefix vpp } plugins { plugin dpdk_plugin.so { disable } }
sleep 1

# ns0 namespace
sudo ip netns add ns0
sudo ip link add vpp0 type veth peer name vethns0
sudo ip link set vethns0 netns ns0
sudo ip netns exec ns0 ip link set lo up
sudo ip netns exec ns0 ip link set vethns0 up
sudo ip netns exec ns0 ip addr add 10.0.0.1/24 dev vethns0
sudo ip netns exec ns0 ethtool -K vethns0 rx off tx off
sudo ethtool --offload vpp0 rx off tx off
sudo ip link set vpp0 up

# switching
sudo vppctl -s /run/vpp/cli-vpp.sock create host-interface name vpp0
sudo vppctl -s /run/vpp/cli-vpp.sock set interface state host-vpp0 up
sudo vppctl -s /run/vpp/cli-vpp.sock set interface l2 bridge host-vpp0 1
sudo vppctl -s /run/vpp/cli-vpp.sock create loopback interface
sudo vppctl -s /run/vpp/cli-vpp.sock set interface l2 bridge loop0 1 bvi
sudo vppctl -s /run/vpp/cli-vpp.sock set interface state loop0 up
sudo vppctl -s /run/vpp/cli-vpp.sock set interface ip address loop0 10.0.0.10/24

# ns2 namespace
sudo vppctl -s /run/vpp/cli-vpp.sock tap connect tap0
sudo ip netns add ns2
sudo ip link set tap0 netns ns2
sudo ip netns exec ns2 ip link set lo up
sudo ip netns exec ns2 ip link set tap0 up
sudo ip netns exec ns2 ip addr add 10.0.1.1/24 dev tap0

# routing
sudo vppctl -s /run/vpp/cli-vpp.sock set interface state tap-0 up
sudo vppctl -s /run/vpp/cli-vpp.sock set interface ip address tap-0 10.0.1.10/24
sudo ip netns exec ns0 ip route add default via 10.0.0.10
sudo ip netns exec ns2 ip route add default via 10.0.1.10

# fill ARP cache
sudo ip netns exec ns0 ping 10.0.1.1 -c 5
sudo ip netns exec ns2 ping 10.0.0.1 -c 5

# enable MMB
sudo vppctl -s /run/vpp/cli-vpp.sock mmb enable host-vpp0
sudo vppctl -s /run/vpp/cli-vpp.sock mmb enable tap-0
#sudo vppctl -s /run/vpp/cli-vpp.sock trace add af-packet-input 100
#sudo vppctl -s /run/vpp/cli-vpp.sock sh run
#sudo vppctl -s /run/vpp/cli-vpp.sock sh tr

# iperf server
sudo ip netns exec ns2 iperf3 -s -D -B 10.0.1.1
sleep 1

# iperf client (test & results)
sudo ip netns exec ns0 iperf3 -c 10.0.1.1 -4 -k 1 -V --get-server-output
sleep 1
#sudo vppctl -s /run/vpp/cli-vpp.sock sh run
#sudo vppctl -s /run/vpp/cli-vpp.sock sh tr
#sleep 1

# cleanup
sudo kill -9 $(ps -aef | grep -v grep | grep iperf3 | awk '{print $2}')
sudo kill -9 $(ps -aef | grep -v grep | grep vpp | awk '{print $2}')
sudo ip link del vpp0
sudo ip netns del ns0
sudo ip netns del ns2

