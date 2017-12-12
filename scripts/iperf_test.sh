#!/bin/bash

# TOPOLOGY:
# =========
#    _________                                              _____________
#   |         |     host-vpp2                              |             |
#   |   VPP   |--- 172.16.2.1 --------vpp2 namespace-------|  veth_vpp2  |
#   |_________|                                            | 172.16.2.2  |
#        |                                                 |_____________|
#     host-vpp1
#    172.16.1.1
#        |
#        |
#  vpp1 namespace
#        |
#   _____|_______
#  |             |
#  |  veth_vpp1  |
#  | 172.16.1.2  |
#  |_____________|
#

# create namespaces
sudo ip netns add vpp1
sudo ip netns add vpp2

# create and configure first veth pair
sudo ip link add name veth_vpp1 type veth peer name vpp1
sudo ip link set dev vpp1 up
sudo ip link set dev veth_vpp1 up netns vpp1

sudo ip netns exec vpp1 \
  bash -c "
    ip link set dev lo up
    ip addr add 172.16.1.2/24 dev veth_vpp1
    ip route add 172.16.2.0/24 via 172.16.1.1
  "

# create and configure second veth pair
sudo ip link add name veth_vpp2 type veth peer name vpp2
sudo ip link set dev vpp2 up
sudo ip link set dev veth_vpp2 up netns vpp2

sudo ip netns exec vpp2 \
  bash -c "
    ip link set dev lo up
    ip addr add 172.16.2.2/24 dev veth_vpp2
    ip route add 172.16.1.0/24 via 172.16.2.1
  "

# create and configure vpp instance
sudo vpp unix { log /tmp/vpp.log cli-listen /run/vpp/cli-vpp.sock } api-segment { prefix vpp } plugins { plugin dpdk_plugin.so { disable } }
sleep 1

sudo vppctl -s /run/vpp/cli-vpp.sock create host-interface name vpp1
sudo vppctl -s /run/vpp/cli-vpp.sock create host-interface name vpp2
sudo vppctl -s /run/vpp/cli-vpp.sock set int state host-vpp1 up
sudo vppctl -s /run/vpp/cli-vpp.sock set int state host-vpp2 up
sudo vppctl -s /run/vpp/cli-vpp.sock set int ip address host-vpp1 172.16.1.1/24
sudo vppctl -s /run/vpp/cli-vpp.sock set int ip address host-vpp2 172.16.2.1/24

# enable and configure mmb
sudo vppctl -s /run/vpp/cli-vpp.sock mmb enable host-vpp1
sudo vppctl -s /run/vpp/cli-vpp.sock mmb enable host-vpp2
sudo vppctl -s /run/vpp/cli-vpp.sock trace add af-packet-input 10

# iperf3 server & client
sudo ip netns exec vpp2 iperf3 -s -D
sudo ip netns exec vpp1 iperf3 -c 172.16.2.2 -4 -k 1 --get-server-output
#sudo ip netns exec vpp1 ping 172.16.2.1 -c 1 #+1 "in" pkt, +1 "out" pkt in mmb (host-vpp1 in/out)
#sudo ip netns exec vpp1 ping 172.16.2.2 -c 1 #+2 "in" pkts, +2 "out" pkts in mmb (host-vpp1 in, host-vpp2 out, host-vpp2 in, host-vpp1 out)

# display results
sudo vppctl -s /run/vpp/cli-vpp.sock sh run
sudo vppctl -s /run/vpp/cli-vpp.sock sh tr

