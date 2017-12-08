#!/bin/bash

# TOPOLOGY:
# =========
#    _________                                                      __________
#   |         |    host-vppiperf                     iperfvpp      |          |
#   |   VPP   |--- 10.10.2.1/24 ------------------ 10.10.2.2/24 ---|  SERVER  |
#   |_________|                                                    |__________|
#        |
#    host-vppout
#   10.10.1.2/24
#        |
#        |
#        |
#        |
#  vpphost (CLIENT)
#   10.10.1.1/24
#

## create vpp and connect it to host
sudo vpp unix { log /tmp/vpp.log cli-listen /run/vpp/cli-vpp.sock } api-segment { prefix vpp } plugins { plugin dpdk_plugin.so { disable } }
sleep 1

# veth interface between host and vpp
sudo ip link add name vppout type veth peer name vpphost
sudo ip link set dev vppout up
sudo ip link set dev vpphost up
sudo ip addr add 10.10.1.1/24 dev vpphost

# host interface between host and vpp
sudo vppctl -s /run/vpp/cli-vpp.sock create host-interface name vppout
sudo vppctl -s /run/vpp/cli-vpp.sock set int state host-vppout up
sudo vppctl -s /run/vpp/cli-vpp.sock set int ip address host-vppout 10.10.1.2/24

## create iperf server and connect it to vpp
sudo ip link add name vppiperf type veth peer name iperfvpp
sudo ip link set dev vppiperf up
sudo ip link set dev iperfvpp up
sudo ip addr add 10.10.2.2/24 dev iperfvpp

sudo vppctl -s /run/vpp/cli-vpp.sock create host-interface name vppiperf
sudo vppctl -s /run/vpp/cli-vpp.sock set int state host-vppiperf up
sudo vppctl -s /run/vpp/cli-vpp.sock set int ip address host-vppiperf 10.10.2.1/24

#sudo ip route add 10.10.2.0/24 via 10.10.1.2
#sudo ip route add 10.10.1.0/24 via 10.10.2.1

sudo vppctl -s /run/vpp/cli-vpp.sock mmb enable host-vppout
sudo vppctl -s /run/vpp/cli-vpp.sock mmb enable host-vppiperf
iperf3 -s -B 10.10.2.2 -D
iperf3 -c 10.10.2.2 -B 10.10.1.1 -u -4 -k 10
sudo vppctl -s /run/vpp/cli-vpp.sock sh run

