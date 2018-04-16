#!/bin/bash

#####
# Simple topology: 2 vpps lined up to host
# host - vpp1 - vpp2
# 10.10.1.1 - 10.10.1.2|10.10.2.1 - 10.10.2.2
####

## create vpp1 and connect it to host
sudo vpp unix { log /tmp/vpp1.log cli-listen /run/vpp/cli-vpp1.sock } api-segment { prefix vpp1 } plugins { plugin dpdk_plugin.so { disable } }
sleep 1

# veth interface between host and vpp1
sudo ip link add name vpp1out type veth peer name vpp1host
sudo ip link set dev vpp1out up
sudo ip link set dev vpp1host up
sudo ip addr add 10.10.1.1/24 dev vpp1host
sudo ethtool -K vpp1host rx off tx off

# host interface between host and vpp1
sudo vppctl -s /run/vpp/cli-vpp1.sock create host-interface name vpp1out
sudo vppctl -s /run/vpp/cli-vpp1.sock set int state host-vpp1out up
sudo vppctl -s /run/vpp/cli-vpp1.sock set int ip address host-vpp1out 10.10.1.2/24


## create vpp2 and connect it to vpp1
sudo vpp unix { log /tmp/vpp2.log cli-listen /run/vpp/cli-vpp2.sock } api-segment { prefix vpp2 } plugins { plugin dpdk_plugin.so { disable } }
sleep 1

sudo vppctl -s /run/vpp/cli-vpp1.sock create memif socket /run/vpp/memif-vpp1vpp2 master
sudo vppctl -s /run/vpp/cli-vpp1.sock set int state memif0/0 up
sudo vppctl -s /run/vpp/cli-vpp1.sock set int ip address memif0/0 10.10.2.1/24

sudo vppctl -s /run/vpp/cli-vpp2.sock create memif socket /run/vpp/memif-vpp1vpp2 slave
sudo vppctl -s /run/vpp/cli-vpp2.sock set int state memif0/0 up
sudo vppctl -s /run/vpp/cli-vpp2.sock set int ip address memif0/0 10.10.2.2/24

# route host to vpp2 via vpp1 and reciprocally
sudo ip route add 10.10.2.0/24 via 10.10.1.2
sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 10.10.1.0/24 via 10.10.2.1

./plugin_test.sh
