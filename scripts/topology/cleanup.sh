#!/bin/bash

echo
echo "Cleaning everything up.."

# cleanup
sudo kill -9 $(ps -aef | grep -v grep | grep iperf3 | awk '{print $2}')
sudo kill -9 $(ps -aef | grep -v grep | grep vpp | awk '{print $2}')

sudo ip link del dev veth_vpp1
sudo ip link del dev veth_vpp2

sudo ip link del dev tap0
sudo ip link del dev tap1

sudo ip netns del ns0
sudo ip netns del ns1

