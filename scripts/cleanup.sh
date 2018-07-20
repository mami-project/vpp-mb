#!/bin/bash

# generic cleanup script that covers the 3 available topologies

sudo service vpp stop
sudo pkill -9 vpp
sudo service vpp start

sudo ip link del dev veth_vpp1
sudo ip link del dev veth_vpp2
sudo ip link del dev vpp1out
sudo ip link del dev vpp6
sudo ip link del dev vpp8
sudo ip link del dev vpp19

sudo ip netns del ns0

sudo ip route del 10.10.2.0/24 via 10.10.1.2
sudo ip route del 10.0.0.0/24 via 10.100.100.2
sudo ip route del 10.202.129.0/24 via 10.100.100.2
sudo ip route del 20.0.0.0/8 via 10.100.100.2
sudo ip route del 30.0.0.0/8 via 10.100.100.2
sudo ip route del 40.0.0.0/8 via 10.100.100.2
  
