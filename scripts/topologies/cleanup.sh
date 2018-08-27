#!/bin/bash

# generic cleanup script that covers the 3 available topologies

sudo service vpp stop
for i in {1..19};
do
    sudo kill -9 $(ps -aef | grep -v grep | grep vpp$i | awk '{print $2}')
done

sudo ip4/server/kill.sh

sudo ip link del dev vpp1out
sudo ip link del dev vpp6
sudo ip link del dev vpp8
sudo ip link del dev vpp19
sudo ip link del dev vpp1
sudo ip link del dev outvpp1
sudo ip link del dev hostvpp1
sudo ip link del dev vpp1host

sudo ip netns del ns0

sudo ip route del 10.0.0.0/24 via 10.100.100.2
sudo ip route del 10.202.129.0/24 via 10.100.100.2
sudo ip route del 20.0.0.0/8 via 10.100.100.2
sudo ip route del 30.0.0.0/8 via 10.100.100.2
sudo ip route del 40.0.0.0/8 via 10.100.100.2

