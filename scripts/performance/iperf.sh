#!/bin/bash
#

sudo ip netns exec ns0 pkill iperf3
sudo ip netns exec ns1 pkill iperf3

# iperf server
sudo ip netns exec ns1 iperf3 -s -D
sleep 1

# iperf client
sudo ip netns exec ns0 iperf3 -c 10.0.1.1 -4 $1
