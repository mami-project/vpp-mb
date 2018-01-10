#!/bin/bash

# latencies, interpackets delay because there is some rate limiting

echo "udp delays"
sudo ip netns exec ns0 traceroute -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1

echo "icmp delays"
sudo ip netns exec ns0 traceroute -I -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -I -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -I -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -I -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -I -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -I -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -I -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -I -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -I -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -I -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1

echo "tcp delays"
sudo ip netns exec ns0 traceroute -T -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -T -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -T -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -T -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -T -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -T -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -T -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -T -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -T -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
sudo ip netns exec ns0 traceroute -T -4 10.0.1.1 -f 30 -m 30 -q 10 -p 80 -z 1
