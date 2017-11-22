#!/bin/bash

sudo vppctl -s /run/vpp/cli-vpp1.sock mmb enable host-vpp1out 
sudo vppctl -s /run/vpp/cli-vpp1.sock mmb enable host-vpp1vpp2

sudo vppctl -s /run/vpp/cli-vpp1.sock mmb add ip-proto tcp mod ip-dscp 1234
sudo vppctl -s /run/vpp/cli-vpp1.sock mmb add ip-ecn mod ip-ecn 0
sudo vppctl -s /run/vpp/cli-vpp1.sock mmb add ip-proto 17 drop
sudo vppctl -s /run/vpp/cli-vpp1.sock mmb add tcp-opt-mss \> 1500 mod tcp-opt-mss 1460
sudo vppctl -s /run/vpp/cli-vpp1.sock mmb add tcp-opt strip ! tcp-opt-mss strip ! tcp-opt-wscale
sudo vppctl -s /run/vpp/cli-vpp1.sock mmb add tcp-opt 22 drop
sudo vppctl -s /run/vpp/cli-vpp1.sock mmb add udp-sport 55 udp-dport 56 mod udp-checksum x1234
sudo vppctl -s /run/vpp/cli-vpp1.sock mmb add tcp-syn 1 tcp-dport 80 tcp-opt-mss <= 1480 ip-ect0 tcp-seq-num == x89abcdef mod tcp-ack 1 mod tcp-dport 321 strip tcp-opt-mss
