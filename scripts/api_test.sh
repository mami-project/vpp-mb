#!/bin/bash

sudo vpp unix { cli-listen /run/vpp/cli-vpp1.sock } api-segment { prefix vpp1 }
sleep 1

sudo vppctl -s /run/vpp/cli-vpp1.sock mmb add ip-dscp 1 mod ip-dscp 1234
sudo vppctl -s /run/vpp/cli-vpp1.sock mmb add tcp-dport 80 mod tcp-dport 8000
sudo vppctl -s /run/vpp/cli-vpp1.sock mmb add udp-dport 80 mod udp-dport 8000

