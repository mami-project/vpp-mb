#!/bin/bash

sudo vppctl -s /run/vpp/cli-vpp1.sock mmb enable host-vpp1out

sudo vppctl -s /run/vpp/cli-vpp1.sock mmb add ip-proto tcp mod ip-dscp 1234
#sudo vppctl -s /run/vpp/cli-vpp1.sock mmb add ip-proto tcp mod ip-dscp 1234
#sudo vppctl -s /run/vpp/cli-vpp1.sock mmb add ip-proto tcp mod ip-dscp 1234


