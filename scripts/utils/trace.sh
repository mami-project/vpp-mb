#!/bin/bash

sudo vppctl -s /run/vpp/cli-vpp1.sock trace add af-packet-input 20
sudo vppctl -s /run/vpp/cli-vpp1.sock clear trace

