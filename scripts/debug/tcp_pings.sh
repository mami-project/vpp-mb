#!/bin/bash

# print mmb trace blocks
function parse_mmb_trace {
   str=$1
   block_name="mmb"
   IFS=$'\n' # make newlines the only separator
   mmb_block=0
   while read -r line; do

      if [[ ${line:0:1} != " " ]] ; then 
         if [[ "$line" == *"${block_name}"* ]]; then
            echo "$line"
            mmb_block=1
         else
            mmb_block=0
         fi

      elif [[ ${mmb_block} == 1 ]]; then
        echo "$line"
      fi

   done <<< "$str"
}

# populate ARP table
ping 10.10.2.2 -c 5

# Init tracer on MB and Bob
sudo vppctl -s /run/vpp/cli-vpp1.sock trace add af-packet-input 10
sudo vppctl -s /run/vpp/cli-vpp2.sock trace add af-packet-input 10
sudo vppctl -s /run/vpp/cli-vpp2.sock clear trace
sudo vppctl -s /run/vpp/cli-vpp1.sock clear trace

# tcp pings
sudo ./tcp_pings.py
sleep 1

# get&clean trace
bob_trace="$(sudo vppctl -s /run/vpp/cli-vpp2.sock show trace)"
mb_trace="$(sudo vppctl -s /run/vpp/cli-vpp1.sock show trace)"
sudo vppctl -s /run/vpp/cli-vpp2.sock clear trace
sudo vppctl -s /run/vpp/cli-vpp1.sock clear trace

#print
echo "MB TCP trace"
echo
parse_mmb_trace "${mb_trace}"
echo "Bob TCP trace"
echo
parse_mmb_trace "${bob_trace}"


