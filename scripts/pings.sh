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
            #echo "$line"
            mmb_block=1
         else
            mmb_block=0
         fi

      elif [[ ${mmb_block} == 1 ]]; then
        echo "$line"
        mmb_block=0
      fi

   done <<< "$str"
}

echo
echo "Processing... Please wait..."

{
  # populate ARP table
  ping 10.10.2.2 -c 5

  # Init tracer on MB and Bob
  sudo vppctl -s /run/vpp/cli-vpp1.sock trace add af-packet-input 10
  #sudo vppctl -s /run/vpp/cli-vpp2.sock trace add af-packet-input 10
  #sudo vppctl -s /run/vpp/cli-vpp2.sock clear trace
  sudo vppctl -s /run/vpp/cli-vpp1.sock clear trace
} &> /dev/null

# udp pings
{
  sudo traceroute -4 10.10.2.2 -f 30 -m 30 -q 2 -p 80
} &> /dev/null

# get&clean trace
#bob_trace="$(sudo vppctl -s /run/vpp/cli-vpp2.sock show trace)"
mb_trace="$(sudo vppctl -s /run/vpp/cli-vpp1.sock show trace)"
#sudo vppctl -s /run/vpp/cli-vpp2.sock clear trace
sudo vppctl -s /run/vpp/cli-vpp1.sock clear trace

# print
#echo "Bob UDP trace"
#echo
#echo
#echo
echo
echo
echo "MB UDP trace"
echo
echo
parse_mmb_trace "${mb_trace}"

# icmp pings
{
  sudo traceroute -I -4 10.10.2.2 -f 30 -m 30 -q 2 -p 80
} &> /dev/null

# get&clean trace
#bob_trace="$(sudo vppctl -s /run/vpp/cli-vpp2.sock show trace)"
mb_trace="$(sudo vppctl -s /run/vpp/cli-vpp1.sock show trace)"
#sudo vppctl -s /run/vpp/cli-vpp2.sock clear trace
sudo vppctl -s /run/vpp/cli-vpp1.sock clear trace

# print
#echo "Bob ICMP trace"
#echo
#echo
#echo
echo
echo
echo "MB ICMP trace"
echo
echo
parse_mmb_trace "${mb_trace}"

# tcp pings
{
  sudo traceroute -T -4 10.10.2.2 -f 30 -m 30 -q 2 -p 80
} &> /dev/null

# get&clean trace
#bob_trace="$(sudo vppctl -s /run/vpp/cli-vpp2.sock show trace)"
mb_trace="$(sudo vppctl -s /run/vpp/cli-vpp1.sock show trace)"
#sudo vppctl -s /run/vpp/cli-vpp2.sock clear trace
sudo vppctl -s /run/vpp/cli-vpp1.sock clear trace

#print
#echo "Bob TCP trace"
#echo
#echo
#echo
echo
echo
echo "MB TCP trace"
echo
echo
parse_mmb_trace "${mb_trace}"
echo
echo

