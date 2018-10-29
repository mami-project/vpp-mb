#!/bin/bash
#
#
# Topology 2
#
# server addr: 10.0.0.10

# enable kernel forwarding
#sudo sysctl -w net.ipv4.ip_forward=1

# VPP Nodes
sudo vpp unix { cli-listen /run/vpp/cli-vpp1.sock } api-segment { prefix vpp1 } plugins { plugin mmb_plugin.so { disable } }
sudo vpp unix { cli-listen /run/vpp/cli-vpp2.sock } api-segment { prefix vpp2 } 
sudo vpp unix { cli-listen /run/vpp/cli-vpp3.sock } api-segment { prefix vpp3 } 
#sudo vpp unix { cli-listen /run/vpp/cli-vpp4.sock } api-segment { prefix vpp4 } plugins { plugin mmb_plugin.so { disable } }
sudo vpp unix { cli-listen /run/vpp/cli-vpp5.sock } api-segment { prefix vpp5 }
sudo vpp unix { cli-listen /run/vpp/cli-vpp6.sock } api-segment { prefix vpp6 } 
sudo vpp unix { cli-listen /run/vpp/cli-vpp7.sock } api-segment { prefix vpp7 } 
sudo vpp unix { cli-listen /run/vpp/cli-vpp8.sock } api-segment { prefix vpp8 } 
sleep 1

# veth interface between host and vpp1
sudo ip link add name vpp1out type veth peer name vpp1host
sudo ip link set dev vpp1out up
sudo ip link set dev vpp1host up
sudo ethtool -K vpp1host rx off tx off
sudo ip addr add 10.100.100.1/24 dev vpp1host
sudo ip route add 10.0.0.0/24 via 10.100.100.2
sudo ip route add 10.202.129.0/24 via 10.100.100.2
sudo ip route add 20.0.0.0/8 via 10.100.100.2
sudo ip route add 30.0.0.0/8 via 10.100.100.2

# host interface between host and vpp1
sudo vppctl -s /run/vpp/cli-vpp1.sock create host-interface name vpp1out
sudo vppctl -s /run/vpp/cli-vpp1.sock set int state host-vpp1out up
sudo vppctl -s /run/vpp/cli-vpp1.sock set int ip address host-vpp1out 10.100.100.2/24

# connect vpp instances
sudo vppctl -s /run/vpp/cli-vpp1.sock create memif socket id 1 filename /run/vpp/memif1.sock
sudo vppctl -s /run/vpp/cli-vpp1.sock create interface memif id 0 socket-id 1 master 
sudo vppctl -s /run/vpp/cli-vpp1.sock set int state memif1/0 up
sudo vppctl -s /run/vpp/cli-vpp1.sock set int ip address memif1/0 10.202.129.13/24

sudo vppctl -s /run/vpp/cli-vpp1.sock ip route add 10.0.0.0/24 via 10.202.129.2 memif1/0
sudo vppctl -s /run/vpp/cli-vpp1.sock ip route add 10.202.129.0/24 via 10.202.129.2 memif1/0
sudo vppctl -s /run/vpp/cli-vpp1.sock ip route add 20.55.55.0/24 via 10.202.129.2 memif1/0
sudo vppctl -s /run/vpp/cli-vpp1.sock ip route add 30.0.0.0/8 via 10.202.129.2 memif1/0

sudo vppctl -s /run/vpp/cli-vpp2.sock create memif socket id 1 filename /run/vpp/memif1.sock
sudo vppctl -s /run/vpp/cli-vpp2.sock create memif socket id 2 filename /run/vpp/memif2.sock
sudo vppctl -s /run/vpp/cli-vpp2.sock create interface memif id 0 socket-id 1 slave
sudo vppctl -s /run/vpp/cli-vpp2.sock set int state memif1/0 up
sudo vppctl -s /run/vpp/cli-vpp2.sock set int ip address memif1/0 10.202.129.2/24
sudo vppctl -s /run/vpp/cli-vpp2.sock create interface memif id 0 socket-id 2 master
sudo vppctl -s /run/vpp/cli-vpp2.sock set int state memif2/0 up
sudo vppctl -s /run/vpp/cli-vpp2.sock set int ip address memif2/0 30.0.3.1/24
#sudo vppctl -s /run/vpp/cli-vpp2.sock create memif socket /run/vpp/memif-vpp2vpp4 master
#sudo vppctl -s /run/vpp/cli-vpp2.sock set int state memif2/0 up
#sudo vppctl -s /run/vpp/cli-vpp2.sock set int ip address memif2/0 30.1.3.2/24

sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 10.100.100.0/24 via 10.202.129.13 memif1/0
sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 10.202.129.0/24 via 10.202.129.13 memif1/0
sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 10.0.0.0/24 via 30.0.3.3 memif2/0
sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 20.55.55.0/24 via 30.0.3.3 memif2/0
sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 30.101.0.0/16 via 30.0.3.3 memif2/0
sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 30.111.2.0/24 via 30.0.3.3 memif2/0
sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 30.0.0.0/16 via 30.0.3.3 memif2/0
#sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 30.1.0.0/16 via 30.1.3.3 memif2/0

#sudo vppctl -s /run/vpp/cli-vpp2.sock ip table 1
#sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 30.0.0.0/16 via 30.0.3.3 memif1/0 table 1
#sudo vppctl -s /run/vpp/cli-vpp2.sock ip route add 0.0.0.0/0 via 30.1.3.3 memif2/0 table 1
#sudo vppctl -s /run/vpp/cli-vpp2.sock mmb add all lb 0 1

sudo vppctl -s /run/vpp/cli-vpp3.sock create memif socket id 2 filename /run/vpp/memif2.sock
sudo vppctl -s /run/vpp/cli-vpp3.sock create memif socket id 3 filename /run/vpp/memif3.sock
sudo vppctl -s /run/vpp/cli-vpp3.sock create interface memif id 0 socket-id 2 slave
sudo vppctl -s /run/vpp/cli-vpp3.sock set int state memif2/0 up
sudo vppctl -s /run/vpp/cli-vpp3.sock set int ip address memif2/0 30.0.3.3/24
sudo vppctl -s /run/vpp/cli-vpp3.sock create interface memif id 0 socket-id 3 master
sudo vppctl -s /run/vpp/cli-vpp3.sock set int state memif3/0 up
sudo vppctl -s /run/vpp/cli-vpp3.sock set int ip address memif3/0 30.0.5.1/24

sudo vppctl -s /run/vpp/cli-vpp3.sock ip route add 10.100.100.0/24 via 30.0.3.1 memif2/0
sudo vppctl -s /run/vpp/cli-vpp3.sock ip route add 10.202.129.0/24 via 30.0.3.1 memif2/0
#sudo vppctl -s /run/vpp/cli-vpp3.sock ip route add 30.1.0.0/16 via 30.0.3.1 memif2/0
sudo vppctl -s /run/vpp/cli-vpp3.sock ip route add 10.0.0.0/24 via 30.0.5.7 memif3/0
sudo vppctl -s /run/vpp/cli-vpp3.sock ip route add 20.55.55.0/24 via 30.0.5.7 memif3/0
sudo vppctl -s /run/vpp/cli-vpp3.sock ip route add 30.101.0.0/16 via 30.0.5.7 memif3/0
sudo vppctl -s /run/vpp/cli-vpp3.sock ip route add 30.111.2.0/24 via 30.0.5.7 memif3/0
sudo vppctl -s /run/vpp/cli-vpp3.sock mmb enable memif2/0
sudo vppctl -s /run/vpp/cli-vpp3.sock mmb enable memif3/0
sudo vppctl -s /run/vpp/cli-vpp3.sock mmb add tcp-cwr tcp-syn tcp-ece drop
sudo vppctl -s /run/vpp/cli-vpp3.sock mmb add all drop 0.1

#sudo vppctl -s /run/vpp/cli-vpp4.sock create memif socket /run/vpp/memif-vpp2vpp4 slave
#sudo vppctl -s /run/vpp/cli-vpp4.sock set int state memif0/0 up
#sudo vppctl -s /run/vpp/cli-vpp4.sock set int ip address memif0/0 30.1.3.3/24
#sudo vppctl -s /run/vpp/cli-vpp4.sock create memif socket /run/vpp/memif-vpp4vpp5 master
#sudo vppctl -s /run/vpp/cli-vpp4.sock set int state memif1/0 up
#sudo vppctl -s /run/vpp/cli-vpp4.sock set int ip address memif1/0 30.1.2.5/24

#sudo vppctl -s /run/vpp/cli-vpp4.sock ip route add 10.100.100.0/24 via 30.1.3.2 memif0/0
#sudo vppctl -s /run/vpp/cli-vpp4.sock ip route add 10.202.129.0/24 via 30.1.3.2 memif0/0
#sudo vppctl -s /run/vpp/cli-vpp4.sock ip route add 30.0.0.0/16 via 30.1.3.2 memif0/0
#sudo vppctl -s /run/vpp/cli-vpp4.sock ip route add 20.55.55.0/24 via 30.1.2.13 memif1/0
#sudo vppctl -s /run/vpp/cli-vpp4.sock ip route add 10.0.0.0/24 via 30.1.2.13 memif1/0
#sudo vppctl -s /run/vpp/cli-vpp4.sock ip route add 30.101.0.0/16 via 30.1.2.13 memif1/0
#sudo vppctl -s /run/vpp/cli-vpp4.sock ip route add 30.111.2.0/24 via 30.1.2.13 memif1/0

#sudo vppctl -s /run/vpp/cli-vpp5.sock create memif socket /run/vpp/memif-vpp4vpp5 slave
#sudo vppctl -s /run/vpp/cli-vpp5.sock set int state memif0/0 up
#sudo vppctl -s /run/vpp/cli-vpp5.sock set int ip address memif0/0 30.1.2.13/24
sudo vppctl -s /run/vpp/cli-vpp5.sock create memif socket id 3 filename /run/vpp/memif3.sock
sudo vppctl -s /run/vpp/cli-vpp5.sock create memif socket id 4 filename /run/vpp/memif4.sock
sudo vppctl -s /run/vpp/cli-vpp5.sock create interface memif id 0 socket-id 3 slave
sudo vppctl -s /run/vpp/cli-vpp5.sock set int state memif3/0 up
sudo vppctl -s /run/vpp/cli-vpp5.sock set int ip address memif3/0 30.0.5.7/24
sudo vppctl -s /run/vpp/cli-vpp5.sock create interface memif id 0 socket-id 4 master
sudo vppctl -s /run/vpp/cli-vpp5.sock set int state memif4/0 up
sudo vppctl -s /run/vpp/cli-vpp5.sock set int ip address memif4/0 20.55.55.1/24

#sudo vppctl -s /run/vpp/cli-vpp5.sock ip route add 30.1.0.0/16 via 30.1.2.5 memif3/0
sudo vppctl -s /run/vpp/cli-vpp5.sock ip route add 10.100.100.0/24 via 30.0.5.1 memif3/0
sudo vppctl -s /run/vpp/cli-vpp5.sock ip route add 10.202.129.0/24 via 30.0.5.1 memif3/0
sudo vppctl -s /run/vpp/cli-vpp5.sock ip route add 30.0.0.0/16 via 30.0.5.1 memif3/0
sudo vppctl -s /run/vpp/cli-vpp5.sock ip route add 10.0.0.0/24 via 20.55.55.6 memif4/0
sudo vppctl -s /run/vpp/cli-vpp5.sock ip route add 20.55.55.0/24 via 20.55.55.6 memif4/0
sudo vppctl -s /run/vpp/cli-vpp5.sock ip route add 30.101.0.0/16 via 20.55.55.6 memif4/0
sudo vppctl -s /run/vpp/cli-vpp5.sock ip route add 30.111.2.0/24 via 20.55.55.6 memif4/0
sudo vppctl -s /run/vpp/cli-vpp5.sock mmb enable memif3/0
sudo vppctl -s /run/vpp/cli-vpp5.sock mmb enable memif4/0
sudo vppctl -s /run/vpp/cli-vpp5.sock mmb add-stateful tcp-syn shuffle tcp-seq-num shuffle tcp-ack-num

#sudo vppctl -s /run/vpp/cli-vpp5.sock ip table 1
#sudo vppctl -s /run/vpp/cli-vpp5.sock ip route add 30.0.0.0/16 via 30.0.5.1 memif1/0 table 1
#sudo vppctl -s /run/vpp/cli-vpp5.sock ip route add 0.0.0.0/0 via 30.1.2.5 memif0/0 table 1
#sudo vppctl -s /run/vpp/cli-vpp5.sock mmb add all lb 0 1

sudo vppctl -s /run/vpp/cli-vpp6.sock create memif socket id 4 filename /run/vpp/memif4.sock
sudo vppctl -s /run/vpp/cli-vpp6.sock create memif socket id 5 filename /run/vpp/memif5.sock
sudo vppctl -s /run/vpp/cli-vpp6.sock create interface memif id 0 socket-id 4 slave
sudo vppctl -s /run/vpp/cli-vpp6.sock set int state memif4/0 up
sudo vppctl -s /run/vpp/cli-vpp6.sock set int ip address memif4/0 20.55.55.6/24
sudo vppctl -s /run/vpp/cli-vpp6.sock create interface memif id 0 socket-id 5 master
sudo vppctl -s /run/vpp/cli-vpp6.sock set int state memif5/0 up
sudo vppctl -s /run/vpp/cli-vpp6.sock set int ip address memif5/0 30.101.2.3/16
sudo vppctl -s /run/vpp/cli-vpp6.sock mmb enable memif4/0
sudo vppctl -s /run/vpp/cli-vpp6.sock mmb enable memif5/0

sudo vppctl -s /run/vpp/cli-vpp6.sock ip route add 10.100.100.0/24 via 20.55.55.1 memif4/0
sudo vppctl -s /run/vpp/cli-vpp6.sock ip route add 10.202.129.0/24 via 20.55.55.1 memif4/0
sudo vppctl -s /run/vpp/cli-vpp6.sock ip route add 30.0.0.0/16 via 20.55.55.1 memif4/0
#sudo vppctl -s /run/vpp/cli-vpp6.sock ip route add 30.1.0.0/16 via 20.55.55.1 memif4/0
sudo vppctl -s /run/vpp/cli-vpp6.sock ip route add 10.0.0.0/24 via 30.101.0.6 memif5/0
sudo vppctl -s /run/vpp/cli-vpp6.sock ip route add 30.111.2.0/24 via 30.101.0.6 memif5/0
sudo vppctl -s /run/vpp/cli-vpp6.sock mmb add ip-proto udp mod ip-dscp 14
sudo vppctl -s /run/vpp/cli-vpp6.sock mmb add ip-proto icmp mod ip-dscp 0
sudo vppctl -s /run/vpp/cli-vpp6.sock mmb add ip-proto tcp mod ip-dscp 14 

sudo vppctl -s /run/vpp/cli-vpp7.sock create memif socket id 5 filename /run/vpp/memif5.sock
sudo vppctl -s /run/vpp/cli-vpp7.sock create memif socket id 6 filename /run/vpp/memif6.sock
sudo vppctl -s /run/vpp/cli-vpp7.sock create interface memif id 0 socket-id 5 slave
sudo vppctl -s /run/vpp/cli-vpp7.sock set int state memif5/0 up
sudo vppctl -s /run/vpp/cli-vpp7.sock set int ip address memif5/0 30.101.0.6/16
sudo vppctl -s /run/vpp/cli-vpp7.sock create interface memif id 0 socket-id 6 master
sudo vppctl -s /run/vpp/cli-vpp7.sock set int state memif6/0 up
sudo vppctl -s /run/vpp/cli-vpp7.sock set int ip address memif6/0 30.111.2.3/24
sudo vppctl -s /run/vpp/cli-vpp7.sock mmb enable memif5/0
sudo vppctl -s /run/vpp/cli-vpp7.sock mmb enable memif6/0

sudo vppctl -s /run/vpp/cli-vpp7.sock ip route add 10.100.100.0/24 via 30.101.2.3 memif5/0
sudo vppctl -s /run/vpp/cli-vpp7.sock ip route add 10.202.129.0/24 via 30.101.2.3 memif5/0
sudo vppctl -s /run/vpp/cli-vpp7.sock ip route add 30.0.0.0/16 via 30.101.2.3 memif5/0
#sudo vppctl -s /run/vpp/cli-vpp7.sock ip route add 30.1.0.0/16 via 30.101.2.3 memif5/0
sudo vppctl -s /run/vpp/cli-vpp7.sock ip route add 20.55.55.0/24 via 30.101.2.3 memif5/0
sudo vppctl -s /run/vpp/cli-vpp7.sock ip route add 30.101.2.0/24 via 30.101.2.3 memif5/0
sudo vppctl -s /run/vpp/cli-vpp7.sock ip route add 10.0.0.0/24 via 30.111.2.2 memif6/0
sudo vppctl -s /run/vpp/cli-vpp7.sock mmb add tcp-syn tcp-opt-mss != 1460 mod tcp-opt-mss 1460
sudo vppctl -s /run/vpp/cli-vpp7.sock mmb add tcp-syn ! tcp-opt-mss add tcp-opt-mss 1460

sudo vppctl -s /run/vpp/cli-vpp7.sock mmb add tcp-syn tcp-opt-wscale != 8 mod tcp-opt-wscale 8
sudo vppctl -s /run/vpp/cli-vpp7.sock mmb add tcp-syn ! tcp-opt-wscale add tcp-opt-wscale 8

sudo vppctl -s /run/vpp/cli-vpp8.sock create memif socket id 6 filename /run/vpp/memif6.sock
sudo vppctl -s /run/vpp/cli-vpp8.sock create interface memif id 0 socket-id 6 slave
sudo vppctl -s /run/vpp/cli-vpp8.sock set int state memif6/0 up
sudo vppctl -s /run/vpp/cli-vpp8.sock set int ip address memif6/0 30.111.2.2/24

sudo vppctl -s /run/vpp/cli-vpp8.sock ip route add 10.100.100.0/24 via 30.111.2.3 memif6/0
sudo vppctl -s /run/vpp/cli-vpp8.sock ip route add 10.202.129.0/24 via 30.111.2.3 memif6/0
sudo vppctl -s /run/vpp/cli-vpp8.sock ip route add 30.0.0.0/16 via 30.111.2.3 memif6/0
#sudo vppctl -s /run/vpp/cli-vpp8.sock ip route add 30.1.0.0/16 via 30.111.2.3 memif6/0
sudo vppctl -s /run/vpp/cli-vpp8.sock ip route add 20.55.55.0/24 via 30.111.2.3 memif6/0
sudo vppctl -s /run/vpp/cli-vpp8.sock ip route add 30.101.2.0/24 via 30.111.2.3 memif6/0
sudo vppctl -s /run/vpp/cli-vpp8.sock ip route add 30.111.2.0/24 via 30.111.2.3 memif6/0

#create namespace for endpoint 
sudo ip netns add ns0
# connect to VPP6
sudo ip link add name vpp8host type veth peer name vpp8
sudo ip link set dev vpp8 up 
sudo ip link set dev vpp8host up netns ns0

sudo ip netns exec ns0 \
  bash -c "
    ip link set dev lo up
    ip addr add 10.0.0.10/24 dev vpp8host
    ip route add default via 10.0.0.11
    ethtool -K vpp8host rx off tx off
"
# veth interface between s and vpp6
sudo vppctl -s /run/vpp/cli-vpp8.sock create host-interface name vpp8
sudo vppctl -s /run/vpp/cli-vpp8.sock set interface state host-vpp8 up
sudo vppctl -s /run/vpp/cli-vpp8.sock set interface ip address host-vpp8 10.0.0.11/24

sudo vppctl -s /run/vpp/cli-vpp8.sock mmb enable host-vpp8
sudo vppctl -s /run/vpp/cli-vpp8.sock mmb enable memif6/0

sudo vppctl -s /run/vpp/cli-vpp8.sock mmb add udp-dport 80 drop
sudo vppctl -s /run/vpp/cli-vpp8.sock mmb add udp-dport 8000 drop
sudo vppctl -s /run/vpp/cli-vpp8.sock mmb add udp-dport 8080 drop
sudo vppctl -s /run/vpp/cli-vpp8.sock mmb add udp-dport 443 drop
sudo vppctl -s /run/vpp/cli-vpp8.sock mmb add udp-dport 135 drop
sudo vppctl -s /run/vpp/cli-vpp8.sock mmb add udp-dport 139 drop
sudo vppctl -s /run/vpp/cli-vpp8.sock mmb add udp-dport 161 drop
sudo vppctl -s /run/vpp/cli-vpp8.sock mmb add udp-dport 162 drop

sudo vppctl -s /run/vpp/cli-vpp8.sock mmb add tcp-dport 53 drop
sudo vppctl -s /run/vpp/cli-vpp8.sock mmb add tcp-dport 25 drop
sudo vppctl -s /run/vpp/cli-vpp8.sock mmb add tcp-dport 135 drop
sudo vppctl -s /run/vpp/cli-vpp8.sock mmb add tcp-dport 139 drop
sudo vppctl -s /run/vpp/cli-vpp8.sock mmb add tcp-dport 445 drop
sudo vppctl -s /run/vpp/cli-vpp8.sock mmb add tcp-dport 161 drop
sudo vppctl -s /run/vpp/cli-vpp8.sock mmb add tcp-dport 162 drop

sudo server/run.sh &


