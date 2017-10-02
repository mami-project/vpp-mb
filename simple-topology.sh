# Create 2-vpps line topology

## create vpp1 and connect it to host
sudo vpp api-segment { prefix vpp1 }

# veth interface between host and vpp1
sudo ip link add name vpp1out type veth peer name vpp1host
sudo ip link set dev vpp1out up
sudo ip link set dev vpp1host up
sudo ip addr add 10.10.1.1/24 dev vpp1host

# host interface between host and vpp1
sudo vppctl -p vpp1 create host-interface name vpp1out
sudo vppctl -p vpp1 set int state host-vpp1out up
sudo vppctl -p vpp1 set int ip address host-vpp1out 10.10.1.2/24


## create vpp2 and connect it to vpp1
sudo vpp api-segment { prefix vpp2 }
sudo ip link add name vpp1vpp2 type veth peer name vpp2vpp1
sudo ip link set dev vpp1vpp2 up
sudo ip link set dev vpp2vpp1 up

sudo vppctl -p vpp1 create host-interface name vpp1vpp2
sudo vppctl -p vpp1 set int state host-vpp1vpp2 up
sudo vppctl -p vpp1 set int ip address host-vpp1vpp2 10.10.2.1/24

sudo vppctl -p vpp2 create host-interface name vpp2vpp1
sudo vppctl -p vpp2 set int state host-vpp2vpp1 up
sudo vppctl -p vpp2 set int ip address host-vpp2vpp1 10.10.2.2/24

# route host to vpp2 via vpp1 and reciprocally
sudo ip route add 10.10.2.0/24 via 10.10.1.2
sudo vppctl -p vpp2 ip route add 10.10.1.0/24 via 10.10.2.1



