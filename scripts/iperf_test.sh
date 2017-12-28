#!/bin/bash

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "Syntax: $0 <rules number> [--with-tcp-options]"
  exit 1
fi

if [ "$1" != 10 ] && [ "$1" != 100 ] && [ "$1" != 1000 ] && [ "$1" != 10000 ]; then
  echo "Rules number must be either 10, 100, 1000 or 10000"
  exit 1
fi

if [ "$2" != "" ] && [ "$2" != "--with-tcp-options" ]; then
  echo "Syntax: $0 <rules number> [--with-tcp-options]"
  exit 1
fi

function get_random_match
{
  if $2; then

    case $(( $1 % 3 )) in
      0)
        echo "tcp-opt-mss $(( RANDOM % 65536 ))";;
      1)
        echo "tcp-opt-wscale $(( RANDOM % 256 ))";;
      2)
        echo "tcp-opt-timestamp $(( RANDOM % 9223372036854775808 ))";;

      #TODO construct "real" sack, fast-open, mptcp ???
    esac

  else

    case $(( $1 % 22 )) in
      0)
        echo "ip-ver $(( RANDOM % 16 ))";;
      1)
        echo "ip-ihl $(( RANDOM % 16 ))";;
      2)
        echo "ip-dscp $(( RANDOM % 64 ))";;
      3)
        echo "ip-ecn $(( RANDOM % 4 ))";;
      4)
        echo "ip-len $(( RANDOM % 65536 ))";;
      5)
        echo "ip-id $(( RANDOM % 65536 ))";;
      6)
        echo "ip-flags $(( RANDOM % 8 ))";;
      7)
        echo "ip-frag-offset $(( RANDOM % 8192 ))";;
      8)
        echo "ip-ttl $(( RANDOM % 256 ))";;
      9)
        echo "ip-checksum $(( RANDOM % 65536 ))";;
      10)
        a=$(( RANDOM % 256 ))
        b=$(( RANDOM % 256 ))
        c=$(( RANDOM % 256 ))
        d=$(( RANDOM % 256 ))
        echo "ip-saddr $a.$b.$c.$d";;
      11)
        a=$(( RANDOM % 256 ))
        b=$(( RANDOM % 256 ))
        c=$(( RANDOM % 256 ))
        d=$(( RANDOM % 256 ))
        echo "ip-daddr $a.$b.$c.$d";;
      12)
        echo "tcp-sport $(( RANDOM % 65536 ))";;
      13)
        echo "tcp-dport $(( RANDOM % 65536 ))";;
      14)
        echo "tcp-seq-num $(( RANDOM % 4294967296 ))";;
      15)
        echo "tcp-ack-num $(( RANDOM % 4294967296 ))";;
      16)
        echo "tcp-offset $(( RANDOM % 16 ))";;
      17)
        echo "tcp-reserved $(( RANDOM % 16 ))";;
      18)
        echo "tcp-flags $(( RANDOM % 256 ))";;
      19)
        echo "tcp-win $(( RANDOM % 65536 ))";;
      20)
        echo "tcp-checksum $(( RANDOM % 65536 ))";;
      21)
        echo "tcp-urg-ptr $(( RANDOM % 65536 ))";;
    esac

  fi
}

function get_random_target
{
  if $2; then

    case $(( $1 % 3 )) in
      0)
        echo "mod tcp-opt-mss $(( RANDOM % 65536 ))";;
      1)
        echo "mod tcp-opt-wscale $(( RANDOM % 256 ))";;
      2)
        echo "mod tcp-opt-timestamp $(( RANDOM % 9223372036854775808 ))";;

      #TODO "add" options ?
    esac

  else

    echo "mod ip-ttl $(( RANDOM % 256 ))"

  fi
}

function rule_gen
{
  RULES=$1
  OPTIONS=$2

  touch random_rules

  i=0
  until [ $i -eq $RULES ]; do
    match=$(get_random_match $i $OPTIONS)
    target=$(get_random_target $i $OPTIONS)

    echo "mmb add ip-proto tcp $match $target" >> random_rules
    let i+=1
  done

  sudo vppctl -s /run/vpp/cli-vpp.sock exec /home/vagrant/vpp-mb/scripts/random_rules
  rm random_rules

  #TODO how many matches in matching part ? how many targets in target part ?
}

echo
echo "Topology initialization & configuration..."

{
  # enable kernel forwarding
  sudo sysctl -w net.ipv4.ip_forward=1
  sysctl -p

  # create vpp instance
  sudo vpp unix { log /tmp/vpp.log cli-listen /run/vpp/cli-vpp.sock } api-segment { prefix vpp } plugins { plugin dpdk_plugin.so { disable } }
  sleep 1

  # ns0 namespace
  sudo ip netns add ns0
  sudo ip link add vpp0 type veth peer name vethns0
  sudo ip link set vethns0 netns ns0
  sudo ip netns exec ns0 ip link set lo up
  sudo ip netns exec ns0 ip link set vethns0 up
  sudo ip netns exec ns0 ip addr add 10.0.0.1/24 dev vethns0
  sudo ip netns exec ns0 ethtool -K vethns0 rx off tx off
  sudo ethtool --offload vpp0 rx off tx off
  sudo ip link set vpp0 up

  # switching
  sudo vppctl -s /run/vpp/cli-vpp.sock create host-interface name vpp0
  sudo vppctl -s /run/vpp/cli-vpp.sock set interface state host-vpp0 up
  sudo vppctl -s /run/vpp/cli-vpp.sock set interface l2 bridge host-vpp0 1
  sudo vppctl -s /run/vpp/cli-vpp.sock create loopback interface
  sudo vppctl -s /run/vpp/cli-vpp.sock set interface l2 bridge loop0 1 bvi
  sudo vppctl -s /run/vpp/cli-vpp.sock set interface state loop0 up
  sudo vppctl -s /run/vpp/cli-vpp.sock set interface ip address loop0 10.0.0.10/24

  # ns2 namespace
  sudo vppctl -s /run/vpp/cli-vpp.sock tap connect tap0
  sudo ip netns add ns2
  sudo ip link set tap0 netns ns2
  sudo ip netns exec ns2 ip link set lo up
  sudo ip netns exec ns2 ip link set tap0 up
  sudo ip netns exec ns2 ip addr add 10.0.1.1/24 dev tap0

  # routing
  sudo vppctl -s /run/vpp/cli-vpp.sock set interface state tap-0 up
  sudo vppctl -s /run/vpp/cli-vpp.sock set interface ip address tap-0 10.0.1.10/24
  sudo ip netns exec ns0 ip route add default via 10.0.0.10
  sudo ip netns exec ns2 ip route add default via 10.0.1.10

  # fill ARP cache
  sudo ip netns exec ns0 ping 10.0.1.1 -c 5
  sudo ip netns exec ns2 ping 10.0.0.1 -c 5

  # enable MMB
  sudo vppctl -s /run/vpp/cli-vpp.sock mmb enable host-vpp0
  sudo vppctl -s /run/vpp/cli-vpp.sock mmb enable tap-0

  # fill MMB rule table
  [[ $2 = "--with-tcp-options" ]] && tcpopts=true || tcpopts=false
  rule_gen $1 $tcpopts

  # iperf server
  sudo ip netns exec ns2 iperf3 -s -D -B 10.0.1.1
  sleep 1
} &> /dev/null

echo
[[ $2 = "--with-tcp-options" ]] && tcpopts="with" || tcpopts="without"
echo "Starting iperf test ($1 rules, $tcpopts tcp options)..."
echo
sleep 2

# iperf client (test & results)
#TODO speed gen ? pass it as an argument ?
sudo ip netns exec ns0 iperf3 -c 10.0.1.1 -4 -k 10000 -V
#TODO filter & display results in our own format ?
sleep 1

echo
echo "Cleaning everything up..."

{
  # cleanup
  sudo kill -9 $(ps -aef | grep -v grep | grep iperf3 | awk '{print $2}')
  sudo kill -9 $(ps -aef | grep -v grep | grep vpp | awk '{print $2}')
  sudo ip link del vpp0
  sudo ip netns del ns0
  sudo ip netns del ns2
} &> /dev/null

