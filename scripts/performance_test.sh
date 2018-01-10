#!/bin/bash
#
#

./topology/cleanup.sh
./topology/3line_veth.sh

datafile=performance_data_veth.txt
>$datafile

#cmd="./performance/run.sh --rules 0 --rules-proto all --rules-type all --matches 5 --targets 5 --iperf-proto tcp --background-udp 0 --background-tcp 0"
#echo $cmd >> $datafile
#eval $cmd >> $datafile

#cmd="./performance/run.sh --rules 10 --rules-proto all --rules-type all --matches 5 --targets 5 --iperf-proto tcp --background-udp 0 --background-tcp 0"
#echo $cmd >> $datafile
#eval $cmd >> $datafile

#cmd="./performance/run.sh --rules 20 --rules-proto all --rules-type all --matches 5 --targets 5 --iperf-proto tcp --background-udp 0 --background-tcp 0"
#echo $cmd >> $datafile
#eval $cmd >> $datafile

#cmd="./performance/run.sh --rules 50 --rules-proto all --rules-type all --matches 5 --targets 5 --iperf-proto tcp --background-udp 0 --background-tcp 0"
#echo $cmd >> $datafile
#eval $cmd >> $datafile

#cmd="./performance/run.sh --rules 100 --rules-proto all --rules-type all --matches 5 --targets 5 --iperf-proto tcp --background-udp 0 --background-tcp 0"
#echo $cmd >> $datafile
#eval $cmd >> $datafile

#cmd="./performance/run.sh --rules 150 --rules-proto all --rules-type all --matches 5 --targets 5 --iperf-proto tcp --background-udp 0 --background-tcp 0"
#echo $cmd >> $datafile
#eval $cmd >> $datafile

#cmd="./performance/run.sh --rules 200 --rules-proto all --rules-type all --matches 5 --targets 5 --iperf-proto tcp --background-udp 0 --background-tcp 0"
#echo $cmd >> $datafile
#eval $cmd >> $datafile

#cmd="./performance/run.sh --rules 300 --rules-proto all --rules-type all --matches 5 --targets 5 --iperf-proto tcp --background-udp 0 --background-tcp 0"
#echo $cmd >> $datafile
#eval $cmd >> $datafile

cmd="./performance/run.sh --rules 500 --rules-proto all --rules-type all --matches 5 --targets 5 --iperf-proto tcp --background-udp 0 --background-tcp 0"
echo $cmd >> $datafile
eval $cmd >> $datafile

cmd="./performance/run.sh --rules 1000 --rules-proto all --rules-type all --matches 5 --targets 5 --iperf-proto tcp --background-udp 0 --background-tcp 0"
echo $cmd >> $datafile
eval $cmd >> $datafile

./topology/cleanup.sh
./topology/3line_tap.sh

datafile=performance_data_tap.txt
>$datafile

cmd="./performance/run.sh --rules 0 --rules-proto all --rules-type all --matches 5 --targets 5 --iperf-proto tcp --background-udp 0 --background-tcp 0"
echo $cmd >> $datafile
eval $cmd >> $datafile

cmd="./performance/run.sh --rules 10 --rules-proto all --rules-type all --matches 5 --targets 5 --iperf-proto tcp --background-udp 0 --background-tcp 0"
echo $cmd >> $datafile
eval $cmd >> $datafile

cmd="./performance/run.sh --rules 20 --rules-proto all --rules-type all --matches 5 --targets 5 --iperf-proto tcp --background-udp 0 --background-tcp 0"
echo $cmd >> $datafile
eval $cmd >> $datafile

cmd="./performance/run.sh --rules 50 --rules-proto all --rules-type all --matches 5 --targets 5 --iperf-proto tcp --background-udp 0 --background-tcp 0"
echo $cmd >> $datafile
eval $cmd >> $datafile

cmd="./performance/run.sh --rules 100 --rules-proto all --rules-type all --matches 5 --targets 5 --iperf-proto tcp --background-udp 0 --background-tcp 0"
echo $cmd >> $datafile
eval $cmd >> $datafile

cmd="./performance/run.sh --rules 150 --rules-proto all --rules-type all --matches 5 --targets 5 --iperf-proto tcp --background-udp 0 --background-tcp 0"
echo $cmd >> $datafile
eval $cmd >> $datafile

cmd="./performance/run.sh --rules 200 --rules-proto all --rules-type all --matches 5 --targets 5 --iperf-proto tcp --background-udp 0 --background-tcp 0"
echo $cmd >> $datafile
eval $cmd >> $datafile

cmd="./performance/run.sh --rules 300 --rules-proto all --rules-type all --matches 5 --targets 5 --iperf-proto tcp --background-udp 0 --background-tcp 0"
echo $cmd >> $datafile
eval $cmd >> $datafile

cmd="./performance/run.sh --rules 500 --rules-proto all --rules-type all --matches 5 --targets 5 --iperf-proto tcp --background-udp 0 --background-tcp 0"
echo $cmd >> $datafile
eval $cmd >> $datafile

cmd="./performance/run.sh --rules 1000 --rules-proto all --rules-type all --matches 5 --targets 5 --iperf-proto tcp --background-udp 0 --background-tcp 0"
echo $cmd >> $datafile
eval $cmd >> $datafile


