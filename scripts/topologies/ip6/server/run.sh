#!/bin/bash
cd ../data
ip netns exec ns0 python3 ../ip6/server/server.py 2>&1 >../ip6/server/server.log 
