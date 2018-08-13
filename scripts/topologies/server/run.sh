#!/bin/bash
cd server/data
ip netns exec ns0 python3 -m http.server 80 2>&1 >server.log 

