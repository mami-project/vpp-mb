#!/bin/bash

# start csit VMs (if needed)
vagrant up

# enter virtual environment
cd csit
source ./env/bin/activate

# gather MAC addresses from topology nodes
export PYTHONPATH=$(pwd)
./resources/tools/topology/update_topology.py -f -v -o topologies/available/vagrant_pci.yaml topologies/available/vagrant.yaml

# start ipv4 tests
pybot -L TRACE -v TOPOLOGY_PATH:topologies/available/vagrant_pci.yaml -s ipv4 tests/

# leave virtual environment
deactivate

