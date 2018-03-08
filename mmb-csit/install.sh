#!/bin/bash

# install dependencies
sudo apt-get install -y virtualenv python-dev python-crypto libpcap-dev
sudo vagrant plugin install vagrant-cachier

# clone csit repo
(rm -rf csit; git clone https://gerrit.fd.io/r/csit; cp 2_node_topology.sch.yaml csit/resources/topology_schemas/2_node_topology.sch.yaml; mv csit/topologies/available/vagrant.yaml csit/topologies/available/vagrant.back.yaml; cp vagrant.yaml csit/topologies/available/vagrant.yaml; sed -i '/ARCH=${1:-"x86_64"}/c\ARCH="x86_64"' csit/tests/tldk/tldk_scripts/run_tldk.sh)

# start csit VMs
(vagrant destroy -f; vagrant up --parallel --provision)
#TODO: try using -f (to avoid typing "yes") and try providing password "csit" automatically instead of typing it too
echo csit@192.168.255.10{0,1} | xargs -n 1 ssh-copy-id #echo csit@192.168.255.10{0,1,2} | xargs -n 1 ssh-copy-id

# create virtual environment and install dependencies
(cd csit; rm -rf env; virtualenv env; source ./env/bin/activate; pip install -r requirements.txt; deactivate)

