#!/bin/bash

# install dependencies
sudo apt-get install -y virtualenv python-dev python-crypto libpcap-dev
sudo vagrant plugin install vagrant-cachier

# clone csit repo (same version as VPP: 17.10)
(rm -rf csit; git clone https://gerrit.fd.io/r/csit; cd csit; git checkout rls1710)

# start csit VMs
(vagrant destroy -f; vagrant up --parallel --provision)
#TODO: try using -f (to avoid typing "yes") and try providing password "csit" automatically instead of typing it too
echo csit@192.168.255.10{0,1,2} | xargs -n 1 ssh-copy-id

# create virtual environment and install dependencies
(cd csit; rm -rf env; virtualenv env; source ./env/bin/activate; pip install -r requirements.txt; deactivate)

