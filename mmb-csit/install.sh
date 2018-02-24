#!/bin/bash

# install dependencies
sudo apt-get install -y virtualenv python-dev python-crypto libpcap-dev
sudo vagrant plugin install vagrant-cachier

# clone csit repo
(rm -rf csit; git clone https://gerrit.fd.io/r/csit)

# start csit VMs
(vagrant destroy -f; vagrant up --parallel --provision)
#TODO: check if mandatory; if so, try using -f (to avoid typing "yes") and try providing password "csit" automatically instead of typing it too
echo csit@192.168.255.10{0,1,2} | xargs -n 1 ssh-copy-id

# create virtual environment and install dependencies
(cd csit; rm -rf env; virtualenv env; source ./env/bin/activate; pip install -r requirements.txt; deactivate)
