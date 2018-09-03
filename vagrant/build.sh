#!/bin/bash

# Install VPP v18.01 (Ubuntu 16.04 Xenial)
echo "deb [trusted=yes] https://nexus.fd.io/content/repositories/fd.io.stable.1801.ubuntu.xenial.main/ ./" | tee /etc/apt/sources.list.d/99fd.io.list
apt-get update
apt-get install -y vpp vpp-lib vpp-dev vpp-plugins vpp-api-python python-cffi autoconf libtool ethtool #traceroute python-scapy

# Remove any installed vpp plugins
service vpp stop
rm /usr/lib/vpp_plugins/*.so

# Compile/Install MMB plugin
(cd /home/vagrant/vpp-mb/mmb-plugin; autoreconf -fis; ./configure; make; make install)

