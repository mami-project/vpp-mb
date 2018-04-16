#!/bin/bash

# Install VPP v17.10 (Ubuntu 16.04 Xenial)
echo "deb [trusted=yes] https://nexus.fd.io/content/repositories/fd.io.stable.1710.ubuntu.xenial.main/ ./" | tee -a /etc/apt/sources.list.d/99fd.io.list
apt-get update
apt-get install -y git vpp vpp-lib vpp-dev autoconf libtool traceroute python-scapy vpp-plugins

# Compile/Install MMB plugin
service vpp stop
(cd /home/vagrant/vpp-mb/mmb-plugin; autoreconf -fis; ./configure; make; make install)

rm /usr/lib/vpp_plugins/acl_plugin.so
rm /usr/lib/vpp_plugins/dpdk_plugin.so
rm /usr/lib/vpp_plugins/flowprobe_plugin.so
rm /usr/lib/vpp_plugins/gtpu_plugin.so
rm /usr/lib/vpp_plugins/ila_plugin.so
rm /usr/lib/vpp_plugins/ioam_plugin.so
rm /usr/lib/vpp_plugins/ixge_plugin.so
rm /usr/lib/vpp_plugins/lb_plugin.so
rm /usr/lib/vpp_plugins/libsixrd_plugin.so
rm /usr/lib/vpp_plugins/pppoe_plugin.so

