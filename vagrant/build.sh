#!/bin/bash

# Install VPP (Ubuntu 16.04 Xenial)
echo "deb [trusted=yes] https://nexus.fd.io/content/repositories/fd.io.stable.1807.ubuntu.xenial.main/ ./" | tee /etc/apt/sources.list.d/99fd.io.list
apt-get update
apt-get install -y vpp vpp-lib vpp-dev vpp-plugins vpp-api-python python-cffi autoconf libtool ethtool #traceroute python-scapy

# Remove any installed vpp plugins
service vpp stop
sudo rm /usr/lib/vpp_plugins/abf_plugin.so
sudo rm /usr/lib/vpp_plugins/gbp_plugin.so
sudo rm /usr/lib/vpp_plugins/l2e_plugin.so
sudo rm /usr/lib/vpp_plugins/stn_plugin.so
sudo rm /usr/lib/vpp_plugins/acl_plugin.so
sudo rm /usr/lib/vpp_plugins/gtpu_plugin.so
sudo rm /usr/lib/vpp_plugins/lacp_plugin.so
sudo rm /usr/lib/vpp_plugins/nat_plugin.so
sudo rm /usr/lib/vpp_plugins/tlsmbedtls_plugin.so
sudo rm /usr/lib/vpp_plugins/avf_plugin.so
sudo rm /usr/lib/vpp_plugins/igmp_plugin.so
sudo rm /usr/lib/vpp_plugins/lb_plugin.so
sudo rm /usr/lib/vpp_plugins/pppoe_plugin.so
sudo rm /usr/lib/vpp_plugins/tlsopenssl_plugin.so
sudo rm /usr/lib/vpp_plugins/cdp_plugin.so
sudo rm /usr/lib/vpp_plugins/ila_plugin.so
sudo rm /usr/lib/vpp_plugins/mactime_plugin.so
sudo rm /usr/lib/vpp_plugins/srv6ad_plugin.so
sudo rm /usr/lib/vpp_plugins/ioam_plugin.so
sudo rm /usr/lib/vpp_plugins/map_plugin.so
sudo rm /usr/lib/vpp_plugins/srv6am_plugin.so
sudo rm /usr/lib/vpp_plugins/flowprobe_plugin.so
sudo rm /usr/lib/vpp_plugins/ixge_plugin.so
sudo rm /usr/lib/vpp_plugins/srv6as_plugin.so
sudo rm /usr/lib/vpp_plugins/dpdk_plugin.so
sudo rm /usr/lib/vpp_plugins/nsh_plugin.so
sudo rm /usr/lib/vpp_plugins/nsim_plugin.so
sudo rm /usr/lib/vpp_plugins/svs_plugin.so
sudo rm /usr/lib/vpp_plugins/unittest_plugin.so
sudo rm /usr/lib/vpp_plugins/vmxnet3_plugin.so

sudo rm /usr/lib/vpp_api_test_plugins/acl_test_plugin.so          
sudo rm /usr/lib/vpp_api_test_plugins/ioam_pot_test_plugin.so        
sudo rm /usr/lib/vpp_api_test_plugins/memif_test_plugin.so
sudo rm /usr/lib/vpp_api_test_plugins/avf_test_plugin.so          
sudo rm /usr/lib/vpp_api_test_plugins/ioam_trace_test_plugin.so      
sudo rm /usr/lib/vpp_api_test_plugins/mmb_test_plugin.so
sudo rm /usr/lib/vpp_api_test_plugins/cdp_test_plugin.so          
sudo rm /usr/lib/vpp_api_test_plugins/ioam_vxlan_gpe_test_plugin.so  
sudo rm /usr/lib/vpp_api_test_plugins/nat_test_plugin.so
sudo rm /usr/lib/vpp_api_test_plugins/dpdk_test_plugin.so         
sudo rm /usr/lib/vpp_api_test_plugins/lacp_test_plugin.so            
sudo rm /usr/lib/vpp_api_test_plugins/pppoe_test_plugin.so
sudo rm /usr/lib/vpp_api_test_plugins/flowprobe_test_plugin.so    
sudo rm /usr/lib/vpp_api_test_plugins/lb_test_plugin.so              
sudo rm /usr/lib/vpp_api_test_plugins/stn_test_plugin.so
sudo rm /usr/lib/vpp_api_test_plugins/gtpu_test_plugin.so         
sudo rm /usr/lib/vpp_api_test_plugins/mactime_test_plugin.so         
sudo rm /usr/lib/vpp_api_test_plugins/udp_ping_test_plugin.so
sudo rm /usr/lib/vpp_api_test_plugins/ioam_export_test_plugin.so  
sudo rm /usr/lib/vpp_api_test_plugins/map_test_plugin.so             
sudo rm /usr/lib/vpp_api_test_plugins/vxlan_gpe_ioam_export_test_plugin.so
sudo rm /usr/lib/vpp_api_test_plugins/ioam_test_plugin.so
sudo rm /usr/lib/vpp_api_test_plugins/nsh_test_plugin.so
sudo rm /usr/lib/vpp_api_test_plugins/nsim_test_plugin.so
sudo rm /usr/lib/vpp_api_test_plugins/vmxnet3_test_plugin.so

# Compile/Install MMB plugin
(cd /home/vagrant/vpp-mb/mmb-plugin; autoreconf -fis; ./configure; make; make install)

