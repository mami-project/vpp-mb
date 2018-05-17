#!/usr/bin/env python

from __future__ import print_function
from vpp_papi import VPP

vpp = VPP(['/usr/share/vpp/api/vpe.api.json', '/home/vagrant/vpp-mb/mmb-plugin/mmb/mmb.api.json'])

r = vpp.connect('justin', chroot_prefix='vpp1')
print(r)

#r = vpp.mmb_table_flush();
#print(r)
#dir(r)
#print(r.retval)

r = vpp.mmb_remove_rule(2)
print(r.retval)

r = vpp.mmb_remove_rule(2)
print(r.retval)

r = vpp.disconnect()
print(r)

exit(r)

