#!/usr/bin/env python

from __future__ import print_function
from vpp_papi import VPP

vpp = VPP(['/usr/share/vpp/api/vpe.api.json', '/home/vagrant/vpp-mb/mmb-plugin/mmb/mmb.api.json'])

r = vpp.connect('justin', chroot_prefix='vpp1')
#print(r)

r = vpp.api.show_version()
print('VPP version =', r.version.decode().rstrip('\0x00'), '\n')

print('MMB table rules:')
print('================')
for rule in vpp.mmb_table_dump():
  print(' rule num ', rule.rule_num)
print('================\n')

print('Removing rule num 3...')
r = vpp.mmb_remove_rule(rule_num=3)
print('return status = ', r.retval, '\n')

print('MMB table rules:')
print('================')
for rule in vpp.mmb_table_dump():
  print(' rule num ', rule.rule_num)
print('================\n')

print('Removing rule num 3...')
r = vpp.mmb_remove_rule(rule_num=3)
print('return status = ', r.retval, '\n')

print('MMB table rules:')
print('================')
for rule in vpp.mmb_table_dump():
  print(' rule num ', rule.rule_num)
print('================\n')

print('Flushing MMB table...')
r = vpp.mmb_table_flush();
#print(r)
#dir(r)
print('return status = ', r.retval, '\n')

print('MMB table rules:')
print('================')
for rule in vpp.mmb_table_dump():
  print(' rule num ', rule.rule_num)
print('================\n')

r = vpp.disconnect()
#print(r)

exit(r)

