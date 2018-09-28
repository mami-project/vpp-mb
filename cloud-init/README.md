# README.md: sample cloud-init script for VPP-MB #

This directory contains a sample cloud-init script for vpp-mb. It will install VPP-MB on a virtual machine (VM) in your OpenStack environment.

## Requirements and dependencies ##

  * Ubuntu Bionic 64-bit cloud image from https://cloud-images.ubuntu.com/releases/18.04/release/
  * CPU model supporting SSE4.1 and SSE4.2 (see requirements in Vagrant directory)
  * 4 GBytes RAM
  * 32 GBytes HDD
  * Internet connectivity for the VM when booting

## Further configuration ##

### Networking ###

Add your networking configuration to the cloud-init script!

### User management ###

Add your SSH keys and/or a specific user definition **only** if needed. The software is installed by root and should be accessible system-wide.

### Reproducilibity ###

The current deployment depends on github HEAD. This may introduce some jitter when the code is updated. When releases are available, clone and select a stable (stabilised) tag to make the VM behave in a reproducible manner.
