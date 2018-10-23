
VPP Modular MiddleBox plugin
=====================

# mmb

**mmb** is a plugin that intents to implement middlebox policies that can be configured using generic CLI commands. It performs stateless packet matching based on any combination of constraints on network or transport protocol fields, stateful TCP and UDP flow matching, packet rewrite, packet dropping, bidirectionnal mapping. mmb is protocol-agnostic by allowing to match and rewrite fields ip4-payload, udp-payload and tcp-opt.

# HOWTO

## Run with vagrant

### Prerequisites

- Install **Vagrant** and **VirtualBox** on host machine.

### Installation

Still on host machine, navigate to `vagrant/`  and run:

    vagrant up
    vagrant ssh
    
### Run

On the virtual machine, navigate to `vpp-mb/scripts`. This directory contains scripts to create a few (VPP-only) network topologies that can be used to test **mmb**. For example, `topologies/ip4/small.sh` creates a 3 nodes (client - middlebox - server) topology.

### CLI Commands
All available commands are described in `docs/user-guide.pdf`.

## Administrative

### Current status

Latest and future additions are described in RELEASE.

### Links

- Github repository: https://github.com/mami-project/vpp-mb
- Material used for RCM tutorial at SIGCOMM 2018: https://github.com/mami-project/vpp-mb/tree/rcm

### Main contributors

Korian Edeline - LF-ID:ekorian
Justin Iurman
