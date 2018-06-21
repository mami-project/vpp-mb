#!/usr/bin/env python3
"""
This file contains basic functions which can be used
to code a simplified Tracebox.

Scapy documentation and examples can be found at: 
  http://www.secdev.org/projects/scapy/doc/

@author: K.Edeline
"""
import sys
from scapy.all import *
import threading
import queue
import time

def send_probe(dst,timeout=3,inter=0,verbose=0,tos=0x4,
               id=RandShort(),ip_flags=0,ttl=1,dport=80,
               seq=RandInt(),ack=0,tcp_flags="S",window=8192,
               options=[("WScale", 18)],iface="vpp1host"):

    """
    sends a single TCP packet
    and returns the answer or None if it timeouted.
    
    Note: IP ihl,length,checksum and TCP data-offset and checksums are computed automatically  

    Arguments:
      timeout   -- the time to wait after the last packet has been sent. 
                   If 0, it will wait forever and the user will have to interrupt 
                   (Ctrl-C) it when he expects no more answers. (default 3)
      inter     -- the time to wait between two packet sending in seconds (default 0)
      verbose   -- override the level of verbosity. 
                   Make the function totally silent when 0, verbose with None 
                   (default 0)

    IP arguments:
      tos       -- the IP ToS value of the packet (default 0x0)
      ttl       -- the Time-To-Live of the packet (default 1)
      id        -- the IP id of the packet (default random)
      flags     -- the IP flags of the packet (default 0x0)      

    TCP arguments:
      flags     -- the TCP flags of the packet (default SYN)
      dport     -- the TCP destination port for the packet (default 80)   
      window    -- the TCP receive window size (default 8192)
      seq       -- the TCP sequence number (default random)
      ack       -- the TCP acknowledgment number (default 0)
      options   -- the TCP options of the packet (see sources at ~/scapy-2.1.0/scapy/layers/inet.py)
                   Available options: EOL, NOP, MSS, WScale, SAckOK, SAck, Timestamp, AlktChksum, AlkChkSumOpt 
    """
    #p=IP(dst=dst,tos=tos,ttl=ttl,flags=ip_flags,id=id)/TCP(flags=tcp_flags,dport=dport,ack=ack,seq=seq,window=window,options=options)
    p=IP(dst=dst,tos=tos,ttl=ttl,flags=ip_flags,id=id)/UDP(dport=dport)
    return send(p,iface=iface,verbose=verbose)

_q=queue.Queue()
def _start_sniffer(src,dst,iface="vpp1host",timeout=3):
    p=sniff(filter="(icmp or udp or tcp) and dst {}".format(src),
            count=1,iface="enp4s0",timeout=timeout)
    _q.put(p)

def start_sniffer(src,dst):
    t = threading.Thread(target=_start_sniffer, args=(src,dst,))
    t.start()
    time.sleep(0.5)
    return t

def recv_probe(t):
    t.join()
    p=_q.get()
    if not p:
      return None
    else:
      return p[0].getlayer(1)

def traceroute(dest,src="10.100.100.1",max_ttl=32,perhop_maxretry=3,total_maxretry=5):
    """
    A simple traceroute function.

    You can use it as a core for your tracebox implementation.


    Arguments:
      dest            -- the destination ipv4 address (mandatory argument)
      max_ttl         -- the maximum TTL value, if the destination is not 
                         reached yet, the traceroute is aborted (default 64)
      perhop_maxretry -- the maximum number of retries for a single 
                         TTL value before trying with the next value (default 3)
      total_maxretry  -- the maximum number of consecutive retries 
                         before aborting (default 5)
            
    """

    perhop_retry_count=0
    consecutive_retry_count=0
    i=1
    while i < max_ttl:
        # Send the packet and get a reply "host "+dest
        #
        s=start_sniffer(src,dest)
        send_probe(dst=dest,ttl=i)
        reply=recv_probe(s)

        if reply is None or not reply:
            # No reply =( (timeouted)
            print("%d: *" % i)
            perhop_retry_count+=1
            consecutive_retry_count+=1
            
            if perhop_retry_count==perhop_maxretry:
               #Trying next hop
               i+=1
               perhop_retry_count=0
            elif consecutive_retry_count >= total_maxretry:
                #Too many retries, aborting ....
                print("Timeout")
                return 0
            
        elif reply.src == dest:
            # We've reached our destination
            print("Destination reached:", reply.src)
            #ls(reply)
            return 1
        else:
            # We received an answer
            print("%d: " % i , reply.src)
            i+=1
            perhop_retry_count=0
            consecutive_retry_count=0
            #ls(reply)
        
    print("Max TTL reached, aborting ....")
    return 0


def main(argv):
    """
    Main function

    """
    if len(argv) != 1:
        print("Usage: ./simple_tracebox.py <destination_ip>")
        return

    traceroute(argv[0])
    return
    
if __name__ == "__main__":
    main(sys.argv[1:])

