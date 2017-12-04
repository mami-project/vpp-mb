#!/usr/bin/python
from scapy.all import *

TIMEOUT = 2
conf.verb = 0

def packet(dst,tos=0x0,id=RandShort(),ip_flags=0L,ttl=1,sport=RandInt(),dport=80,seq=RandInt(),ack=0,tcp_flags="S",window=65535,options={}):

    """
    forge a single TCP packet
    and returns it
    
    Note: IP ihl,length,checksum and TCP data-offset and checksums are computed automatically  

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
    p=IP(dst=dst,tos=tos,ttl=ttl,flags=ip_flags,id=id)/TCP(flags=tcp_flags,dport=dport,sport=sport,ack=ack,seq=seq,window=window,options=options)
    #ls(p) # displays each packets field
    return p

def tcp_ping(host,timeout=2,inter=0,verbose=0):
    ''' 
     TCP Ping 
    

     Arguments:
      host      -- the destination
      timeout   -- the time to wait after the last packet has been sent. 
                   If 0, it will wait forever and the user will have to interrupt 
                   (Ctrl-C) it when he expects no more answers. (default 3)
      inter     -- the time to wait between two packet sending in seconds (default 0)
      verbose   -- override the level of verbosity. 
                   Make the function totally silent when 0, verbose with None 
                   (default 0)
    '''

    # define probes
    tcp_opt=[("MSS",1850),("WScale",18),("NOP",None)]
    tcp_seq=RandInt() % (2**32 - 1)
    tcp_sport=(RandInt() % 2000)+35000
    tcp_dport=80
    ip_id=1234
    ip_tos=64
    ip_ttl=10
    p1=packet(host,ttl=ip_ttl,tos=ip_tos,id=ip_id,seq=tcp_seq,
             dport=tcp_dport,sport=tcp_sport,options=tcp_opt)

    tcp_opt=[("SAck",(0x1badc0de,0xdeadbeef,0x900d90a7,0xb19a55)),("WScale",3),("NOP",None)]
    tcp_seq=0x12345678
    tcp_sport=335
    tcp_dport=443
    ip_id=0
    ip_tos=128
    p2=packet(host,ttl=ip_ttl,tos=ip_tos,id=ip_id,seq=tcp_seq,
             dport=tcp_dport,sport=tcp_sport,options=tcp_opt)


    tcp_opt=[("SAckOK",""),("NOP",None),("NOP",None)]
    tcp_seq=0x12345678
    tcp_sport=335
    tcp_dport=443
    ip_id=RandInt()%2**16
    ip_tos=128
    p3=packet(host,ttl=ip_ttl,tos=ip_tos,id=ip_id,seq=tcp_seq,
             dport=tcp_dport,sport=tcp_sport,options=tcp_opt)

    tcp_opt=[("SAckOK",""),("NOP",None),("NOP",None)]
    tcp_seq=0x1fedbeef
    tcp_sport=12345
    tcp_dport=54321
    tcp_payload="PAYLOAD_LOL"
    ip_id=RandInt()%2**16
    ip_tos=128
    p4=packet(host,ttl=ip_ttl,tos=ip_tos,id=ip_id,seq=tcp_seq,
             dport=tcp_dport,sport=tcp_sport,options=tcp_opt)/tcp_payload

    # option kind 25, unsassigned but defined in scapy
    # probably for testing, so let's test
    tcp_opt=[("Mood", ("ip-options-are-not-an-option^^"))] 
    tcp_seq=0x1fedbeef
    tcp_sport=12345
    tcp_dport=54321
    tcp_payload="not a payload"
    ip_id=RandInt()%2**16
    ip_tos=128
    p5=packet(host,ttl=ip_ttl,tos=ip_tos,id=ip_id,seq=tcp_seq,
             dport=tcp_dport,sport=tcp_sport,options=tcp_opt)/tcp_payload

    send(p1,count=2)
    send(p2,count=2)
    send(p3,count=2)
    send(p4,count=2)
    send(p5,count=2)

tcp_ping("10.10.2.2")
