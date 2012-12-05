#!/usr/bin/python

# -*- coding: utf-8 -*-
__license__ = '''
Topera - IPv6 Analysis tool

Copyright (C) 2011-2012  Daniel Garcia a.k.a cr0hn (@ggdaniel) | dani@iniqua.com
Copyright (C) 2011-2012  Rafael Sanchez (@r_a_ff_a_e_ll_o) | rafa@iniqua.com

Project page: http://code.google.com/p/topera/

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
'''

__author__ = ["Daniel Garcia a.k.a cr0hn (@ggdaniel) - dani@iniqua.com",
              "Rafael Sanchez (@r_a_ff_a_e_ll_o) - rafa@iniqua.com"]
__copyright__ = "Copyright 2012 - Topera project"
__credits__ = ["Daniel Garcia a.k.a cr0hn (@gganiel) - dani@iniqua.com", 
               "Rafael Sanchez (@r_a_ff_a_e_ll_o) - rafa@iniqua.com"]
__maintainer__ = "Daniel Garcia a.k.a cr0hn"
__status__ = "Testing"

import logging
# Delete warning messages for scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff,sendp,Ether,IPv6,TCP,IPv6ExtHdrDestOpt,LogLevel,RandShort
from libs.IODebug import *
from time import sleep
from libs.IPv6_utils import getLocalIPv6Address
from time import gmtime, strftime, clock
from libs.IPv6_utils import *


ports_opened = []
ports_closed = []
ports_filtered = []
ports_total = 0
ports_current = 0

LocalIP = None
isFound = False


#
# ProcessSniffedPacket
def ProcessSniffedPacket(pkt):
    """Process an sniffed packet looking for TCP response"""
    
    global ports_current
    global ports_total
    global isFound
    
    if pkt is not None and "IPv6" in pkt and "TCP" in pkt:

	if str(pkt[IPv6].src) != LocalIP:
	    rport = pkt[TCP].sport

	    # Check for state
	    state = pkt[TCP].flags
	    ack = pkt[TCP].ack

	    if ack != 0:
		if state == 18: # Open
		    ports_opened.append(rport)
		    IODebug.displayDebugInfo("Discovered open port %s/tcp on %s" % (str(rport), LocalIP))
		else: # Close
		    ports_closed.append(rport)	
	    else:
		if state == 18: # Filtered/closed
		    ports_filtered.append(rport)		    
		else: # Closed
		    ports_closed.append(rport)		    

	    ports_current += 1

	    if ports_current == ports_total:
		isFound = True # all ports scanned
# End ProcessSniffedPacket
#

#
# MakePacket
def __MakePacket(Global_params, dst_port):
    """Make a packet to send and return it"""
    m_MAC = Global_params.mac_dst
    m_ip_dst = Global_params.Target
    m_ip_src = Global_params.ip_src
    
    eth = Ether(dst=m_MAC, src = Global_params.mac_src)
    ip = IPv6(dst=m_ip_dst, src=m_ip_src)
    ipeh = IPv6ExtHdrDestOpt()/IPv6ExtHdrDestOpt()/IPv6ExtHdrDestOpt()/IPv6ExtHdrDestOpt()/IPv6ExtHdrDestOpt()/IPv6ExtHdrDestOpt()/IPv6ExtHdrDestOpt()/IPv6ExtHdrDestOpt()/IPv6ExtHdrDestOpt()
    tcp = TCP(dport=int(dst_port), sport=RandShort())
    
    packet = eth/ip/ipeh/tcp
    
    return packet
    
    
# End MakePacket
#

    

def sneakyTCPScan(Params_):
    """Do an sneaky IPv6 scan"""
    global LocalIP
    global ports_total
    global isFound
    
    # Convert to ms 
    m_sleep_time = Params_.sleep / 1000.0
	
    m_start_init = clock()
    LocalIP = Params_.ip_src # set var used for function called by sniffer
    ports_total = len(Params_.Port_range)
    
    IODebug.displayInfo("Starting Topera  ( http://iniqua.com ) at %s CET" % strftime("%Y-%m-%d %H:%M:%S", gmtime()))
    IODebug.displayInfo("Scanning %s [%s ports]" % (Params_.ip_src, str(len(Params_.Port_range))))    

    # Start sniffer
    m_sniffer = csniffer(Params_, "ip6 && tcp && not src host %s" % str(Params_.ip_src), fun=ProcessSniffedPacket)
    m_sniffer.start()

    # Start scan
    for port in Params_.Port_range:
	# Generate a packet
	l_packet = __MakePacket(Params_, port)
	
	IODebug.displayMoreDebugInfo("Trying port %s" % str(port))
	
	
	# Send
	sendp(l_packet, iface=Params_.iface_out, verbose=False)
	
	# Sleep time
	if m_sleep_time != 0:
	    sleep(m_sleep_time)	
	
    # Wait 10s to end
    for i in range(400):
	if isFound is not True:
	    sleep(0.05)

    # Stop sniffer
    m_sniffer.join()
    
    IODebug.displayInfo("Not shown: %s closed ports" % str(len(ports_closed)))
    
    # Display results
    IODebug.displayInfo("%s scan report for %s" % ("Topera", Params_.ip_src))
    IODebug.displayInfo("PORT\t\tSTATE")

    # Order results
    for po in ports_opened:
	IODebug.displayInfo("%s/tcp\t\topen" % (str(po)))	
    
    IODebug.displayInfo("\nTopera done: 1 IP address (1 host up) scanned in %s seconds" % (str(clock() - m_sleep_time)))

