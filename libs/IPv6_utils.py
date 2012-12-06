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

import threading
from scapy.all import *


#
# csniffer
class csniffer(threading.Thread):

	def __init__(self, Params_, filter_, fun):
		super(csniffer, self).__init__()
		self._params = Params_
		self._filters = filter_
		self.func = fun
		self.stoprequest = threading.Event()
	def run(self):
		m_filter = self._filters
		
		while not self.stoprequest.isSet():
			sniff(iface=self._params.iface_out, filter=m_filter, prn=self.func, store=0, timeout=2)

	def join(self, timeout=None):
		self.stoprequest.set()
		super(csniffer, self).join(timeout)

# End csniffer
#


#
# __getLocalIPv6Address
def getLocalIPv6Address(Params):
	"""Get first IPv6 address of IPv6 routes"""
	m_target = Params.Target
	m_return = ""	
	
	isIfaceSpecified = None # Check if iface is specified
	if Params.iface_out is None:
		isIfaceSpecified = False
	else:
		isIfaceSpecified = True

	for a in conf.route6.routes:
		if isIfaceSpecified:
			if a[1] == 128 and a[3] == Params.iface_out:			
				m_return = a[4][0]
				break			
		else:
			if a[1] == 128 and a[3] != "lo":			
				m_return = a[4][0]
				break
	return m_return
# __getLocalIPv6Address
#


#
# initGetRemoteAddr
def getRemoteAddr(Params):
	"""
	Get remote MAC addr of target

	return IPv6 Addr | "" if fail
	
	"""

	m_return = ""

	pkt = None
	
	try:
		pkt = neighsol(Params.Target, Params.ip_src, Params.iface_out, timeout=4)
	except:
		pass

	if pkt != None:
		m_return = str(pkt[ICMPv6ND_NA].lladdr)
		
	return m_return
		
# END initGetRemoteAddr
#

