#!/usr/bin/python
# -*- coding: utf-8 -*-

__license__ = '''
Topera - IPv6 Analysis tool

Copyright (C) 2011-2012  Daniel Garcia a.k.a cr0hn (@ggdaniel) | cr0hn<@>cr0hn.com
Copyright (C) 2011-2012  Rafael Sanchez (@r_a_ff_a_e_ll_o) | rafa<@>iniqua.com

Project page: https://github.com/toperaproject/topera/

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



__all__ = ["get_local_ipv6_address", "get_remote_addr", "split_ports"]

import threading
from scapy.all import neighsol, ETH_P_ALL, conf, ICMPv6ND_NA, PcapReader, plist, MTU
import select
import time


#----------------------------------------------------------------------
class Sniffer(threading.Thread):

	def __init__(self, Params_, filter_, fun):
		super(Sniffer, self).__init__()
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
		super(Sniffer, self).join(timeout)



#----------------------------------------------------------------------
def get_local_ipv6_address(iface):
	"""Get first IPv6 address for an input interface.

	:param iface: interface name.
	:type iface: str

	:return: IPv6 address
	:rtype: str
	"""
	m_return = None

	isIfaceSpecified = True if iface else False # Check if iface is specified

	# Get first IPv6 address
	for a in conf.route6.routes:
		if isIfaceSpecified:
			if a[3] == iface:
				m_return = a[4][0]
				break

	if not m_return:
		raise RuntimeError("Can't obtain local IPv6 address for '%s' interface. You can try pass it manually as command line parameter." % iface)

	return m_return
#----------------------------------------------------------------------
def get_remote_addr(target, ip_src, output_iface):
	"""
	Get remote MAC addr of target

	return IPv6 Addr | "" if fail
	"""

	pkt = None

	try:
		if not target or not ip_src or not output_iface:
			raise RuntimeError("Can't obtain remote MAC addr. Target, source IP or output inteface can't be null. You can try pass it manually as command line parameter.")

		pkt = neighsol(target, ip_src, output_iface, timeout=4)
	except:
		raise RuntimeError("Can't obtain dinamically remote MAC addr. Ensure that your interface can be set as promiscuous mode. You can try pass it manually as command line parameter. BE SURE YOU HAVE VISIBILITY WITH THE TARGET.")

	if not pkt:
		raise RuntimeError("Can't obtain dinamically remote MAC addr. Ensure that your interface can be set as promiscuous mode. You can try pass it manually as command line parameter. BE SURE YOU HAVE VISIBILITY WITH THE TARGET.")

	return str(pkt[ICMPv6ND_NA].lladdr)


#----------------------------------------------------------------------
def split_ports(text_):
	'''
	Split comma or range separated ports from text_.

	:param text_: text with comma or range separated parameters.
	:type text_: str

	:return: list with splited values. If values are not correct return empty list.
	:rtype: list | None if error
	'''

	if not text_:
		raise ValueError("Ports can't be empty value.")

	m_return = []
	m_return_append = m_return.append
	m_return_extend = m_return.extend

	ports = text_.split(",")

	# Check for errors
	if not ports:
		raise ValueError("Ports must contain ports numbers. Invalid format got.")


	for port in ports:
		# Check if split are a range

		if port.find("-") != -1:
			l_range = port.split("-")

			if len(l_range) != 2:
				raise ValueError("Port range specification error.")

			l_range_init = int(l_range[0])
			l_range_end  = int(l_range[1])

			if l_range_init >= l_range_end:
				raise ValueError("Initial value of port range must be lower than end value.")

			# Check ranges
			if l_range_init < 0 or l_range_init > 65535 or \
			   l_range_end  < 0 or l_range_end  > 65535:
				raise ValueError("Port value must be between 1-65535")

			m_return_extend(range(l_range_init, l_range_end))

		else: # If is not a range
			m_port = None
			try:
				m_port = int(port)
			except TypeError:
				raise ValueError("Port must be a number")

			if m_port < 1 or m_port > 65535:
				raise ValueError("Port value must be between 1-65535")

			m_return_append(port)

	return set(m_return) # Delete repeated values


#----------------------------------------------------------------------
# Overwritten version of sniff function to add and option to force stopping
#
@conf.commands.register
def sniff(count=0, store=1, offline=None, prn = None, lfilter=None, L2socket=None, timeout=None,
           opened_socket=None, stop_filter=None, var_stop = False, *arg, **karg):
	"""Sniff packets
sniff([count=0,] [prn=None,] [store=1,] [offline=None,] [lfilter=None,] + L2ListenSocket args) -> list of packets

	count: number of packets to capture. 0 means infinity
	store: wether to store sniffed packets or discard them
	prn: function to apply to each packet. If something is returned,
	     it is displayed. Ex:
	     ex: prn = lambda x: x.summary()
lfilter: python function applied to each packet to determine
	     if further action may be done
	     ex: lfilter = lambda x: x.haslayer(Padding)
offline: pcap file to read packets from, instead of sniffing them
timeout: stop sniffing after a given time (default: None)
L2socket: use the provided L2socket
opened_socket: provide an object ready to use .recv() on
stop_filter: python function applied to each packet to determine
	         if we have to stop the capture after this packet
	         ex: stop_filter = lambda x: x.haslayer(TCP)
	"""
	c = 0

	if opened_socket is not None:
		s = opened_socket
	else:
		if offline is None:
			if L2socket is None:
				L2socket = conf.L2listen
			s = L2socket(type=ETH_P_ALL, *arg, **karg)
		else:
			s = PcapReader(offline)

	lst = []
	if timeout is not None:
		stoptime = time.time()+timeout
	remain = None

	while 1 and not var_stop:
		try:
			if timeout is not None:
				remain = stoptime-time.time()
				if remain <= 0:
					break
			sel = select.select([s],[],[],remain)
			if s in sel[0]:
				p = s.recv(MTU)
				if p is None:
					break
				if lfilter and not lfilter(p):
					continue
				if store:
					lst.append(p)
				c += 1
				if prn:
					r = prn(p)
					if r is not None:
						print r
				if stop_filter and stop_filter(p):
					break
				if count > 0 and c >= count:
					break
		except KeyboardInterrupt:
			var_stop = True
			break


	if opened_socket is None:
		s.close()