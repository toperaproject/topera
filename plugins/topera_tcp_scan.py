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

import logging
# Delete warning messages for scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# System imports
import multiprocessing
from time import sleep
from time import gmtime, strftime, clock
from random import randint

try:
	from scapy.all import IPv6, TCP, Ether
except ImportError:
	print ""
	print "[!] You need to install scapy libs."
	print ""
	print "To install it, run:"
	print "   apt-get install python-scapy"
	print ""
	exit(1)


# Topera imports
from topera.common import cmdParams, setup_firewall
from topera.plugins.plugins import ToperaPlugin
from topera.payloader import make_payload
from topera.iodebug import *
from topera.utils import split_ports, sniff

PORTS_OPEN     = multiprocessing.Manager().list()
PORTS_CLOSED   = multiprocessing.Manager().list()
PORTS_FILTERED = multiprocessing.Manager().list()

#------------------------------------------------------------------------------
class ToperaPortScanner(multiprocessing.Process):
	""""""

	#----------------------------------------------------------------------
	def __init__(self, target, partial_header, send_function, sleep_time = 0, dest_ports = ["80"], output_iface = "eth0", debuging = 0):
		"""Constructor"""
		super(ToperaPortScanner, self).__init__()

		self.__TARGET               = target
		self.__DEBUG                = debuging
		self.__OUTIFACE             = output_iface
		self.__PORTS                = dest_ports
		self.__TOTAL_PORTS          = len(dest_ports)
		self.__PARTIAL_HEADER       = partial_header
		self.__USED_PORTS           = multiprocessing.Manager().list()
		self.__PORTS_COUNT          = 0
		self.__SEND_FUNC            = send_function
		self.__SLEEP_TIME           = sleep_time
		self.__DONE                 = False

		# Configure the firewall
		setup_firewall(self.__TARGET)

	#----------------------------------------------------------------------
	def send_syn(self):
		"""Send all TCP SYN"""

		for l_dst_port in self.__PORTS:

			# Select source port
			m_SPORT      = randint(1025,65534)
			# Check if port are not already used
			while m_SPORT in self.__USED_PORTS:
				m_SPORT  = randint(1025,65534)

			# Store the port
			self.__USED_PORTS.append(m_SPORT)

			m_seq        = randint(11111,99999)

			IODebug.displayMoreDebugInfo("DEBUG 3: 3 way finished in thread '%s'" % str(self.ident))

			#
			# Making 3 way handshake
			#
			IODebug.displayDebugInfo("Trying port %s" % str(l_dst_port))
			self.__SEND_FUNC(self.__PARTIAL_HEADER/TCP(sport=m_SPORT, dport=int(l_dst_port), flags="S", seq=m_seq), verbose=0, iface=self.__OUTIFACE)

			# Sleep time
			sleep(self.__SLEEP_TIME)


	#----------------------------------------------------------------------
	def run(self):
		"""Run the attack"""
		# Run sniffer to receive ack
		m_filter     = "tcp and src host %s and ip6" % (str(self.__TARGET))
		m_timeout    = 2 if self.__TOTAL_PORTS * 0.5 < 2 else self.__TOTAL_PORTS * 0.5
		sniff(filter = m_filter, prn = self.count_ack, store=0, var_stop=self.__DONE, timeout =  m_timeout) # wait 200ms per port

	#----------------------------------------------------------------------
	def count_ack(self, pkt):
		""""""

		if "TCP" not in pkt or "IPv6" not in pkt or pkt["IPv6"].src != self.__TARGET:
			return

		rport = str(pkt[TCP].sport)

		# Check for state
		state = pkt[TCP].flags
		ack = pkt[TCP].ack

		global PORTS_OPEN, PORTS_CLOSED, PORTS_FILTERED

		if ack != 0:
			if state == 18: # Open
				if rport not in PORTS_OPEN:
					# Remove from closed ports
					if rport in PORTS_CLOSED:
						PORTS_CLOSED.remove(rport)

					PORTS_OPEN.append(rport)
					IODebug.displayDebugInfo("Discovered open port %s/tcp on %s" % (str(rport), self.__TARGET))
			else: # Close
				if rport not in PORTS_CLOSED:
					PORTS_CLOSED.append(rport)
		else:
			if state == 18: # Filtered/closed
				if rport not in PORTS_FILTERED:
					# Remove from closed ports
					if rport in PORTS_CLOSED:
						PORTS_CLOSED.remove(rport)
					PORTS_FILTERED.append(rport)
			else: # Closed
				if rport not in PORTS_CLOSED:
					PORTS_CLOSED.append(rport)

		self.__PORTS_COUNT += 1

		if self.__PORTS_COUNT == self.__TOTAL_PORTS:
			self.__DONE = True


class ToperaPortScannerPlugin(ToperaPlugin):

	#----------------------------------------------------------------------
	def get_parser(self, main_parser):
		if not main_parser:
			raise ValueError("Main parser can't be null")
		grmode = main_parser.add_argument_group("Port scanner options")

		grmode.add_argument('--scan-delay', action='store', dest='sleep', help='adjust delay between probes. Default 0ms', default=0.01, type=float)
		grmode.add_argument('-p', action='store', dest='ports_scan', help='ports to scan. Format: 22,23,43|22-34. Default: 0-1024', default="1-1024")

	def run(self, plugin_Params, global_params):
		"""Get the help message for this plugin."""

		#----------------------------------------------------------------------
		# Packet layers
		TARGET            = global_params.target
		DST_MAC           = global_params.mac_dst
		OUT_IFACE         = global_params.iface_out
		SEND_FUNCTION     = global_params.send_function
		PORTS             = split_ports(plugin_Params.ports_scan)
		SLEEP_TIME        = plugin_Params.sleep / 1000.0

		eth_header        = Ether(dst=DST_MAC)
		ip_header         = IPv6(dst=TARGET)
		# Add headers
		ip_payload        = make_payload(num_headers=global_params.headers_num, ext_type=global_params.payload_type)

		# Make the payload
		if ip_payload:
			PARTIAL_HEADER    = eth_header/ip_header/ip_payload
		else:
			PARTIAL_HEADER    = eth_header/ip_header

		#
		# Shared data
		# {'state': []}
		#
		# Example:
		# {
		#   'open'   : [80,8080],
		#   'closed' : [139,445]
		# }
		#
		global PORTS_OPEN, PORTS_CLOSED, PORTS_FILTERED

		# Init all ports as closed
		PORTS_CLOSED.extend(PORTS)

		# Process
		topera  = ToperaPortScanner(TARGET,
		            partial_header = PARTIAL_HEADER,
		            send_function  = SEND_FUNCTION,
		            dest_ports     = PORTS,
		            sleep_time     = SLEEP_TIME,
		            output_iface   = OUT_IFACE,
		            debuging       = global_params.verbosity)
		try:

			IODebug.displayInfo("Scanning %s [%s ports]" % (TARGET, str(len(PORTS))))
			m_start_init      = clock()
			m_timeout         = len(PORTS) * 2
			m_timeout_counter = 0

			# Start
			topera.start()

			# Launch all syn packets
			topera.send_syn()

			topera.join()

			IODebug.displayInfo("Not shown: %s closed ports" % str(len(PORTS_CLOSED)))

			# Display results
			IODebug.displayInfo("%s scan report for %s" % ("Topera", TARGET))
			IODebug.displayInfo("PORT\t\tSTATE")

			# Order results
			for po in PORTS_OPEN:
				IODebug.displayInfo("%s/tcp\t\topen" % (str(po)))

			IODebug.displayInfo("\nTopera done: 1 IP address (1 host up) scanned in %s seconds" % (str(clock() - m_start_init)))


		except KeyboardInterrupt:
			print "\n[*] Stoping, please be patient..."
			topera.terminate()
			print ""

	#----------------------------------------------------------------------
	def display_help(self):
		"""Display help for this plugin."""
		return """
A IPv6 TCP scanner undetectable for Snort."""
