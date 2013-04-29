#!/usr/bin/env python
# -*- coding: utf-8 -*-

__license__ = '''
Topera - IPv6 Analysis tool

Copyright (C) 2011-2012  Daniel Garcia a.k.a cr0hn (@ggdaniel) | cr0hn<@>cr0hn.com
Copyright (C) 2011-2012  Rafael Sanchez (@r_a_ff_a_e_ll_o) | rafa<@>iniqua.com

Project page: https://github.com/toperaproject/topera

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



__all__ = ["cmdParams", "Proxy", "Singleton", "setup_firewall"]


from subprocess import call
from platform import system

# Reject RST: Rules for man operating system
FIREWALL_RULES_TCP = {
    'darwin' : "ip6fw -q flush && ip6fw add 00042 drop tcp from any to %s in tcpflags rst", # MAC
    'linux'  : "ip6tables -F && ip6tables -A OUTPUT -p tcp --tcp-flags RST RST -d %s -j DROP",
    'bsd'    : "ip6fw -q flush && ip6fw add 00042 drop tcp from any to %s in tcpflags rst",
}



#----------------------------------------------------------------------
def setup_firewall(target, debug = 0):
	"""
	Configure the firewall for drop rst packets.

	BEFORE TO ADD THE RULE TO THE FIREWALL, ALL
	RULES WILL BE FLUSHED!!!!
	"""

	if not target:
		raise ValueError("You need to specify a target")

	try:
		if debug > 2:
			print "DEBUG 3: Setup firewall"
		m_command = FIREWALL_RULES_TCP[system().lower()]

		# Set dst
		m_command = m_command % (target)
		# Setup firewall
		retcode = call(m_command, shell=True)
		if retcode < 0:
			if debug:
				print "DEBUG 0: Fail executing firewall. Ret value: '%s'" % str(retcode)
			raise OSError("Command: '%s' can't be executed successfully.")
	except OSError, e:
		if debug:
			print "DEBUG 0: Execution failed in firewall"
	except KeyError:
		if debug:
			print "DEBUG 0: Execution failed in firewall: OS not supported"
		raise ("Your operating system '%s' is not supported." % system())

#----------------------------------------------------------------------
class Proxy(object):
	def __init__(self):
		self.lport = 80
		self.dport = 80
		self.rhost = "::1"
		self.lhost = "::1"

#----------------------------------------------------------------------
class cmdParams(object):
	def __init__(self):
		self.target        = ""
		self.mac_dst       = None
		"""Destination MAC address"""
		self.verbosity     = 0
		"""More verbose mode"""
		self.iface_out     = "eth0"
		"""Output interface"""
		self.sleep         = 100
		"""Sleep time between two packets"""
		self.ip_src        = ""
		"""Source IPv6 address"""
		self.mac_src       = ""
		"""Source MAC address"""
		self.run_mode      = ""
		"""Set run mode"""
		self.headers_num   = 10
		"""Headers num"""
		self.payload_type  = None
		"""Payload type"""

		self.level         = 2
		"""Network level: 2 o 3"""

		self.send_function = None
		"""Function used to send data: sendp or send."""

		# Internal use for output messages
		self.Out_normal   = None
		self.Out_error    = None


		self.proxy        = Proxy()


#--------------------------------------------------------------------------
class Singleton (object):
	"""
	Implementation of the Singleton pattern.
	"""

	# Variable where we keep the instance.
	_instance = None

	def __new__(cls):

		# If the singleton has already been instanced, return it.
		if cls._instance is not None:
			return cls._instance

		# Create the singleton's instance.
		cls._instance = super(Singleton, cls).__new__(cls)

		# Call the constructor.
		cls.__init__(cls._instance)

		# Delete the constructor so it won't be called again.
		cls._instance.__init__ = object.__init__
		cls.__init__ = object.__init__

		# Return the instance.
		return cls._instance