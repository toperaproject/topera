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

# system import
import sys
import textwrap

# Custom libs
import libs.argparse
from libs.data import *
from libs.IODebug import *
from api import *
from os import geteuid
from scapy.all import get_if_hwaddr
from libs.IPv6_utils import getRemoteAddr


__version__ = "0.0.1"
__prog__ = "Topera.py"
__examples__ = '''
Examples:	 
- %s -t fe80:b100:::c408
- %s -t fe80:b100:::c408 -vv -e eth2
	 ''' % (__prog__, __prog__)


def Credits():

	print ""
	print "|--------------------------------------------------|"
	print "| Topera - IPv6 analysis tool: the other side      |"
	print "|                                                  |"
	print "| Daniel Garcia a.k.a cr0hn (@ggdaniel)            |"
	print "| Rafael Sanchez (@r_a_ff_a_e_ll_o)                |"	
	print "|--------------------------------------------------|"
	print ""

#
# __splitParams
def __splitPorts(text_):
	'''
	Split comma or range separated ports from text_.
	
	@param text_: text with comma or range separated parameters.
	@param type: str
	
	@return: list with splited values. If values are not correct return empty list.
	@rtype: list | None if error
	'''
	m_return = []
	if text_ is not None:
		ports = text_.split(",")
		
		# Check for errors
		if len(ports) < 1:
			m_return = None
			return
			 

		for port in ports:
			# Check if split are a range
			l_range = port.split("-")
			
			if len(l_range) > 1: # Is a range
				if len(l_range) != 2: # Error!
					m_return = None
					break
				else:
					l_range_init = int(l_range[0])
					l_range_end = int(l_range[1])
					
					# Check for errors
					if l_range_init >= l_range_end and l_range_init >= 0 and l_range_init <= 65535  and l_range_end >= 0 and l_range_end <= 65535:
						m_return = None
						break
					else:
						m_return.extend(range(l_range_init, l_range_end))
						
					
			else: # Is not a range
				m_return.append(port)
	return m_return

# END __splitParams
#

#
# Start of program
#
if __name__ == '__main__':
	
	# Check for python version
	#if sys.version_info < (2, 7):
	#	print "\n[!] you must use python 2.7 or greater\n"
	#	#sys.exit(1)

	# Check if running user is root	
	if not geteuid()==0:
		print "\n[!] You must be root to run %s\n" % (__prog__)
		#sys.exit(1)
	
	Credits()	
	
	# Configure command line parser
	parser = libs.argparse.ArgumentParser(formatter_class=libs.argparse.RawDescriptionHelpFormatter, epilog=__examples__)
	gr1 = parser.add_argument_group("Main options")
	gr1.add_argument('-t', action='store', dest='target', help='IPv6 target. **MANDATORY**', required=True)	
	gr1.add_argument('-s', action='store', dest='ip_src', help='source IPv6 address.', default = None)
	gr1.add_argument('-V', action='store_true', help='display version.')
	gr1.add_argument('-sm', action='store', dest = 'mac_source', help='source mac address.', default = None)	
	gr1.add_argument('-dm', action='store', dest = 'mac_dest', help='target MAC address.', default = None)
	gr1.add_argument('-p', action='store', dest='ports_scan', help='ports to scan. Format: 22,23,43|22-34. Default: 0-1024', default="0-1024")
	gr1.add_argument('-v', action='store_true', dest='verbose', help='enable verbose mode')
	gr1.add_argument('-vv', action='store_true', dest='more_verbose', help='enable more verbose level')	
	gr1.add_argument('-e', action='store', dest='iface', help='output interface', default = None)
	gr1.add_argument('--scan-delay', action='store', dest='sleep', help='adjust delay between probes. Default 0ms')
	gr1.add_argument('-oN', action='store', dest='ofile', help='Output scan results.', default = None)


	# threads
	# resultados

	P = parser.parse_args()
	
	# Linking command line arguments with global structure
	cmdParams = cParams()
	cmdParams.Target = P.target
	cmdParams.mac_dst = P.mac_dest
	cmdParams.mac_src = P.mac_source	
	cmdParams.Port_raw = P.ports_scan
	cmdParams.verbose = P.verbose
	cmdParams.iface_out = P.iface
	cmdParams.ip_src = P.ip_src
	cmdParams.file_results = P.ofile
	cmdParams.more_verbose = P.more_verbose

	
	# Internal vas for show output 
	cmdParams.Out_normal = sys.stdout
	cmdParams.Out_error = sys.stderr
	
	# Configure IO display library
	IODebug.Configure(cmdParams.Out_normal, cmdParams.Out_error, cmdParams.verbose, cmdParams.more_verbose, cmdParams.file_results)	
	
	# Show version
	if P.V is True:
		IODebug.displayInfo("%s version is '%s'\n" % (__prog__, __version__))
		exit(0)
		
	
	# Split ports
	cmdParams.Port_range = __splitPorts(cmdParams.Port_raw)
	if cmdParams.Port_range == None:
		IODebug.displayError("Specified ports range are not valid.\n")
		exit(1)
		
		
	# Set local IP
	if cmdParams.ip_src is None:		
		cmdParams.ip_src = getLocalIPv6Address(cmdParams)
		if cmdParams.ip_src == "":
			IODebug.displayError("Can't get source IPv6. Please specify source IPv6 address option '-s'.\n")
			exit(1)				

	# Get remote MAC
	if cmdParams.mac_dst is None:
		cmdParams.mac_dst = getRemoteAddr(cmdParams)
		if cmdParams.mac_dst == "":
			IODebug.displayError("Can't get remote MAC address. Please specify source MAC address option '-dm'.\n")
			exit(1)					

	# Set local MAC
	try:
		if cmdParams.iface_out is None:
			cmdParams.mac_src = get_if_hwaddr("eth0")
		else:
			cmdParams.mac_src = get_if_hwaddr(cmdParams.iface_out)
	except:
		IODebug.displayError("Can't get source MAC address. Please specify source MAC address option '-sm'.\n")
		exit(1)				
	
	try:
		Topera_Main(cmdParams)
	except IOError,e:
		IODebug.displayInfo("\nError: %s\n" % str(e))
		sys.exit(1)
	except KeyboardInterrupt:
		IODebug.displayInfo("\nStopping...\n")
		sys.exit(1)
	except EOFError:
		print "CTRL+D"
		sys.exit(1)