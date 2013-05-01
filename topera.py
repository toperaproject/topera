#!/usr/bin/python
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

__author__ = ["Daniel Garcia a.k.a cr0hn (@ggdaniel) - cr0hn<@>cr0hn.com",
              "Rafael Sanchez (@r_a_ff_a_e_ll_o) - rafa<@>iniqua.com"]
__copyright__ = "Copyright 2012 - Topera project"
__credits__ = ["Daniel Garcia a.k.a cr0hn (@gganiel) - cr0hn<@>cr0hn.com",
               "Rafael Sanchez (@r_a_ff_a_e_ll_o) - rafa<@>iniqua.com"]
__maintainer__ = "Daniel Garcia a.k.a cr0hn"
__status__ = "Testing"


# system import
import sys
import os.path as path

try:
	import argparse
except ImportError:
	print "\n[!] You must use python 2.7 or greater\n"
	sys.exit(1)

from time import gmtime, strftime, clock

# Delete warning messages for scapy
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
	from scapy.all import send, sendp, IPv6, sr1, ICMPv6EchoRequest
except ImportError:
	print ""
	print "[!] You need to install scapy libs."
	print ""
	print "First install depends:"
	print "   apt-get install tcpdump graphviz imagemagick python-gnuplot python-crypto python-pyx"
	print ""
	print "Then intall scapy:"
	print "   wget http://hg.secdev.org/scapy/archive/tip.zip -O scapy-lastest.zip"
	print "   unzip scapy-latest.zip"
	print "   cd scapy-xxxxxxxxx"
	print "   sudo python setup.py install"
	print ""
	exit(1)


# Custom libs
from topera.iodebug import *
from topera.common import cmdParams
from topera.plugins.pricillapluginmanager import *
from topera.payloader import PAYLOAD_TYPES
from topera.utils import *


__version__ = "0.0.2"
__prog__ = "topera.py"
__examples__ = '''
Examples:
+ List plugins:
  - %s -L
+ Topera loris:
  - %s -M topera_loris -t fe80:b100:::c408
  - %s -M topera_loris -t fe80:b100:::c408 --dport 8080 --delay 0 --headers-num 0 -vvv
+ Topera TCP scanner:
  - %s -M topera_tcp_scan -t fe80:b100:::c408
  - %s -M topera_tcp_scan -t fe80:b100:::c408 -p 21,22,23,80,8080 --scan-delay 0 --headers-num 0 -vvv
''' % (__prog__, __prog__, __prog__, __prog__, __prog__)


def Credits():

	print ""
	print "|--------------------------------------------------|"
	print "| Topera - IPv6 analysis tool: the other side      |"
	print "|                                                  |"
	print "| Project page:                                    |"
	print "|   http://toperaproject.github.io/topera/         |"
	print "|                                                  |"
	print "| Daniel Garcia a.k.a cr0hn (@ggdaniel)            |"
	print "| Rafael Sanchez (@r_a_ff_a_e_ll_o)                |"
	print "|--------------------------------------------------|"
	print ""


#----------------------------------------------------------------------
def get_user():
	"""Return True if User is system Admin. False otherwise. This is valid for Windows and *NIX"""
	try:
		from os import geteuid
		return geteuid() == 0
	except ImportError:
		from getpass import getuser

		return getuser().lower().startwith("admin")


#
# Start of program
if __name__ == '__main__':

	Credits()

	# Check for python version
	if sys.version_info < (2, 7):
		print "\n[!] you must use python 2.7 or greater\n"
		sys.exit(1)

	# Check if running user is root
	if not get_user():
		print "\n[!] You must be root to run %s\n" % (__prog__)
		sys.exit(1)

	# Configure command line parser
	parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__examples__, add_help=False)
	#parser.add_argument("target", metavar="TARGET", help="IPv6 target")
	target = parser.add_argument_group("Target selection")
	target.add_argument("-t",action="store", dest="target", metavar="TARGET", help="IPv6 target")

	gr1 = parser.add_argument_group("Main options")
	gr1.add_argument('-V', action='store_true', help='display version.')
	gr1.add_argument("-v", "--verbose", action="count", default=0, help="increase output verbosity")
	gr1.add_argument('-oN', metavar="OUTPUT_FILE", action='store', dest='ofile', help='Output scan results.', default = None)
	gr1.add_argument('--headers-num', metavar="NUMBER", action='store', dest='headers_num', help='Number of extension headers', default=10, type=int)
	gr1.add_argument('--payload-type', metavar="PAYLOAD", action='store', dest='payload_type', help='type of payload for IPv6 packages', choices = PAYLOAD_TYPES.keys(), default="FRAGOPT")
	gr1.add_argument('-h','--help', action='store_true', dest='help', help='display help')

	grnet = parser.add_argument_group("Network options")
	grnet.add_argument('-s', action='store', dest='ip_src', help='source IPv6 address.', default = None)
	grnet.add_argument('-sm', action='store', dest = 'mac_source', help='source mac address.', default = None)
	grnet.add_argument('-dm', action='store', dest = 'mac_dest', help='target MAC address.', default = None)
	grnet.add_argument('-e', action='store', dest='iface', help='output interface', default = "eth0")

	grmode = parser.add_argument_group("Modes")
	grmode.add_argument('-M', action='store', dest='run_mode', help='set run mode', default="topera_loris")
	grmode.add_argument('-L', action='store_true', dest='modes_lists', help='list run modes')
	grmode.add_argument('--runmode-info', action='store_true', dest='runmode_info', help='display information for a run mode.')


	#
	# Load plugins
	#
	# Set plugin folder
	plugins_folder = path.abspath(__file__)
	plugins_folder = path.dirname(plugins_folder)
	plugins_folder = path.join(plugins_folder, "plugins")
	if not path.isdir(plugins_folder):
		raise EnvironmentError("Can't locate plugin folder at './plugins'. Execution aborted.")

	# Load plugin options
	manager = PriscillaPluginManager()
	manager.find_plugins(plugins_folder)

	# Add command line options of each plugin
	m_plugin_instances = manager.load_plugins(category="all")
	#for name, prop in manager.get_plugins("all").iteritems():
	for name, l_instance in m_plugin_instances.iteritems():
		# Set argparse options of plugin
		l_instance.get_parser(parser)

	P = parser.parse_args()

	# Linking command line arguments with global structure
	cmdParams              = cmdParams()
	cmdParams.target       = P.target
	cmdParams.mac_dst      = P.mac_dest
	cmdParams.mac_src      = P.mac_source
	cmdParams.verbose      = P.verbose
	cmdParams.iface_out    = P.iface
	cmdParams.ip_src       = P.ip_src
	cmdParams.file_results = P.ofile
	cmdParams.run_mode     = P.run_mode
	cmdParams.headers_num  = P.headers_num
	cmdParams.payload_type = P.payload_type


	# Internal vas for show output
	cmdParams.Out_normal   = sys.stdout
	cmdParams.Out_error    = sys.stderr

	# Configure IO display library
	IODebug.Configure(cmdParams.Out_normal, cmdParams.Out_error, cmdParams.verbose, cmdParams.file_results)

	# Show version
	if P.V:
		IODebug.displayInfo("%s version is '%s'\n" % (__prog__, __version__))
		exit(0)

	try:

		# Display run modes?
		if P.modes_lists:
			print "Run modes:"
			for name, prop in manager.get_plugins("all").iteritems():
				print "+ %s - %s" % (name, prop.description)
			print ""
			sys.exit(0)

		# Check if run mode exits
		if P.run_mode not in manager.get_plugins("all"):
			raise ValueError("Selected run mode are not valid")

		# Display run mode info?
		if P.runmode_info:
			print P.run_mode
			print "=" * len(P.run_mode)
			print m_plugin_instances[P.run_mode].display_help()
			print ""
			sys.exit(0)


		# Plugin info selected?
		if P.help:
			parser.print_help()
			sys.exit(0)


		# Passed target as parameter?
		if not cmdParams.target:
			IODebug.displayInfo("%s: error: too few arguments\n" % __prog__)
			exit(1)

		# Set local IP
		if not cmdParams.ip_src:
			cmdParams.ip_src = get_local_ipv6_address(cmdParams.iface_out)

		# Start
		IODebug.displayInfo("Starting Topera  ( https://github.com/toperaproject/topera ) at %s CET" % strftime("%Y-%m-%d %H:%M:%S", gmtime()))

		# Check if destination are reachable
		IODebug.displayDebugInfo("DEBUG 1: Checking if destination are reachable")

		# Get remote MAC
		if not cmdParams.mac_dst:
			try:
				cmdParams.mac_dst = get_remote_addr(cmdParams.target, cmdParams.ip_src, cmdParams.iface_out)
				# If is level3 add a var
				cmdParams.level = 2

				# Set send function
				cmdParams.send_function = sendp

			except RuntimeError:
				# Check if address is accesible without net level 2
				test = sr1(IPv6(dst=cmdParams.target)/ICMPv6EchoRequest(), iface = cmdParams.iface_out, timeout=4, verbose = 0)

				cmdParams.level = 3


				# Set send function
				cmdParams.send_function = send

				if not test:
					raise RuntimeError("Destination are not reachable")



		# Run plugin
		m_plugin_instances[P.run_mode].run(P, cmdParams)

	except IOError,e:
		IODebug.displayInfo("\nError: %s\n" % str(e))
		sys.exit(1)
	except KeyboardInterrupt:
		IODebug.displayInfo("\nstopping...\n")
		sys.exit(1)
	except EOFError:
		print "CTRL+D"
		sys.exit(1)
#	except Exception, e:
#		IODebug.displayError(str(e))
#		exit(1)