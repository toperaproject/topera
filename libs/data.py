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

#
# Class to manage program parameters
class cParams:
    def __init__(self):
        self.Target = ""
        """Target IP"""
        self.port_raw = "0-1024"
        """Ports read from command line"""
        self.port_range = None
        """Ports separated as array format"""
        self.mac_dst = None
        """Destination MAC address"""
        self.verbose = False
        """Verbose mode"""
        self.more_verbose = False
        """More verbose mode"""        
        self.iface_out = "eth0"
        """Output interface"""
        self.sleep = 100
        """Sleep time between two packets"""
        self.ip_src =""
        """Source IPv6 address"""
        self.mac_src = ""
        """Source MAC address"""
        self.file_results = None
        """Output results file"""


        # Internal use for output messages
        self.Out_normal = None
        self.Out_error = None
        
        
        
        
        
        
    