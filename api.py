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


from libs.data import *
from attacks.sneakyTCPScan import *
from libs.IPv6_utils import *

def Topera_Main(cmdParams):
    
    # Do a sneaky Scan
    sneakyTCPScan(cmdParams)
    
    