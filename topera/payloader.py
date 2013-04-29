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

__author__ = ["Daniel Garcia a.k.a cr0hn (@ggdaniel) - cr0hn<@>cr0hn.com",
              "Rafael Sanchez (@r_a_ff_a_e_ll_o) - rafa<@>iniqua.com"]
__copyright__ = "Copyright 2012 - Topera project"
__credits__ = ["Daniel Garcia a.k.a cr0hn (@gganiel) - cr0hn<@>cr0hn.com",
               "Rafael Sanchez (@r_a_ff_a_e_ll_o) - rafa<@>iniqua.com"]
__maintainer__ = "Daniel Garcia a.k.a cr0hn"
__status__ = "Testing"


__all__ = ["PAYLOAD_TYPES", "make_payload"]

from scapy.all import IPv6ExtHdrDestOpt, IPv6ExtHdrFragment
from random import randint

PAYLOAD_TYPES = {
    "RANDOM"     : 1,
    "DESTOPT"    : IPv6ExtHdrDestOpt,
    "FRAGOPT"    : IPv6ExtHdrFragment
    }

#----------------------------------------------------------------------
def make_payload(num_headers=10, ext_type="DESTOPT"):
    """
    Create a payload by specified option.

    :param num_headers: number of extensions headers.
    :type num_headers: int

    :parame ext_type: type of extension headers. Options are available in "PAYLOAD_TYPES" var.
    :type ext_type: str

    :return: a payload or None, if num_headers is 0.
    """

    if num_headers < 0:
        raise ValueError("Number of headers must be greater than 0")

    if ext_type not in PAYLOAD_TYPES:
        raise ValueError("Invalid ext type")


    m_return = None

    if num_headers > 0:

        m_return = PAYLOAD_TYPES[ext_type]()

        if ext_type == "RANDOM":
            m_keys = PAYLOAD_TYPES.keys()

            for i in xrange(num_headers - 1):
                m_return /= PAYLOAD_TYPES[m_keys[randint(1, len(m_keys))]]()
        else:
            for i in xrange(num_headers - 1):
                m_return /= PAYLOAD_TYPES[ext_type]()

    return m_return
