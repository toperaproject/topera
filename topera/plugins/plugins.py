#!/usr/bin/env python
# -*- coding: utf-8 -*-

#-----------------------------------------------------------------------
#
# This code are borrowed from GoLismero project
#
#-----------------------------------------------------------------------

#-----------------------------------------------------------------------
# Base classes for plugins
#-----------------------------------------------------------------------

__license__="""
GoLismero 2.0 - The web knife - Copyright (C) 2011-2013

Authors:
  Daniel Garcia Garcia a.k.a cr0hn | cr0hn<@>cr0hn.com
  Mario Vilas | mvilas@gmail.com

Golismero project site: http://code.google.com/p/golismero/
Golismero project mail: golismero.project@gmail.com

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
"""


__all__ = ["ToperaPlugin"]

class ToperaPlugin (object):
    """
    Base class for all plugins.
    """

    PLUGIN_TYPE_GENERAL = 0

    PLUGIN_TYPE_FIRST = PLUGIN_TYPE_GENERAL
    PLUGIN_TYPE_LAST  = PLUGIN_TYPE_GENERAL

    #----------------------------------------------------------------------
    def run(self, plugin_Params, global_params):
        """Get the help message for this plugin."""
        raise NotImplementedError("All plugins must implement this method!")

    #----------------------------------------------------------------------
    def display_help(self):
        """Display help for this plugin."""
        raise NotImplementedError("All plugins must implement this method!")

    #----------------------------------------------------------------------
    def get_parser(self, main_parser):
        """Add a subparser info for the main parser"""
        raise NotImplementedError("All plugins must implement this method!")
