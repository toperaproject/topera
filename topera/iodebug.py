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

from sys import stdout,stderr

__all__ = ["IODebug"]


class IODebug:
    _normal_output = stdout
    _error_output = stderr
    _debug = False
    #: This var controle if class was already configured
    _isSet = False
    _fileOut = None
    #
    # isConfigured
    @staticmethod
    def isConfigured():
        '''
        This method inform if class was already configured or not.

        @return: if alread configured return true. False otherwise.
        @rtype: bool
        '''
        return IODebug._isSet
    # END isConfigured
    #


    #
    # setOutputs
    @staticmethod
    def Configure(Out_normal, Out_error, verbose, path_output):
        '''
        Configure debugging

        @param normal_output: file handle where write normal output for debugging. Screen by defaul.
        @type normal_output: file handle

        @param error_output: file handle where write error info for debugging. Screen by defaul.
        @type error_output: file handle

        @param debug: flag that indicates if debug is enabled or not. Not by default
        @type debug: bool

        @return: None
        '''
        IODebug._normal_output = Out_normal
        IODebug._error_output = Out_error
        IODebug._debug = verbose

        IODebug._isSet = True
        if path_output is not None:
            IODebug._fileOut = open(path_output, 'w')
        else:
            IODebug._fileOut = None
    # END setOutputs
    #


    #
    # displayInfo
    @staticmethod
    def displayInfo(text, indentation = 0, carry = True):
        '''
        This function display informational info

        @param text: Text to display
        @type text: str

        @param indentation: Number of spaces between start line and text.
        @type indentation: int

        @return: None
        '''
        if text is not None and IODebug.isConfigured():
            m_text = "%s%s%s" % (" " * indentation, text, '\n' if carry else '')
            IODebug._normal_output.write(m_text)
            IODebug._normal_output.flush()
            if IODebug._fileOut != None:
                IODebug._fileOut.write(m_text)
                IODebug._fileOut.flush()
    # END displayInfo
    #

    #
    # displayInfo
    @staticmethod
    def displayError(text, indentation = 0, carry = True):
        '''
        This function display informational info

        @param text: Text to display
        @type text: str

        @param indentation: Number of spaces between start line and text.
        @type indentation: int

        @return: None
        '''
        if text is not None and IODebug.isConfigured():
            m_text = "%s[!] %s%s" % (" " * indentation, text, '\n\n' if carry else '')
            IODebug._error_output.write(m_text)
            IODebug._error_output.flush()
            if IODebug._fileOut != None:
                IODebug._fileOut.write(m_text)
                IODebug._fileOut.flush()
    # END displayInfo
    #

    #
    # displayInfo
    @staticmethod
    def displayDebugInfo(text, indentation = 0, carry = True):
        '''
        This function display informational info, only if debug is enabled.

        @param text: Text to display
        @type text: str

        @return: None
        '''
        if text is not None and IODebug._debug > 0 and IODebug.isConfigured():
            m_text = "%s%s%s" % (" " * indentation, text, '\n' if carry else '')
            IODebug._normal_output.write(m_text)
            IODebug._normal_output.flush()
            if IODebug._fileOut != None:
                IODebug._fileOut.write(m_text)
                IODebug._fileOut.flush()
    # END displayInfo
    #


    #
    # displayInfo
    @staticmethod
    def displayDebugError(text, indentation = 0, carry = True):
        '''
        This function display informational info, only if debug is enabled.

        @param text: Text to display
        @type text: str

        @return: None
        '''
        if text is not None and IODebug._debug > 0 and IODebug.isConfigured():
            m_text = "%s[i] %s%s" % (" " * indentation, text, '\n' if carry else '')
            IODebug._normal_output.write(m_text)
            IODebug._normal_output.flush()
            if IODebug._fileOut != None:
                IODebug._fileOut.write(m_text)
                IODebug._fileOut.flush()
    # END displayInfo
    #


    #
    # displayMoreDebugInfo
    @staticmethod
    def displayMoreDebugInfo(text, indentation = 0, carry = True):
        '''
        This function display informational info, only if debug is enabled.

        @param text: Text to display
        @type text: str

        @return: None
        '''
        if text is not None and IODebug._debug > 2 and IODebug.isConfigured():
            m_text = "%s%s%s" % (" " * indentation, text, '\n' if carry else '')
            IODebug._normal_output.write(m_text)
            IODebug._normal_output.flush()
            if IODebug._fileOut != None:
                IODebug._fileOut.write(m_text)
                IODebug._fileOut.flush()
    # END displayMoreDebugInfo
    #


    #
    # displayMoreDebugError
    @staticmethod
    def displayMoreDebugError(text, indentation = 0, carry = True):
        '''
        This function display informational info, only if debug is enabled.

        @param text: Text to display
        @type text: str

        @return: None
        '''
        if text is not None and IODebug._debug > 2 and IODebug.isConfigured():
            m_text = "%s%s%s" % (" " * indentation, text, '\n' if carry else '')
            IODebug._normal_output.write(m_text)
            IODebug._normal_output.flush()
            if IODebug._fileOut != None:
                IODebug._fileOut.write(m_text)
                IODebug._fileOut.flush()
    # END displayMoreDebugError
    #
