#!/usr/bin/env python

"""
Jaime Blasco
jaime.blasco@alienvault.com
(c) Alienvault, Inc. 2013

"""

from ctypes import sizeof , POINTER , pointer , cast

def duplicate(src):
        """Returns a new ctypes object which is a bitwise copy of an existing one
        """
        dst = type(src)()
        pointer(dst)[0] = src
        return dst

