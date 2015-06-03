#!/usr/bin/env python

feedback = False
verbose = 0

def error(e, method_name=None):
    """Print exception or error. In the future will log it somewhere."""
    if feedback and verbose>0:
        print '[-] Error:', str(e), '| method:', method_name

def warning(e):
    """Print warning. In the future will log it somewhere."""
    if feedback and verbose>1:
        print '[!] Warning:', str(e)

class NoInternetAccess(Exception):
    pass