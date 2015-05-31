#!/usr/bin/env python

feedback = False
verbose = False

def error(e, method_name=None):
    """Print exception or error. In the future will log it somewhere."""
    if feedback and verbose:
        print '[-] Error:', str(e), '| method:', method_name

class NoInternetAccess(Exception):
    pass