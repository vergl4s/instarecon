#!/usr/bin/env python

feedback = False
verbose = False

def raise_error(e, method_name=None):
    if feedback and verbose:
        print '# Error:', str(e), '| method:', method_name