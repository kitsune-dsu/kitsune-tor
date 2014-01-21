#!/usr/bin/env python
# -*- Mode: Python; coding: utf-8; indent-tabs-mode: nil;  -*-
# Copyright © 2011 Edward Smith
#
# All rights reserved. 
#
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, 
# this list of conditions and the following disclaimer. 
#
# 2. Redistributions in binary form must reproduce the above copyright notice, 
# this list of conditions and the following disclaimer in the documentation 
# and/or other materials provided with the distribution. 
#
# 3. The names of the contributors may not be used to endorse or promote 
# products derived from this software without specific prior written 
# permission. 
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
# POSSIBILITY OF SUCH DAMAGE. 

# Checks that for each intstance of a /* DSU static */ comment, there
# is a corresponding MIGRATE_GLOBAL in that file. Prints non-compliant /**DSU data */
# lines and counts of matched lines.

import sys, os

def get_variable(string):
    """Parse a line of C that is either a declaration or an invocation
    of a MIGRATE macro and return a string representing the variable.
    This won't work for all variables and will return None if it
    fails."""
    if "MIGRATE" in string:
        half = string.split("MIGRATE")[1] # right of the migrate
        half = half.split("(")[1]       # right of the first open paren
        half = half.split(")")[0]         # left of the first close paren
        return half
    elif "/* DSU static */" in string:
        if string.startswith("HT_HEAD"):
            name = string.split(" ")[0]
            name = name.split("(")[1]
            name = name.replace(",", "")
        else:
            name = string.split(" ")[1]
        
        if "[" in name:
            name = name.split("[")[0]

        if "=" in name:
            name = name.split("=")[0]
        name = name.replace("*", "")
        name = name.replace(";", "")
        return name
    else:
        return None

def check_migrates(filename):
    fh = open(filename, "r")
    lines = fh.readlines()
    fh.close()
    migrates = {}
    statics = {}
    for line in lines:
        if "MIGRATE" in line:
            migrates[get_variable(line)] = line
        if "/* DSU static */" in line:
            statics[get_variable(line)] = line
    matched = 0
    unmatched = []
    for key in statics.keys():
        if key in migrates:
            matched += 1
        else:
            unmatched.append(key)
    if len(unmatched) > 0:
        print "For file %s:" % filename
        print "Unmatched variables:"
        for um in unmatched:
            print "** %s **" % um
        print

if __name__ == "__main__":
    check_migrates(sys.argv[1])
