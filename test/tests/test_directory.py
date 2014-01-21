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

# Tests that we can download a directory mirror from our Tor's
# DirPort.

import urllib2
from hashlib import sha512

import sys
sys.path.append('../torciden/')
from torciden import get_controller

DEFAULT_DIRPORT = 9035
CONSENSUS_URL = \
    "tor/status-vote/current/consensus/14C131+27B6B5+585769+81349F+E2A2AF+E8A9C4.z"

def run_test():
    ctl = get_controller()
    dirport = ctl.get_option("DirPort")[0][1]
    if dirport == None:
        ctl.set_option(("DirPort", DEFAULT_DIRPORT))
        dirport = DEFAULT_DIRPORT
    else:
        dirport = int(dirport)  # get_option returns a string
    url = "http://localhost:%d/%s" % (dirport, CONSENSUS_URL)
    
    consensus = urllib2.urlopen(url, None, 10)
    # we time out here because we're accessing a local service and it
    # shouldn't take longer than 10 seconds if Tor is working;
    # however, in some cases a libevent issue can cause this to wait
    # indefinitely
    assert(consensus != None)
    ctl.close()
    return 0

if __name__ == '__main__':
    exit(run_test())
