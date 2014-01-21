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

# Sets up an HTTP hidden service and downloads a file over it.

import SimpleHTTPServer
import SocketServer
SocketServer.TCPServer.allow_reuse = True
import os
import hashlib
import pycurl
import StringIO
import threading

import sys
sys.path.append('../torciden/')
from torciden import get_controller, get_repo_root
ctl = get_controller(1)         # get a controller that will die when
                                # we die

TESTFILE = "kitsune_test.jpg"

def init_hs():
    """Set up a hidden service -- configure Tor, and start an HTTP
    server that we return a handle to."""
    options = ctl.get_option("HiddenServiceOptions")
    if (options[0][1] == None or options[1][1] == None):
        ctl.set_options((("HiddenServiceDir", get_repo_root() + '/examples/tor/data/hs'), 
                         ("HiddenServicePort", str(8888))))
    port = int(ctl.get_option("HiddenServiceOptions")[1][1])
    serve_path = get_repo_root() + '/examples/tor/test/tests/'
    os.chdir(serve_path)
    httpd = SocketServer.TCPServer(("", port), 
                                   SimpleHTTPServer.SimpleHTTPRequestHandler)
    return (httpd, port)

def fetch_file_from_hs(filename, hs, port):
    localIP = "127.0.0.99"
    ctl.map_address([(localIP,hs)])
    url = "http://%s:%d/%s" % (localIP, port, filename)
    c = pycurl.Curl()
    c.setopt(pycurl.URL, url)
    c.setopt(pycurl.PROXY, "127.0.0.1")
    c.setopt(pycurl.PROXYPORT,
             int(ctl.get_option("SocksPort")[0][1]))
    c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5)
    output = StringIO.StringIO()
    c.setopt(pycurl.WRITEFUNCTION, output.write)
    # jack up the timeouts to allow Tor to set up more circuits to
    # connect to the hidden services
    ctl.set_option("SocksTimeout", "5 minutes")
    c.setopt(pycurl.CONNECTTIMEOUT, 60 * 5)
    print "Attempting to download %s" % filename
    c.perform()
    return output.getvalue()

def fetch_file_clear(filename, host, port):
    url = "http://%s:%d/%s" % (host, port, filename)
    c = pycurl.Curl()
    c.setopt(pycurl.URL, url)
    output = StringIO.StringIO()
    c.setopt(pycurl.WRITEFUNCTION, output.write)
    c.perform()
    return output.getvalue()
    
class HSTestThread(threading.Thread):
    def __init__(self, httpd):
        threading.Thread.__init__(self)
        self.httpd = httpd
    
    def run(self):
        self.httpd.serve_forever(0.1)

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.socket.close()
        del self.httpd

def run_test():
    # set up
    (httpd, port) = init_hs()
    thread = HSTestThread(httpd)
    thread.daemon = True
    thread.start()

    # get the hidden service hostname
    f = open(get_repo_root() + '/examples/tor/data/hs/hostname', "r")
    hs_hostname = f.read().rstrip()
    f.close()

    # download the file without Tor
    print "%s: Downloading test file without Tor" % __file__
    file_hash = hashlib.sha512(fetch_file_clear(TESTFILE, "localhost", port)).hexdigest()
    
    # download the image over Tor
    print "%s: Downloading test file over Tor" % __file__
    tor_hash = hashlib.sha512(fetch_file_from_hs(TESTFILE, hs_hostname, port)).hexdigest()

    # test
    assert(tor_hash == file_hash)
    # shut down
    thread.shutdown()
    thread.join()
    return 0
if __name__ == '__main__':
    exit(run_test())
