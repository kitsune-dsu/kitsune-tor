#!/usr/bin/python
# -*- Mode: Python; coding: utf-8; indent-tabs-mode: nil;  -*-
# Copyright © 2011 Edward Smith
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from pytorctl import TorCtl

# Read in the password from the authentication cookie
cookie = (open("/home/tedks/Projects/plum/workdir/examples/tor/data/control_auth_cookie",
               "r")).read()

# create a controller object from a connection to host localhost, port
# 9100, with the password we got from the cookie
ctl = TorCtl.connect("localhost", 9100, cookie)

# get some information about this running Tor daemon
print "Version: %s" % ctl.get_info("version")["version"] # returns 1-elem hash
print "Address: %s" % ctl.get_info("address")["address"] # and another one
print "Circuit statuses:"
print "\t%s" % ctl.get_info("circuit-status")["circuit-status"].replace("\n", "\n\t")
print "All known events: %s" % ctl.get_info("events/names")["events/names"]
# print "All known GETINFO options: %s" % ctl.get_info("info/names")["info/names"]
# full list in doc/spec/control-spec.txt, and at runtime by
# uncommenting that line (warning: lots of text)




