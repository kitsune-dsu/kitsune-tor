#!/usr/bin/env perl
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

# Download a file "in the clear" and over Tor, and check that it
# matches a sha512 checksum.

use warnings;
use strict;

use LWP::Simple;
use LWP::UserAgent;
use LWP::Protocol::socks;

use Digest::SHA qw(sha512);

use Carp::Assert;

my $test_url = "http://www.cs.umd.edu/~tedks/kitsune_test.jpg";
my $proxy_url = "socks://localhost:9055";

# Download the file "in the clear"
my $ref_img  = get($test_url);

# Download the file over Tor
my $ua = LWP::UserAgent->new;
$ua->agent("Kitsune test");
$ua->proxy([qw(http https)] => $proxy_url);
my $res = $ua->get($test_url);

if (!$res->is_success) {
    print "Couldn't download file!\n";
    exit(1);
}
my $tor_img = $res->decoded_content;

# Generate SHA512 hashes of all content
my ($ref_digest, $tor_digest) = 
    (sha512($ref_img), sha512($tor_img));
assert($ref_digest eq $tor_digest);
exit(0);
