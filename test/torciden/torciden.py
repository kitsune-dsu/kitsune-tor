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

from pytorctl import TorCtl, PathSupport
import os, socket, sys, optparse, Queue, time
from os import popen, system
try:
    import pynotify
    from pynotify import Notification
    notify = True
except:
    notify = False
# A list of versions that are in our streak
VERSIONS = ["0.2.1.18",
            "0.2.1.19",
            "0.2.1.20",
            "0.2.1.21",
            "0.2.1.22",
            "0.2.1.23",
            "0.2.1.24",
            "0.2.1.25",
            "0.2.1.26",
            "0.2.1.27",
            "0.2.1.28",
            "0.2.1.29",
            "0.2.1.30"]

TESTS_DIRECTORY = "../tests/"

EXIT_CODE = -1
DONT_CLOSE = True

# disable logging
from pytorctl import TorUtil
TorUtil.logfile = "/dev/null"

def ensureController(f):
    """
    A decorator for functions where the first argument is a Tor
    controller. Asserts that the controller is connected to a live Tor
    instance. If not, invokes the shutdown method as a failure.
    """
    def ensured_f(*args):
        ctl = args[0]
        if not ctl.is_live():
            shutdown(ctl, 2)
        else:
            return f(*args)
    return ensured_f
    
@ensureController
def wait_on_circuits(ctl):
    class CircuitWatcher(TorCtl.PostEventListener):
        """Watches circuit activity and calls callback when there's an
        update"""
        def __init__(self, callback, data=None):
            TorCtl.PostEventListener.__init__(self)
            self.callback = callback
            self.data = data

        def circ_status_event(self, event):
            if self.data == None:
                (self.callback)(event)
            else:
                (self.callback)(event, self.data)

    def circuit_trigger(event, q):
        q.put(event)
        
    if are_circuits_built(ctl):
        return                  # circuits are already all built
    q = Queue.Queue()
    ctl.set_events(["CIRC"])
    ctl.add_event_listener(CircuitWatcher(circuit_trigger, q))
    printed = False
    while True:
        try:
            # sleep until circuit_trigger puts something in the queue
            b = q.get(True, 2)
            if are_circuits_built(ctl):
                break
            else:
                if printed:
                    sys.stdout.write("")
                    print ".",
                    sys.stdout.flush()
                else:
                    print "Waiting for circuits to be built",
                    printed = True            
        except:
            if not ctl.is_live():   # make sure we're still live
                shutdown(ctl, 2)    # if not, shut down
            else:
                pass

    if printed:
        print
    ctl.set_events([""])
    return

def start_tors():
    tor_root = get_repo_root() + "/examples/tor"
    config_files = [r for r in os.listdir(tor_root) 
                    if r.endswith(".torrc")]
    [dir_cf] = [cf for cf in config_files if "directory" in cf]
    del(config_files[config_files.index(dir_cf)])
    config_files.append(config_files[0])
    config_files[0] = dir_cf
    for cf in config_files:
        print "=========================================="
        print "Starting tor with config file" + cf
        print "=========================================="
        start_tor(VERSIONS[9], False, tor_root + "/" + cf)        

def run_onehop_tests():
    """
    Entry point for single-hop tests mode. For this mode, torciden
    will connect to a client and run arbitrary tests through the
    client. These tests will handle initiating an update on the relay
    node if such functionality is desired.
    """
    def load_tests():
        # load tests
        testdir_name = "../onehop-tests"
        sys.path.append(testdir_name)
        return [__import__(e.rstrip(".py")) for e in 
                os.listdir(testdir_name) if e.endswith(".py")]
    def config_circuits(ctl):
        selection_mgr = \
            PathSupport.SelectionManager(pathlen=1,
                                         order_exits=False,
                                         percent_fast=0,
                                         percent_skip=0,
                                         min_bw=0,
                                         use_all_exits=False,
                                         uniform=False,
                                         use_exit=("UMDDSUTestNode"),
                                         use_guards=False)
        ctl.set_events([TorCtl.EVENT_TYPE.CIRC,TorCtl.EVENT_TYPE.STREAM,
                        TorCtl.EVENT_TYPE.ADDRMAP,TorCtl.EVENT_TYPE.NS,
                        TorCtl.EVENT_TYPE.NEWDESC], True)
        c.set_option("FastFirstHopPK","0") # necessary for one-hop circuits
        
        print "waiting for an up-to-date consensus"
        found_exit = False
        while not found_exit:
            found_exit = reduce(
                lambda acc, ns: acc or ns.nickname == "UMDDSUTestNode",
                ctl.get_consensus(), False)
            time.sleep(1)
        print "Got a consensus with UMDDSUTestNode in it"
        return PathSupport.StreamHandler(ctl, selection_mgr, 10, 
                                         TorCtl.Router)
        
    print "Initiating single hop tests"
    exit_code = -1
    try:
        start_tors()
        c = get_controller(False, "/examples/tor/client-data/control_auth_cookie")
        handler = config_circuits(c)
        tests = load_tests()
        for test in tests:
            print "Running test %s" % str(test)
            wait_on_circuits(c)
            test.run_test(c)
    except Exception as e:
        print "shutting down with errors"
        os.system("killall driver") # fixme
        raise
    else:
        os.system("killall driver") # fixme
        shutdown(c, 0)

    
        
        

def get_repo_root():
    # this is sort of opaque, but on my setup, the fourth line in the
    # bzr info output contains the "repository branch" info, which is
    # a path on the end of the line.
    return popen("bzr info").read().split("\n")[3].split(" ")[-1]
    
def update_path(version):
    return get_repo_root() + "/examples/tor/tor-" + version + "/src/or/tor-update.so"

def get_tests(directory):
    """Returns a list of paths to executable files. These files will
    exit with 0 on success and non-0 on failure."""
    directory_listing = os.listdir(directory)
    output_list = []
    for entry in directory_listing:
        if (entry.startswith("test_") and 
            os.access(directory + entry, os.X_OK) and
            not entry.endswith("~")):
            output_list.append(entry)
    return output_list

@ensureController
def are_circuits_built(controller):
    csl = controller.get_info("circuit-status")["circuit-status"].split("\n")
    statuses = map(lambda s: s.split(" ")[1], csl[0:-1])
    return reduce(lambda acc,s: acc and s == "BUILT", statuses, True) \
        and len(statuses) > 0


@ensureController
def run_tests(ctl):
    def run(testname):
        """Runs a test and return 0 on success."""
        if testname.endswith(".py"):
            if not "../tests/" in sys.path:
                sys.path.append("../tests/")
            testname = os.path.basename(testname).split(".")[0]
            test = __import__(testname)
            return test.run_test()
        else:
            return system(testname)
    
    # Run all tests retrieved by get_tests. 
    print "Starting test run"
    for test in get_tests(TESTS_DIRECTORY):
        if not are_circuits_built(ctl):
            wait_on_circuits(ctl)
        print "Running %s" % test
        if run(TESTS_DIRECTORY + test) != 0:
            print "Test %s failed!" % test
            return False
    return True

def shutdown(controller, excode=0):
    if controller.is_live():
        controller.send_signal("HALT")

    if excode == 0:
        success = "successfully ☺ "
    else:
        success = "with errors ☹ "
    notice = "Tests completed %s! Torciden shutting down." % success

    if notify:
        pynotify.init("Torciden")
        Notification("Torciden", notice).show()
    print notice
    os._exit(excode)

def get_controller(stayalive=False, cookiePath=None):
    def tor_error_shutdown(ex=None):
        if ex==None:
            os._exit(0)
        else:
            print "Shutting down after Tor error"
            os._exit(1)
    if stayalive:
        stayalive = 0
    else:
        stayalive = 1
    if cookiePath == None:
        cookiePath = "/examples/tor/data/control_auth_cookie"
    # Read in the password from the authentication cookie
    cookie = (open(get_repo_root() + cookiePath,
                   "r")).read()
    # connect to the control port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("localhost", 9100))
    ctl = PathSupport.Connection(s)
    ctl.launch_thread(daemon=stayalive)
    ctl.authenticate(cookie)
    ctl.set_close_handler(tor_error_shutdown)
    return ctl

def start_tor(version=VERSIONS[0], valgrind=False, tor_config_path=None):
    def get_tor(version):
        return get_repo_root() + "/examples/tor/tor-%s/src/or/tor.so" % version
    # Start the first version of Tor in our streak running via Kitsune.
    valcmd = ""
    if valgrind:
        valcmd = ("valgrind --log-file=valgrind-%p.log -v " +
                  # "--tool=exp-ptrcheck --enable-sg-checks=no " + 
                  "--tool=memcheck --leak-check=full --free-fill=0x77 " +
                  "--read-var-info=yes ")
    driver = get_repo_root() + "/bin/driver"
    bench_filename = "/tmp/kitsune/tor-bench.%d" % os.getpid()
    tor = get_tor(version)
    if tor_config_path == None:
        tor_config_path = get_repo_root() + "/examples/tor/torrc"
    # there's a better way to do this but python is horrible anyway
    run_str = valcmd + driver + " -b " + bench_filename + \
        " " + tor + " -f " + tor_config_path + " RunAsDaemon 1"
    print "Running %s " % run_str
    return system(run_str)

@ensureController
def update_tor(ctl, version=None, tor_path=None):
    if version != None:
        if tor_path == None:
            tor_path = update_path(version)
        ctl.set_option("DSUTarget", tor_path)
    print "Updating Tor to version %s." % version 
    ctl.send_signal("UPDATE")

def simple_test(should_start=True, start=0, target=0, 
                valgrind=False):
    print 'Doing a simple test.'
    if should_start:
        start_tor(VERSIONS[start], valgrind)
    if target < start:
        target = start
    c = get_controller()
    wait_on_circuits(c)
    update_tor(c, VERSIONS[target])
    wait_on_circuits(c)
    shutdown(c, 0)

def oneshot():
    print "Connecting to running Tor"
    c = get_controller()
    version = c.get_info("version")["version"]
    print "Connected to version %s" % version
    new_version_index = VERSIONS.index(version) + 1
    update_tor(c, VERSIONS[new_version_index])
    print "Detatching."
    c.close()
    return

# @ensureController
# def run_loop_tests(ctl):
#     while True:
#         if not run_tests(ctl):
#             shutdown(ctl, 1)
#         update_tor(ctl, start_version)

def run_streak(should_start_tor=True, start_version=0, count=-1,
               valgrind=False, loop=False):
    if should_start_tor:
        if start_tor(VERSIONS[start_version], valgrind) != 0 and not valgrind:
            print "Error: Couldn't start Tor."
            exit(1)
    ctl = get_controller()
    print "Started tor version %s" % ctl.get_info("version")["version"]
    # normal test run
    count = count if count == -1 else count + start_version + 1
    for version in VERSIONS[(start_version):count]:
        if not run_tests(ctl):
            shutdown(ctl, 1)
        update_tor(ctl, version)
    shutdown(ctl, 
             0 if run_tests(ctl) else 1)
    
if __name__ == '__main__':
    parser = optparse.OptionParser(version="%prog %ver")
    parser.add_option(          # no-start
        "-n", "--no-start", action="store_false", dest="should_start_tor", 
        default=True,
        help="Connect to a running instance of Tor instead of starting our own.")
    parser.add_option(          # simple-test
        "-m", "--simple-test", action="store_true", dest="simple_test", 
        default=False,
        help="Just wait for circuits to build, update Tor, and quit.")
    parser.add_option(          # start
        "-s", "--start-version", action="store", type=int, dest="start",
        default=0,
        help="The version (v0-v12) to start the streak on.")
    parser.add_option(          # count
        "-c", "--count", action="store", type=int, dest="count",
        default=-1,
        help="How many versions to streak through.")
    parser.add_option(          # epoll
        "-e", "--epoll", action="store_true", dest="epoll", default=True,
        help="Disable epoll and use poll.")
    parser.add_option(          # valgrind
        "-v", "--valgrind", action="store_true", dest="valgrind", 
        default=False,
        help="Run under the valgrind memory debugger.")
    parser.add_option(          # onehop
        "-1", "--onehop", action="store_true", dest="onehop",
        default=False,
        help="Run single-hop circuit performance tests.")
    parser.add_option(          # singleshot
        "-S", "--singleshot", action="store_true", dest="oneshot",
        default=False,
        help="Update the running Tor version to the next version.")
    parser.add_option(          # loop
        "-l", "--loop", action="store_true", dest="loop", default=False,
        help="Loop forever in a simple or sophisticated test. Implies " +
        "target=start version.")
    
    (options, args) = parser.parse_args()

    if not options.epoll:
        os.environ["EVENT_NOEPOLL"] = "1"
        
    if options.oneshot:
        oneshot()
        exit(0)

    if options.onehop:
        run_onehop_tests()
        exit(0)

    if options.valgrind:
        print "Using Valgrind"
    
    if options.simple_test:
        simple_test(options.should_start_tor, 
                    options.start,
                    options.start + options.count,
                    options.valgrind)

    run_streak(options.should_start_tor, options.start,
               options.count, options.valgrind, options.loop)
    
