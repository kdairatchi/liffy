#!/usr/bin/python

__author__ = 'rotlogix'
__author__ = 'unicornFurnace'

import argparse
import sys
import requests
from urllib.parse import urlparse
import time
import core
import datetime
from blessings import Terminal


def main():
    # Terminal Colors
    t = Terminal()

    def banner():
        print(t.cyan("""

    .____    .__  _____  _____
    |    |   |__|/ ____\\/ ____\\__.__.
    |    |   |  \\   __\\   __<   |  |
    |    |___|  ||  |   |  |  \\___  |
    |_______ \\__||__|   |__|  / ____| v1.2
        \\/                \\/

"""))

    def progressbar():

        bar_width = 70
        sys.stdout.write(t.cyan("[{0}]  ".format(datetime.datetime.now())) + " " * bar_width)
        sys.stdout.flush()
        sys.stdout.write("\b" * (bar_width + 1))

        for w in range(bar_width):
            time.sleep(0.01)
            sys.stdout.write(".")
            sys.stdout.flush()

        sys.stdout.write("\n")

    #---------------------------------------------------------------------------------------------------

    banner()

    if not len(sys.argv) or (len(sys.argv) == 1 and sys.argv[0].endswith('liffy.py')):
        print(t.cyan("[{0}] ".format(datetime.datetime.now())) + "No URL provided, using random targets from scope...")
        print(t.cyan("[{0}] ".format(datetime.datetime.now())) + "Running random alias script...")
        
        # Execute the random alias script
        import subprocess
        import os
        
        try:
            # Get the directory of the current script
            script_dir = os.path.dirname(os.path.abspath(__file__))
            random_script = os.path.join(script_dir, 'random')
            
            # Make sure the random script is executable
            os.chmod(random_script, 0o755)
            
            # Execute the random script
            result = subprocess.run([random_script], cwd=script_dir, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(t.green("[{0}] ".format(datetime.datetime.now())) + "Random script executed successfully!")
                print(result.stdout)
            else:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Error running random script:")
                print(t.red(result.stderr))
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Falling back to manual mode...")
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Example: ./liffy.py --url http://target/files.php?file= --data")
                sys.exit(1)
        except Exception as e:
            print(t.red("[{0}] ".format(datetime.datetime.now())) + f"Error executing random script: {str(e)}")
            print(t.red("[{0}] ".format(datetime.datetime.now())) + "Example: ./liffy.py --url http://target/files.php?file= --data")
            sys.exit(1)

    #---------------------------------------------------------------------------------------------------

    """ Command Line Arguments """

    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="target url (if not provided, will use random targets from scope)")
    parser.add_argument("--data", help="data technique", action="store_true")
    parser.add_argument("--input", help="input technique", action="store_true")
    parser.add_argument("--expect", help="expect technique", action="store_true")
    parser.add_argument("--environ", help="/proc/self/environ technique", action="store_true")
    parser.add_argument("--access", help="access logs technique", action="store_true")
    parser.add_argument("--ssh", help="auth logs technique", action="store_true")
    parser.add_argument("--filter", help="filter technique", action="store_true")
    parser.add_argument("--location", help="path to target file (access log, auth log, etc.)")
    parser.add_argument("--nostager", help="execute payload directly, do not use stager", action="store_true")
    parser.add_argument("--relative", help="use path traversal sequences for attack", action="store_true")
    parser.add_argument("--cookies", help="session cookies")
    parser.add_argument("--random", help="use random targets from scope instead of specific URL", action="store_true")
    args = parser.parse_args()

    #---------------------------------------------------------------------------------------------------

    """ Assign argument values """

    url = args.url
    nostager = args.nostager
    relative = args.relative
    c = args.cookies
    use_random = args.random

    #---------------------------------------------------------------------------------------------------

    """ Handle random mode or specific URL """

    if use_random or not url:
        print(t.cyan("[{0}] ".format(datetime.datetime.now())) + "Using random targets from scope...")
        print(t.cyan("[{0}] ".format(datetime.datetime.now())) + "Running random alias script...")
        
        # Execute the random alias script
        import subprocess
        import os
        
        try:
            # Get the directory of the current script
            script_dir = os.path.dirname(os.path.abspath(__file__))
            random_script = os.path.join(script_dir, 'random')
            
            # Make sure the random script is executable
            os.chmod(random_script, 0o755)
            
            # Execute the random script
            result = subprocess.run([random_script], cwd=script_dir, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(t.green("[{0}] ".format(datetime.datetime.now())) + "Random script executed successfully!")
                print(result.stdout)
                sys.exit(0)
            else:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Error running random script:")
                print(t.red(result.stderr))
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Please provide a specific URL or check your scope directory")
                sys.exit(1)
        except Exception as e:
            print(t.red("[{0}] ".format(datetime.datetime.now())) + f"Error executing random script: {str(e)}")
            print(t.red("[{0}] ".format(datetime.datetime.now())) + "Please provide a specific URL")
            sys.exit(1)
    
    # If we have a specific URL, proceed with normal flow
    print(t.cyan("[{0}] ".format(datetime.datetime.now())) + "Checking Target: {0}".format(url))
    parsed = urlparse.urlsplit(url)
    domain = parsed.scheme + "://" + parsed.netloc
    progressbar()

    try:
        r = requests.get(domain)
        if r.status_code != 200:
            print(t.red("[{0}] ".format(datetime.datetime.now())) + "Did Not Receive Correct Response From Target URL!")
        else:
            print(t.red("[{0}] ".format(datetime.datetime.now())) + "Target URL Looks Good!")
            if args.data:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Data Technique Selected!")
                d = core.Data(url, nostager, c)
                d.execute_data()
            elif args.input:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Input Technique Selected!")
                i = core.Input(url, nostager, c)
                i.execute_input()
            elif args.expect:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Expect Technique Selected!")
                e = core.Expect(url, nostager, c)
                e.execute_expect()
            elif args.environ:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "/proc/self/environ Technique Selected!")
                i = core.Environ(url, nostager, relative, c)
                i.execute_environ()
            elif args.access:
                if not args.location:
                    print(t.red("[{0}] ".format(datetime.datetime.now())) + "Log Location Not Provided! Using Default")
                    l = '/var/log/apache2/access.log'
                else:
                    l = args.location
                a = core.Logs(url, l, nostager, relative, c)
                a.execute_logs()
            elif args.ssh:
                if not args.location:
                    print(t.red("[{0}] ".format(datetime.datetime.now())) + "Log Location Not Provided! Using Default")
                    l = '/var/log/auth.log'
                else:
                    l = args.location
                a = core.SSHLogs(url, l, relative, c)
                a.execute_ssh()
            elif args.filter:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Filter Technique Selected!")
                f = core.Filter(url, c)
                f.execute_filter()
            else:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Technique Not Selected!")
                sys.exit(0)
    except requests.HTTPError as e:
        print(t.red("[{0}] HTTP Error: " + str(e)))

    #---------------------------------------------------------------------------------------------------


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        main_t = Terminal()
        print(main_t.red(" [{0}] ".format(datetime.datetime.now())) + "Keyboard Interrupt!")
        sys.exit(0)

