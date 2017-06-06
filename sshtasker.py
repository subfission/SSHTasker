#!/usr/bin/env python3

"""
Author: Zach Jetson
Date:   May 2017
Name:   sshtasker.py


Copyright (c) 2017, Zach Jetson All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met: * Redistributions
of source code must retain the above copyright notice, this list of conditions and
the following disclaimer. * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution. * Neither the
name of the nor the names of its contributors may be used to endorse or promote
products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL CHRISTOPHER DUFFY BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
"""

import sys, os
import argparse
from getpass import getpass


class Colors():
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


DEV_NULL = open("/dev/null", "w")

try:
    import paramiko
except ImportError as e:
    sys.exit(Colors.RED + "[!] Unable to setup paramiko dependency.  Run: pip3 install paramiko" + Colors.ENDC)



class Connect():

    def __init__(self, user, password, log=False, auto=False, key=False):
        self.user = user
        self.password = password
        self.log = log
        self.auto = auto
        self.key = key


    def ssh(self, hostname, port, command=None):

        if not command:
            command = 'echo "Connected!"'
        try:
            client = paramiko.SSHClient()
            client.load_system_host_keys()

            if self.log:
                paramiko.util.log_to_file('ssh.log')  # sets up logging

            if self.auto:
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            client.connect(hostname, port=port, username=self.user, password=self.password, look_for_keys=self.key)
            stdin, stdout, stderr = client.exec_command(command)

            errors = stderr.readlines()
            if errors:
                print(Colors.YELLOW + "[!] Error" + Colors.ENDC)
                for error in errors:
                    print(str(error))

            print("".join(stdout.readlines()))

            client.close()

        except paramiko.AuthenticationException:
            print("[!] Authentication failed, please verify your credentials.")
        except paramiko.SSHException as sshException:
            print("[!] Unable to establish SSH connection: %s" % sshException)
        except paramiko.BadHostKeyException as badHostKeyException:
            print("[!] Unable to verify server's host key: %s" % badHostKeyException)
#        except Exception as e:
#            print("[!] Operation error: %s" % e)
        except KeyboardInterrupt:
            print("[!] Connection terminated by user")

        client.close()


def main():
    parser = argparse.ArgumentParser(description="""
{}
         (   (       )
         )\ ))\ ) ( /(        )           )
        (()/(()/( )\())   )  /(   )    ( /(   (  (
         /(_))(_)|(_)\   ( )(_)| /( (  )\()) ))\ )(
        (_))(_))  _((_) (_(_()))(_)))\((_)\ /((_|())
        / __/ __|| || | |_   _((_)_((_) |(_|_))  ((_)
        \__ \__ \| __ |   | | / _` (_-< / // -_)| '_|
        |___/___/|_||_|   |_| \__,_/__/_\_ \___||_|

{}      This script will run a command against a file of
             hosts over SSH, tasking each host.
{}
                     By: Zach Jetson
           github: https://github.com/subfission
    """.format(Colors.RED, Colors.BLUE, Colors.ENDC),
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('--command', '-c', help="Accepts a file or string with a command to be run on each host.")
    parser.add_argument('--user', '-u', help="Username for all hosts.")
    parser.add_argument('--password', '-p', help="Password for all hosts.")
    parser.add_argument('--key', '-k', action='store_true', help="Use private key instead of password from ~/.ssh/.")
    parser.add_argument('--auto', '-a', action="store_true",
                        help="Enable auto-adding of remote host keys (not secure).")
    parser.add_argument('list', metavar="server_list",
                        help="List of servers to connect to, separated by newline characters.")
    parser.add_argument('--version', action='version', version='%(prog)s 0.8')
    parser.add_argument('--log', action='store_true', help="Eneble SSH logging")
    args = parser.parse_args()

    if not args.key and not args.password:
        password = getpass("Password:")
    else:
        password = args.password

    ssh_tasker = Connect(args.user, password, log=args.log, auto=args.auto, key=args.key)

    if args.command and os.path.isfile(args.command):
        with open(args.command, 'r') as shell_script:
            command=shell_script.read()
    else:
        command = args.command

    if os.path.isfile(args.list):
        with open(args.list) as f:
            for hostname in f:
                task_hostname(ssh_tasker, hostname, command)
    else:
        hostname = args.list
        task_hostname(ssh_tasker, hostname, command)

def task_hostname(ssh_tasker, hostname, command):
    host = hostname.split(':')
    try:
        port = host[1]
    except IndexError:
        port = 22

    ssh_tasker.ssh(host[0], port, command)


if __name__ == '__main__':
    main()
