#!/usr/bin/env python
"""Dynamic dns to ip address firewall rule creator.

Resolve dynamic dns names into ips and automatically create/destroy
firewall rules. Write access in the directory where the script will reside is
necesarry in order to log the resolved domains ip address.


Requirements:
    The following packages should be installed before attempting to run the
    script

    Fedora based:
        'bind-utils'

    Debian based:
        'dnsutils'

Example:
    To manually run the script

        $ python dns_to_ip_firewall-rules.py

Todo:
    * Fedora based firewall rule creation.
    * Debian firewall rule creation
    * Add cron setup instructions to automate the running of the script.

Author:
    Rodrigo Hissam
"""

import re
import os.path
import time
import datetime
import sys

from subprocess import Popen, PIPE
from platform import linux_distribution


# Functions
def main():
    """Main entry point for the script."""

    # Variables
    # Example domain names, use your set your configured dynamic dns names here
    dynamic_domains = ["mangolassi.it", "google.com", "wordpress.com"]
    distro = linux_distribution()[0]

    # Script start
    for domain in dynamic_domains:
        current_ip = get_current_ip(domain)
        if os.path.isfile(domain):
            old_ip = get_logged_ip(domain)
            if not current_ip == old_ip:
                delete_firewall_rule(distro, old_ip)
                create_firewall_rule(distro, current_ip)
                print("\nAdding {} ip {} - removing {}".format
                      (domain, current_ip, old_ip))
                create_hostname_ip_log(domain, current_ip)
            else:
                print("\nSame ip address nothing to do")
        else:
            create_hostname_ip_log(domain, current_ip)
            create_firewall_rule(distro, current_ip)
            print("\nAdding to firewall")

        print("{0} - {1}".format(domain, current_ip))
    print("\n")


def get_current_ip(domain):
    """Return the ip after resolving 'host hostame' in the shell."""
    response = Popen(["host", domain], stdout=PIPE)
    response = response.communicate()[0].decode("utf-8")
    response = re.search('^.+?(?=\\n)', response)
    response = response.group(0)
    ip = re.search('\d+.\d+.\d+.\d+$', response)
    return ip.group(0)


def create_hostname_ip_log(domain, ip):
    """Create a file with the ip of the resolved domain."""
    file = open(domain, "w")
    file.write("{0}".format(ip))
    file.close()


def get_logged_ip(domain):
    """Get logged ip for requested domain."""
    file = open(domain, 'r')
    logged_ip = file.read()
    file.close()
    return logged_ip


def create_firewall_rule(distro, ip):
    """Create firewall rule based on newest ip of dynamic domain."""
    if 'Ubuntu' in distro:
        Popen(["ufw", "allow", "from", ip, "to", "any", "port", "53"],
              stdout=PIPE, stderr=PIPE)
        # ufw freaks out when adding rules too fast
        time.sleep(1)
    elif 'Cent' in distro or 'Fedora' in distro or 'Red' in distro:
        print("")


def delete_firewall_rule(distro, ip):
    """Delete firewall rule in order to add new ip from dynamic domain."""
    if 'Ubuntu' in distro:
        Popen(["ufw", "delete", "allow", "from", ip, "to", "any", "port",
              "53"], stdout=PIPE, stderr=PIPE)
        # ufw freaks out when deleting rules too fast
        time.sleep(1)
    elif 'Cent' in distro or 'Fed' in distro or 'Red' in distro:
        print("")


if __name__ == '__main__':
    sys.exit(main())

