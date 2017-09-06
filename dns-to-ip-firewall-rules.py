#!/usr/bin/python
"""Dynamic dns to ip address firewall rule creator.

Resolve dynamic dns names into ips and automatically create/destroy
firewall rules. Write access in the directory where the script will reside is
necesarry in order to log the resolved domains ip address.

Example:
    To manually run the script

        $ python dns_to_ip_firewall-rules.py

Todo:
    * OS detection to properly configure firewall rules in different OS
    * Creation and destruction of firewall rules.
    * Add cron setup instructions to automate the running of the script.

Author:
    Rodrigo Hissam
"""

import re
import os.path

from subprocess import Popen, PIPE


# Functions
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

# Variables
# Example domain names, use your own previously configured dynamic dns names
dynamic_domains = ["mangolassi.it", "google.com", "theverge.com"]

for domain in dynamic_domains:
    current_ip = get_current_ip(domain)
    if os.path.isfile(domain):
        old_ip = get_logged_ip(domain)
        if not current_ip == old_ip:
            print("Adding {} to firewall - TODO".format(current_ip))
            create_hostname_ip_log(domain, current_ip)
        else:
            print("Same ip address nothing to do")
    else:
        create_hostname_ip_log(domain, current_ip)
        print("Adding to firewall - TODO")

    print("{0} - {1} \n".format(domain, current_ip))
