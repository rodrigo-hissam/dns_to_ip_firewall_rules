#!/usr/bin/env python
"""Dynamic dns to ip address firewall rule creator.

Resolve dynamic dns names into ips and automatically create/destroy
firewall rules. Script requires to run as super user in order to be able to
create the firewall rules.


Requirements:
    The following packages should be installed and enabled before attempting to
    run the script

    Fedora based:
        bind-utils, firewalld

    Ubuntu based:
        dnsutils , ufw

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
import sys

from subprocess import Popen, PIPE
from platform import linux_distribution
from datetime import datetime


# Functions
def main():
    """Main entry point for the script."""
    # Variables
    #
    # Config your domains their ports and the protocol needed per port. If you
    # want both udp and tcp protocols for the port enter 'both' for protocol
    # type.
    # Example: domain with its ports and protocol:
    #   {
    #    'name': 'example.com',
    #    'ports': [
    #       (53, 'udp'),
    #       (22, 'both'),
    #       (80, 'tcp')
    #       ]
    #   },
    # Example: Allow any port and protocol for domain
    #     {'name': 'theverge.com'},
    dynamic_domains = [
        {'name': 'theverge.com'},
        {'name': 'arstechnica.com'},
        {
         'name': 'google.com',
         'ports': [
            (53, 'udp'),
            (22, 'both'),
            (80, 'tcp')
            ]
        },
        {
         'name': 'example.com',
         'ports': [
            (53, 'udp'),
            (22, 'both'),
            (80, 'tcp')
            ]
        },
        {
         'name': 'mangolassi.it',
         'ports': [
            (53, 'both'),
            (443, 'tcp')
         ]
        }
    ]
    # Getting linux distro
    distro = linux_distribution()[0]
    # Script start
    for domain in dynamic_domains:
        current_ip = get_current_ip(domain['name'])
        if os.path.isfile(domain['name']):
            old_ip = get_logged_ip(domain['name'])
            if not current_ip == old_ip:
                if 'ports' in domain.keys():
                    delete_firewall_rule(distro, old_ip, domain['ports'])
                    create_firewall_rule(distro, current_ip, domain['ports'])
                else:
                    delete_firewall_rule(distro, old_ip)
                    create_firewall_rule(distro, current_ip)
                log_script_messages(domain['name'], current_ip, old_ip)
                create_hostname_ip_log(domain['name'], current_ip)
        else:
            if 'ports' in domain.keys():
                create_firewall_rule(distro, current_ip, domain['ports'])
            else:
                create_firewall_rule(distro, current_ip)
            create_hostname_ip_log(domain['name'], current_ip)
            log_script_messages(domain['name'], current_ip)
    if 'Cent' in distro or 'Fedora' in distro or 'Red' in distro:
        reload_fw = "firewall-cmd --reload"
        Popen(reload_fw.split(' '), stdout=PIPE, stderr=PIPE)


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
    with open(domain, "w") as file:
        file.write("{0}".format(ip))


def get_logged_ip(domain):
    """Get logged ip for requested domain."""
    with open(domain, "r") as file:
        logged_ip = file.read()
    return logged_ip


def log_script_messages(domain, current_ip, old_ip=None):
    """Log firewall rule creation and deletion."""
    date_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if old_ip:
        with open("dns-to-ip-firewall.log", "a") as file:
            file.write("{} - {} adding {} - removing {} from firewall\n"
                       .format(date_time, domain, current_ip, old_ip))

    else:
        with open("dns-to-ip-firewall.log", "a") as file:
            file.write("{} - New domain {}/{} added to the firewall\n".format(
                date_time, domain, current_ip))


def create_firewall_rule(distro, ip, ports=None):
    """Create firewall rule based on newest ip of dynamic domain."""
    if 'Ubuntu' in distro:
        if ports:
            for port in ports:
                if port[1] == 'both':
                    Popen(
                     ["ufw", "allow", "from", ip, "to", "any", "port",
                      str(port[0])], stdout=PIPE, stderr=PIPE)
                else:
                    Popen(
                      ["ufw", "allow", "from", ip, "to", "any", "port",
                       str(port[0]), "proto", port[1]],
                      stdout=PIPE, stderr=PIPE)
                # ufw freaks out when adding rules too fast
                time.sleep(.5)
        else:
            Popen(["ufw", "allow", "from", ip], stdout=PIPE, stderr=PIPE)
    elif 'Cent' in distro or 'Fedora' in distro or 'Red' in distro:
        if ports:
            for port in ports:
                if port[1] == 'both':
                    rule_tcp = (
                     "firewall-cmd --permanent --add-rich-rule='rule "
                     "family=ipv4 source address={}/32 port port={} "
                     "protocol=tcp accept'".format(ip, port[0], port[1]))

                    rule_udp = (
                      "firewall-cmd --permanent --add-rich-rule='rule "
                      "family=ipv4 source address={}/32 port port={} "
                      "protocol=udp accept'".format(ip, port[0], port[1]))

                    Popen(rule_tcp.split(' '), stdout=PIPE, stderr=PIPE)
                    Popen(rule_udp.split(' '), stdout=PIPE, stderr=PIPE)
                else:
                    rule = (
                     "firewall-cmd --permanent --add-rich-rule='rule "
                     "family=ipv4 source address={}/32 port port={} "
                     "protocol={} accept'".format(ip, port[0]))
                    Popen(rule.split(' '), stdout=PIPE, stderr=PIPE)
        else:
            rule = (
             "firewall-cmd --permanent --add-rich-rule='rule family=ipv4 "
             "source address={}/32 '{}".format(ip))
            Popen(rule.split(' '), stdout=PIPE, stderr=PIPE)


def delete_firewall_rule(distro, ip, ports=None):
    """Delete firewall rule in order to add new ip from dynamic domain."""
    if 'Ubuntu' in distro:
        if ports:
            for port in ports:
                if port[1] == 'both':
                    Popen(
                     ["ufw", "delete", "allow", "from", ip, "to", "any",
                      "port", str(port[0])], stdout=PIPE, stderr=PIPE)
                else:
                    Popen(
                      ["ufw", "delete", "allow", "from", ip, "to", "any",
                       "port", str(port[0]), "proto", port[1]], stdout=PIPE,
                      stderr=PIPE)
                # ufw freaks out when deleting rules too fast
                time.sleep(.5)
        else:
            Popen(["ufw", "delete", "allow", "from", ip], stdout=PIPE,
                  stderr=PIPE)
    elif 'Cent' in distro or 'Fed' in distro or 'Red' in distro:
        if ports:
            for port in ports:
                if port[1] == 'both':
                    rule_tcp = (
                     "firewall-cmd --permanent --remove-rich-rule='rule "
                     "family=ipv4 source address={}/32 port port={} "
                     "protocol=tcp accept'".format(ip, port[0], port[1]))

                    rule_udp = (
                      "firewall-cmd --permanent --remove-rich-rule='rule "
                      "family=ipv4 source address={}/32 port port={} "
                      "protocol=udp accept'".format(ip, port[0], port[1]))

                    Popen(rule_tcp.split(' '), stdout=PIPE, stderr=PIPE)
                    Popen(rule_udp.split(' '), stdout=PIPE, stderr=PIPE)
                else:
                    rule = (
                     "firewall-cmd --permanent --add-rich-rule='rule "
                     "family=ipv4 source address={}/32 port port={} "
                     "protocol={} accept'".format(ip, port[0]))
                    Popen(rule.split(' '), stdout=PIPE, stderr=PIPE)
        else:
            rule = (
             "firewall-cmd --permanent --add-rich-rule='rule family=ipv4 "
             "source address={}/32 '{}".format(ip))
            Popen(rule.split(' '), stdout=PIPE, stderr=PIPE)


if __name__ == '__main__':
    sys.exit(main())
