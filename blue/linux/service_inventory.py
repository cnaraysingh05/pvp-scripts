#!/usr/bin/env python3
"""Read-only service, container, firewall-manager and dependency inventory."""
from common import collect, main_guard, report, require_linux


def main():
    require_linux()
    commands = {
        'services': ['systemctl', 'list-units', '--type=service', '--all', '--no-pager'],
        'listeners': ['ss', '-tulpn'],
        'processes': ['ps', '-eo', 'pid,ppid,user,comm'],
        'containers': ['docker', 'ps', '-a', '--no-trunc'],
        'podman': ['podman', 'ps', '-a', '--no-trunc'],
        'firewalld': ['firewall-cmd', '--list-all-zones'],
        'ufw': ['ufw', 'status', 'verbose'],
        'nftables': ['nft', 'list', 'ruleset'],
        'forwarding': ['sysctl', 'net.ipv4.ip_forward', 'net.ipv6.conf.all.forwarding'],
        'database_services': ['systemctl', 'status', 'mariadb', 'mysql', 'postgresql', '--no-pager'],
        'pihole': ['pihole', 'status'],
        'disk': ['df', '-h'],
        'failed_units': ['systemctl', '--failed', '--no-pager'],
    }
    report({key: collect(argv) for key, argv in commands.items()})


if __name__ == '__main__':
    main_guard(main)
