import netmiko
import re
import subprocess
import requests

import json
import sys

from time import sleep
from _fmc import FMC
from datetime import datetime
from types import SimpleNamespace


def ping_host(ip, result=True):
    reply = subprocess.run(f"ping -n 2 -w 750 {ip}", capture_output=True, text=True).stdout
    if result:
        print(reply)
    if re.search(r'Received = [1-9]', reply):
        if 'unreachable' not in reply:
            return True
    return False


class NoPingToFTD(Exception):
    pass


class NoPassword(Exception):
    pass


class FTD:

    def __init__(
            self, ip, hostname: str, fmc: FMC,
            login: str = 'admin', password: str = None, on_fmc=None,
            init_connect: bool = False
    ):
        if on_fmc is None:
            on_fmc = {}
        if not password:
            raise NoPassword
        if not ping_host(ip, result=False):
            raise NoPingToFTD
        self.fmc = fmc
        self.ip = ip
        self.on_fmc = on_fmc
        self.hostname = hostname
        self.hostname_config = ''
        if self.on_fmc.get('ha_id', False):
            self.ha: bool = True
        else:
            self.ha: bool = False
        self.subs: int = 0
        self.ha_ips: bool = False
        self.out = ''
        self.route = ''
        self.s2s = ''
        self.bgp = ''
        self.clock = False
        self._device = {
            'device_type': 'cisco_ftd',
            'host': ip,
            'username': login,
            'password': password
        }
        if init_connect:
            self.ssh = netmiko.ConnectHandler(
                **self._device,
                conn_timeout=20,
                banner_timeout=25
            )
            self.get_data()

    def get_data(self):
        network = self.ssh.send_command('show network', expect_string='>')
        self.hostname_config = network.strip().splitlines()[1].strip().split()[-1]
        failover = self.ssh.send_command('show failover').strip().splitlines()
        if 'On' in failover[0]:
            self.ha = True
            subs = [x for x in failover if "  Interface" in x and 'diagnostic' not in x]
            if len([x for x in subs if '0.0.0.0' in x]) == 0:
                self.ha_ips = True
            self.subs = (len(subs) - 2) / 2
        time = self.ssh.send_command('show time').strip().splitlines()[-1]
        if '2021' in time or '2022' in time:
            self.clock = True

    def _reconnect_ssh_decorator(func):
        """
            decorator for reconnection to sessions with timeout
        """

        def wrapper(self, *args, **kwargs):
            if not self.hostname_config:
                self.ssh = netmiko.ConnectHandler(**self._device)
                self.get_data()
                return func(self, *args, **kwargs)

            try:
                return func(self, *args, **kwargs)
            # TODO name of exception?
            except netmiko.NetmikoTimeoutException:
                self.ssh.disconnect()
                self.ssh = netmiko.ConnectHandler(**self._device)
                # TODO clear CLI via CTRL+u?
                return func(self, *args, **kwargs)
            except IOError:
                self.ssh.write_channel('\x15')
                self.ssh.read_channel()

        return wrapper

    @_reconnect_ssh_decorator
    def check_managers(self, bad_manager) -> str:
        # I HATE FTD CLI - spamming ctrl-u to clear everything
        self.ssh.write_channel('\x15')
        self.ssh.write_channel('\x15')
        self.ssh.write_channel('\x15')
        self.ssh.read_channel()
        managers_cli = self.ssh.send_command(
            'show managers',
            delay_factor=10, max_loops=1000
        )
        if bad_manager in managers_cli and self.fmc.ip not in managers_cli:
            return 'full_fix'
        elif bad_manager in managers_cli:
            return 'bad_fix'
        elif self.fmc.ip not in managers_cli:
            return 'good_fix'
        else:
            return ''

    @_reconnect_ssh_decorator
    def check_fix_manager(self, bad_manager):
        check = self.check_managers(bad_manager)
        cli_fix = False
        if check == 'bad_fix':
            if self.ha:
                obj_id = self.on_fmc['ha_id']
                uri = FMC.urls.ha
            else:
                obj_id = self.on_fmc['id']
                uri = FMC.urls.device
            check = self.fmc.delete_from_fmc(uri, obj_id)
            sleep(30)
            cli_fix = True
        if check == 'full_fix' or cli_fix:
            _ = self.ssh.send_command(
                'configure manager delete',
                delay_factor=10, max_loops=1000
            )
        if check in ['good_fix', 'full_fix']:
            if self.ha:
                _ = self.ssh.send_command(
                    'configure high-availability disable',
                    strip_prompt=False, expect_string="'NO':",
                    delay_factor=10, max_loops=1000
                )
                _ = self.ssh.send_command_timing(
                    'yes',
                    delay_factor=10, max_loops=1000
                )
            _ = self.ssh.send_command(
                f'configure manager add {self.fmc.ip} asdASD123',
                delay_factor=100, max_loops=1000
            )
            r = self.add_to_fmc()
            if r.ok:
                self.fmc.need_refresh = True
        return check

    def add_to_fmc(self) -> requests.models.Response:
        j = {
            "name": self.hostname,
            "hostName": self.ip,
            "regKey": "asdASD123",
            "type": "Device",
            "license_caps": [
                "BASE"
            ],
            "accessPolicy": {
                "id": "7C310EB7-E0EE-0ed3-0000-107374186574",
                "type": "AccessPolicy"
            }
        }
        r = self.fmc.post_to_fmc(FMC.urls.device, j)
        if r.ok:
            self.fmc.need_refresh = True
        return r


"""
FTD
ping_site_and_ftd
ssh_connect
check_manager
    fix_manager
fix_clock
reboot

delete_from_fmc
add_to_fmc

check_ha/subs on device
check_bgp_state

create_port_channel
create_subs
create_ha
create_out
create_static_routes

fix_standby_ips
"""
