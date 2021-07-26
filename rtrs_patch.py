#!/usr/bin/env python
# coding: utf-8

import netmiko
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed

from site_check_mtreat import ping_host
from ue_config import *


PATCH_INDEX = 'patch1'


LBS = pd.read_excel(PATH/'Data.xlsx', sheet_name='Loopbacks')
P_STATUS = pd.read_excel(
    PATH/'rtr_patches.xlsx',
    index_col='Hostname',
    na_filter=False,
    dtype='bool'
)


def patch_rtr(fname):
    rtr = fname.stem
    ip = LBS[LBS.Hostname == rtr]['Loopback0'].to_string(index=False, header=False)
    if ping_host(ip, False):
        host = {
            'device_type': 'cisco_ios',
            'host': ip,
            'username': LOGIN,
            'password': PASSWORD,
            'secret': PASSWORD
        }
        print(f'Connecting to {rtr}')
        with netmiko.ConnectHandler(**host) as ssh, \
                fname.open('rt') as f:
            ssh.enable()
            print(f'Pushing config to {rtr}')
            config_set = f.readlines()
            if "-AU-" not in rtr and "ES3_PS02" not in rtr:
                config_set.append('no ptp clock ordinary domain 0')
            else:
                config_set.append('ptp clock ordinary domain 0')
            ssh.send_config_set(config_set, cmd_verify=False)
            ssh.save_config()
        return rtr, True
    else:
        print(f'No ping from {rtr} - {ip}')
        return rtr, False


def mpatch_rtr(patches):
    global P_STATUS
    threads = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        for fname in patches:
            if not P_STATUS.loc[fname.stem, f'{PATCH_INDEX}_set']:
                threads.append(executor.submit(patch_rtr, fname))

        for task in as_completed(threads):
            rtr, result = task.result()
            P_STATUS.loc[rtr, f'{PATCH_INDEX}_set'] = result
    with pd.ExcelWriter(PATH / 'rtr_patches.xlsx', engine='openpyxl') as writer:
        P_STATUS.to_excel(writer)
        writer.save()


def main():
    # TODO check if there are patches in folder and set in DF. Add check in mthread
    # PATCHES.apply(lambda row: check_patches(), axis=1)

    patches = Path(PATH_PATCH).glob(f'*.{PATCH_INDEX}')
    mpatch_rtr(patches)
    with pd.ExcelWriter(PATH / 'rtr_patches.xlsx', engine='openpyxl') as writer:
        P_STATUS.to_excel(writer)
        writer.save()


if __name__ == '__main__':
    main()
