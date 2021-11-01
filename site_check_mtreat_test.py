#!/usr/bin/env python
# coding: utf-8

import netmiko
import pandas as pd
import re
import itertools
import json
import os
import subprocess
import click
# from rich import print
from time import sleep
from pprint import pprint
from sys import exit
from ipaddress import IPv4Network as net4
from datetime import datetime
from openpyxl import load_workbook
from pysnmp.hlapi import *
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from config_file import LOGIN, PASSWORD

CURRENT_DATE = datetime.now().date().isoformat()
PATH = Path('C:/check_data/')
PATH_JSON = PATH / 'json/'
PATH_TMPLT = PATH / 'templates/'
PATH_INV = PATH / 'inventory/'


@click.group()
def cli():
    pass


@cli.command()
@click.option('-f', '--check_fw', is_flag=True, default=False, help='Check and fix FWs - use if power is enabled')
@click.option('-m', '--mtu_check', is_flag=True, default=False, help='Set to skip MTU check (use if DG fails)')
@click.option('-e1', '--check_e1', default='direct', help='How to check e1 -accepted values are: direct, all, no')
@click.option('-s', '--set_loops', is_flag=True, default=False, help='Set loops. Default - remove loops(no flag)')
@click.option('-l', '--last_site', is_flag=True, default=False, help='Use last cached site')
@click.argument('site_id', required=False)
def main(check_fw, check_e1, mtu_check, last_site, set_loops, site_id):
    """Main function to check new sites, or re-check after FW enabling"""
    site = click_site(last_site, site_id)
    for rtr in site['rtrs']:
        if ping_host(rtr['Loopback0']):
            print(f"Ping from TERM to {rtr['Hostname']} {rtr['Loopback0']} ok")
            if 'RTR-01' in rtr['Hostname'] and not site.get('dg_ok', False) and not mtu_check:
                check_from_dc(site)
        else:
            print(f"No ping on {rtr['Hostname']}  -  {rtr['Loopback0']}")
            if 'RTR-01' in rtr['Hostname']:
                print("Will try to ping from DC1 & DC2")
                check_from_dc(site)
                form_letter(site, site['mtu1'])
            exit(0)
    infra_generate_data(site)
    gather_site_data(site, check_fw)
    infra_find_interface(site, check_fw)
    check_site_rtrs(site)
    if check_e1 == 'all':
        print('Setting loops and checking MUX interfaces, will take couple minutes')
        mux_status = {ip: get_mux_status(ip)[1] for ip in site['infra']['MUX_MGMT']}
        for ip in mux_status.keys():
            if not mux_status[ip]:
                site['infra']['MUX_MGMT'][ip]['ping'] = ping_host(ip)

        for rtr in site['rtrs']:
            print(f"working with {rtr['Hostname']}")
            mux_check_full(rtr, site['infra']['MUX_MGMT'], mux_status)
    elif check_e1 == 'direct':
        print('Checking mux wiring')
        mux_check_direct_e1(site['infra']['MUX_MGMT'], site['rtrs'])
    if set_loops:
        for rtr in site['rtrs']:
            manage_e1_loops(rtr, set_loops)
    print_report(site, check_fw)
    site['check_fw'] = check_fw
    with open(PATH_JSON / f"{site['id']}_{CURRENT_DATE}.txt", 'w') as f:
        json.dump(site, f, indent=2)
    if check_fw:
        set_fw(site['infra']['FW_MGMT'])


@cli.command()
@click.argument('site_id', default=False)
def mtu_check(site_id):
    """Force MTU check"""
    site = click_site(False, site_id)
    site['mtu1'] = 0
    site['mtu2'] = 0
    check_from_dc(site)
    form_letter(site, site['mtu1'])
    with open(PATH_JSON / f"{site['id']}_{CURRENT_DATE}.txt", 'w') as f:
        json.dump(site, f, indent=2)


@cli.command()
@click.argument('site_id', default=False)
def print_dg(site_id):
    """Print DG and Eaton data"""
    site = click_site(False, site_id)
    print(site['name'])
    print(f'шафа R2 {site["rtrs"][0]["Hostname"]}  <---> {site["isp_eq"]}')
    infra_df = pd.read_excel(PATH / 'IP_for_INFRA_2021_v3_iponly.xlsx',
                             sheet_name='TECH'
                             ).dropna(how='all')
    infra = infra_df[infra_df['Site ID'] == site['id']][['DEV_NAME (project)', 'DEV_TYPE', 'DEV_IP', 'GW_IP', 'MASK']]
    infra.columns = ['dev_name', 'dev', 'ip', 'gw', 'mask']

    for x in infra.to_dict('records'):
        if "eaton" in x['dev'].lower():
            print('Eaton IP:')
            print(f"{x['ip']}\n{x['mask']}\n{x['gw']}")


@cli.command()
@click.option('-e1', '--check_e1', default='direct', help='How to check e1 -accepted values are: direct, all')
@click.option('-l', '--last_site', is_flag=True, default=False, help='Use last cached site')
@click.argument('site_id', default=False)
def mux_check(check_e1, last_site, site_id):
    # TODO check type
    """Check only E1 connection on MUXes"""
    site = click_site(last_site, site_id)
    if 'infra' not in site.keys():
        print('No cache file for site, run MAIN first')
    else:
        if check_e1 == 'all':
            mux_status = {ip: get_mux_status(ip)[1] for ip in site['infra']['MUX_MGMT']}
            for ip in mux_status.keys():
                if not mux_status[ip]:
                    site['infra']['MUX_MGMT'][ip]['ping'] = ping_host(ip)

            for rtr in site['rtrs']:
                print(f"working with {rtr['Hostname']}")
                mux_check_full(rtr, site['infra']['MUX_MGMT'], mux_status)
        else:
            print(f'Fast check started')
            mux_check_direct_e1(site['infra']['MUX_MGMT'], site['rtrs'])
        print_infra(site['infra'], check_fw=False)


@cli.command()
@click.option('-s', '--set_loops', is_flag=True, default=False, help='Set loops. Default - remove loops(no flag)')
@click.option('-l', '--last_site', is_flag=True, default=False, help='Use last cached site')
@click.argument('site_id', default=False)
def manage_loop(set_loops, last_site, site_id):
    """Set/remove loops on all E1 on site"""
    site = click_site(last_site, site_id)
    if 'infra' in site.keys():
        for rtr in site['rtrs']:
            print(rtr['Hostname'])
            manage_e1_loops(rtr, set_loops)
    else:
        print('No cache file for site, run MAIN first')


@cli.command()
@click.option('-l', '--last_site', is_flag=True, default=False, help='Use last cached site')
@click.argument('site_id', required=False)
def print_cache(last_site, site_id):
    """Print last check result, if available"""
    site = click_site(last_site, site_id)
    if 'infra' in site.keys():
        check_fw = site.get('check_fw', True)
        print_report(site, check_fw)
    else:
        print('No cache file for site, run MAIN first')


@cli.command()
@click.option('-s', '--shut', is_flag=True, default=False, help='Set loops. Default - unshut(no flag)')
@click.option('-l', '--last_site', is_flag=True, default=False, help='Use last cached site')
@click.argument('site_id', default=False)
def shut_cem(shut, last_site, site_id):
    """Shut / no shut CEM interfaces"""
    site = click_site(last_site, site_id)
    if 'infra' in site.keys():
        for rtr in site['rtrs']:
            print(rtr['Hostname'])
            manage_cem_ifs(rtr, shut)
    else:
        print('No cache file for site, run MAIN first')


@cli.command()
@click.option('-l', '--last_site', is_flag=True, default=False, help='Use last cached site')
@click.argument('site_id', default=False)
def show_e1(last_site, site_id):
    """Print current status of E1 interfaces on site"""
    site = click_site(last_site, site_id)
    if 'infra' in site.keys():
        for rtr in site['rtrs']:
            print(rtr['Hostname'])
            site_rtr = {
                'device_type': 'cisco_ios',
                'host': rtr['Loopback0'],
                'username': LOGIN,
                'password': PASSWORD,
                'secret': PASSWORD
            }
            with netmiko.ConnectHandler(**site_rtr) as ssh:
                pprint(ssh.send_command('show controller e1 | i E1').strip().splitlines())
    else:
        print('No cache file for site, run MAIN first')


@cli.command()
@click.option('-all', '--all_mux', is_flag=True, default=False)
@click.option('-l', '--last_site', is_flag=True, default=False, help='Use last cached site')
@click.argument('ip', default='10.253.161.132')
def mux_status(ip, all_mux, last_site):
    """print single MUX status (00/01/11)"""
    if not all_mux:
        ip, status = get_mux_status(ip)
        print(f'MUX {ip} current status {status}')
    else:
        site = click_site(last_site)
        if 'infra' in site.keys():
            for ip in site['infra']['MUX_MGMT'].keys():
                ip, status = get_mux_status(ip)
                print(f'MUX {ip} current status {status}')


@cli.command()
@click.option('-l', '--last_site', is_flag=True, default=False, help='Use last cached site')
@click.option('-2', '--two_rtrs', is_flag=True, default=False, help='only RTR-01 & 02')
@click.option('-fw', '--firewalls', is_flag=True, default=False, help='Only to FWs')
@click.option('-all', '--all_devices', is_flag=True, default=False, help='FWs + RTRs')
@click.option('-dc', '--data_center', is_flag=True, default=False, help='Connect to DC')
@click.argument('site_id', required=False)
def ssh_all(last_site, firewalls, all_devices, data_center, site_id, two_rtrs):
    """SSH to devices from site via Puttyy"""
    if data_center:
        for i in range(1, 5):
            subprocess.Popen(f"{PATH / 'putty.exe'} -ssh -pw C!sco123 root@10.252.0.{i} 22",
                             stdin=None, stdout=None, stderr=None, close_fds=True)
    else:
        site = click_site(last_site, site_id)
        if firewalls or all_devices:
            for ip in site['infra']['FW_MGMT'].keys():
                subprocess.Popen(f"{PATH / 'putty.exe'} -ssh -pw C!sco123 admin@{ip} 22",
                                 stdin=None, stdout=None, stderr=None, close_fds=True)

        if 'rtrs' in site.keys() and (all_devices or not firewalls):
            print(f'Connecting to {site["name"]}')
            if two_rtrs:
                for rtr in site['rtrs'][:2]:
                    subprocess.Popen(f"{PATH / 'putty.exe'} -ssh -pw C!sco123 root@{rtr['Loopback0']} 22",
                                     stdin=None, stdout=None, stderr=None, close_fds=True)
            else:
                for rtr in site['rtrs']:
                    subprocess.Popen(f"{PATH / 'putty.exe'} -ssh -pw C!sco123 root@{rtr['Loopback0']} 22",
                                     stdin=None, stdout=None, stderr=None, close_fds=True)
                if 'sws' in site.keys():
                    for sw in site['sws']:
                        subprocess.Popen(f"{PATH / 'putty.exe'} -ssh -pw C!sco123 root@{sw['ip']} 22",
                                         stdin=None, stdout=None, stderr=None, close_fds=True)


def get_mux_status(ip):
    port_snmp = 161
    OID = '.1.3.6.1.4.1.36837.2.1.1.84.1'
    iterator = getCmd(SnmpEngine(),
                      CommunityData('public', mpModel=0),
                      UdpTransportTarget((ip, port_snmp)),
                      ContextData(),
                      ObjectType(ObjectIdentity(OID)))
    try:
        for response in iterator:
            errorIndication, errorStatus, errorIndex, varBinds = response
            return ip, f'{int(varBinds[0][-1].prettyPrint()[1], base=16):04b}'[2:]
    except:
        return ip, False


def click_site(last_site, site_id=False):
    if last_site:
        last = sorted(Path(PATH_JSON).iterdir(), key=os.path.getmtime)[-1]
        with last.open('r') as f:
            site = json.load(f)
    else:
        site = choose_sites(site_id)
        # fix old caches with ID instead of name
        tmp = site['name']
        site = read_cache(site)
        site['name'] = tmp
    return site


def ping_host(ip, result=True):
    reply = subprocess.run(f"ping -n 2 -w 750 {ip}", capture_output=True, text=True).stdout
    if result:
        print(reply)
    if re.search('Received = [1-9]', reply):
        if 'unreachable' not in reply:
            return True
    return False


def choose_sites(site_id=False):
    wb = load_workbook(PATH / 'ukr-en-2-6-sp-equipments.xlsx')
    while True:
        if site_id:
            choose = site_id
        else:
            choose = input('Enter site name> ').strip()
        if "ES" in choose or "REC" in choose or "EXT" in choose or "PS" in choose:
            column = 'N'
        else:
            column = 'C'
        st = [x[0].value for x in wb.active[f'{column}2':f'{column}200'] if x[0].value != None]
        # replace letters
        choose = re.sub('[ІИЄЇЕЬіиєїеь]', '.', choose)
        # drop single letters
        choose = [x for x in choose.split() if len(x) > 1]
        pattern = '|'.join(['.*'.join(x) for x in itertools.permutations(choose, len(choose))])
        site_matches = [x for x in st if re.search(pattern, x, re.IGNORECASE)]
        if not site_matches:
            print(f'no matches with "{choose}", re-enter site name')
            if site_id:
                with (PATH/'fail.log').open('a') as f:
                    f.write(site_id + '\r\n')
                break
        elif len(site_matches) == 1 or site_id:
            site = site_matches[0]
            print(f'single match with site {site}')
            break
        else:
            print('Multiple match. Enter number of site we are checking')
            for i, site in enumerate(site_matches):
                print(f'{i + 1!s:>2s}. {site}')
            nm = click.prompt('number>', type=int)
            site = site_matches[nm - 1]
            break
    # fill json
    row_id = st.index(site) + 2
    site_data = {
        'name': wb.active[f'C{row_id}'].value,
        'id': wb.active[f'N{row_id}'].value,
        'vlan1': wb.active[f'K{row_id}'].value,
        'vlan2': wb.active[f'L{row_id}'].value,
        'isp_eq': wb.active[f'R{row_id}'].value,
        'dg_ok': False,
        'mtu1': False,
        'mtu2': False
    }
    if '/' in site_data['id']:
        print(f"Site ID consists of two {site_data['id']}")
        site_data['id'] = input('Please, enter correct > ').strip().upper()
    lbs = pd.read_excel(PATH / 'Data.xlsx', sheet_name='Loopbacks')
    site_data['rtrs'] = lbs[lbs['Site ID'] == site_data['id']][['Hostname', 'Loopback0', 'Loopback1']].to_dict(
        'records')
    for rtr in site_data['rtrs']:
        rtr['config'] = False
        rtr['loop_set'] = False
    # gather SW data
    switch_int = pd.read_excel(
        PATH / 'Data.xlsx',
        sheet_name='Switches',
        header=1,
        index_col=0
    ).fillna(False)
    switch_int = switch_int.filter(like=site_data['id'] + '-SW', axis=0)
    if not switch_int.empty:
        switch_int = switch_int.drop(columns=switch_int.columns[(switch_int == False).all()])
        site_data['sws'] = [{'Hostname': x[0], 'ifs': x[1].to_dict()} for x in switch_int.iterrows()]
    return site_data


def generate_config(rtr):
    commands = []
    if 'sw_int' in rtr.keys():
        for i in set(rtr['sw_int']):
            commands += [
                f"interface {i}",
                "service instance 999 ethernet",
                "encapsulation untagged",
                "l2protocol peer cdp",
                "bridge-domain 1"
            ]
    loop1 = rtr['Loopback1']
    commands += [
        "router bgp 65000",
        "address-family ipv4",
        f"network {loop1} mask 255.255.255.255 route-map LOOPBACK_0_COMMUNITY"
    ]
    commands += [
        # TODO remove after ptp fix
        "no ptp clock ordinary domain 0",
        "no ip access-list extended EPNM_ACL",
        "ip access-list extended EPNM_ACL",
        " 10 permit ip 10.253.152.0 0.0.0.255 any",
        " 20 permit ip 10.253.159.0 0.0.0.255 any",
        "no snmp-server host 10.99.99.246 vrf Mgmt-intf version 2c UkR3N3rg0-EPNM",
        "snmp-server community UkR3N3rg0-EPNM RW EPNM_ACL",
        "snmp-server community UkR3N3rgRO-EPNM RO EPNM_ACL",
        "snmp-server trap link ietf",
        "snmp-server trap link switchover",
        "snmp-server trap retry 4",
        "snmp-server trap-source Loopback0",
        "snmp-server enable traps snmp authentication linkdown linkup coldstart warmstart",
        "snmp-server enable traps ds1",
        "snmp-server enable traps ds3",
        "snmp-server enable traps call-home message-send-fail server-fail",
        "snmp-server enable traps tty",
        "snmp-server enable traps ospf state-change",
        "snmp-server enable traps ospf errors",
        "snmp-server enable traps ospf retransmit",
        "snmp-server enable traps ospf lsa",
        "snmp-server enable traps ospf cisco-specific state-change nssa-trans-change",
        "snmp-server enable traps ospf cisco-specific state-change shamlink interface",
        "snmp-server enable traps ospf cisco-specific state-change shamlink neighbor",
        "snmp-server enable traps ospf cisco-specific errors",
        "snmp-server enable traps ospf cisco-specific retransmit",
        "snmp-server enable traps ospf cisco-specific lsa",
        "snmp-server enable traps license",
        "snmp-server enable traps smart-license",
        "snmp-server enable traps pki",
        "snmp-server enable traps atm pvc",
        "snmp-server enable traps atm subif",
        "snmp-server enable traps atm snmp-walk-serial",
        "snmp-server enable traps bfd",
        "snmp-server enable traps bgp",
        "snmp-server enable traps bgp cbgp2",
        "snmp-server enable traps config-copy",
        "snmp-server enable traps config",
        "snmp-server enable traps config-ctid",
        "snmp-server enable traps dhcp",
        "snmp-server enable traps otn",
        "snmp-server enable traps event-manager",
        "snmp-server enable traps hsrp",
        "snmp-server enable traps ipmulticast",
        "snmp-server enable traps ospfv3 state-change",
        "snmp-server enable traps ospfv3 errors",
        "snmp-server enable traps ospfv3 rate-limit 10 20",
        "snmp-server enable traps pim neighbor-change rp-mapping-change",
        "snmp-server enable traps ipsla",
        "snmp-server enable traps bridge newroot topologychange",
        "snmp-server enable traps adslline",
        "snmp-server enable traps ether-oam",
        "snmp-server enable traps ethernet cfm cc mep-up mep-down cross-connect loop config",
        "snmp-server enable traps ethernet cfm crosscheck mep-missing mep-unknown service-up",
        "snmp-server enable traps memory bufferpeak",
        "snmp-server enable traps entity-state",
        "snmp-server enable traps entity",
        "snmp-server enable traps cpu threshold",
        "snmp-server enable traps rep",
        "snmp-server enable traps vtp",
        "snmp-server enable traps cef resource-failure peer-state-change peer-fib-state-change inconsistency",
        "snmp-server enable traps lisp",
        "snmp-server enable traps entity-sensor",
        "snmp-server enable traps resource-policy",
        "snmp-server enable traps flash insertion removal lowspace",
        "snmp-server enable traps netsync",
        "snmp-server enable traps rsvp",
        "snmp-server enable traps ptp",
        "snmp-server enable traps lost-ptp-slave",
        "snmp-server enable traps breach-ptp-offset-threshold",
        "snmp-server enable traps cnpd",
        "snmp-server enable traps aaa_server",
        "snmp-server enable traps ethernet evc status create delete",
        "snmp-server enable traps mvpn",
        "snmp-server enable traps nhrp",
        "snmp-server enable traps mpls rfc ldp",
        "snmp-server enable traps mpls ldp",
        "snmp-server enable traps mpls rfc traffic-eng",
        "snmp-server enable traps mpls traffic-eng",
        "snmp-server enable traps mpls fast-reroute protected",
        "snmp-server enable traps pw vc",
        "snmp-server enable traps l2tun session",
        "snmp-server enable traps l2tun pseudowire status",
        "snmp-server enable traps alarms informational",
        "snmp-server enable traps bulkstat collection transfer",
        "snmp-server enable traps mac-notification",
        "snmp-server enable traps rf",
        "snmp-server enable traps ethernet cfm alarm",
        "snmp-server enable traps transceiver all",
        "snmp-server enable traps mpls vpn",
        "snmp-server enable traps mpls rfc vpn",
        "snmp-server enable traps mpls p2mp-traffic-eng",
        "snmp-server host 10.253.152.10 version 2c UkR3N3rg0-EPNM ",
        "snmp-server host 10.253.159.10 version 2c UkR3N3rg0-EPNM",
        "logging buffered 40000000"
    ]
    return commands


def infra_generate_data(site):
    vrf_ip = pd.read_excel(
        PATH / 'Data.xlsx',
        sheet_name='VRF_IPs',
        index_col=1
    ).fillna(False)
    site_net = vrf_ip.loc[site['rtrs'][0]['Hostname']]['Network']

    infra_df = pd.read_excel(PATH / 'IP_for_INFRA_2021_v3_iponly.xlsx',
                             sheet_name='TECH'
                             ).dropna(how='all')
    infra = infra_df[infra_df['Site ID'] == site['id']][['DEV_NAME (project)', 'DEV_TYPE', 'DEV_IP']]
    infra.columns = ['dev_name', 'dev', 'ip']
    mux_df = pd.read_excel(PATH / 'Muxes_IP_and_management.xlsx'
                           ).dropna(how='all')[['IP', 'uplink', 'uplink_port', 'MUX']]
    mux_df.columns = ['ip', 'uplink', 'port', 'dev']
    mux = mux_df[mux_df.dev.str.contains(f'-{site["id"]}-MUX')].to_dict('records')
    mux_port_df = pd.read_excel(
        PATH / 'Legacy_Ports_architecture_01_05_20.xlsx',
        sheet_name='E1 Ports'
    ).dropna(how='all')
    mux_port_df = mux_port_df[~(mux_port_df['MUX A'] == 'no')]
    infra = {
        'FW': {
            site_net[:-4] + '4': {
                'dev': 'FW_OUT_ACTIVE',
                'ping': False,
                'mac': '',
                'uplink': '',
                'uif': ''
            },
            site_net[:-4] + '5': {
                'dev': 'FW_OUT_STANDBY',
                'ping': False,
                'mac': '',
                'uplink': '',
                'uif': ''
            }
        },
        'FW_MGMT': {
            site_net[:-4] + '12': {
                'dev': 'FW_M_PRI',
                'ping': False,
                'mac': '',
                'uplink': '',
                'uif': ''
            },
            site_net[:-4] + '13': {
                'dev': 'FW_M_SEC',
                'ping': False,
                'mac': '',
                'uplink': '',
                'uif': ''
            }
        },
        'MISC_MGMT': {
            x['ip']: {
                'dev': x['dev'],
                'ping': False,
                'mac': '',
                'uplink': '',
                'uif': ''
            } for x in infra.to_dict('records')
        },
        'MUX_MGMT': {
            x['ip']: {
                'dev': x['dev'],
                'ping': False,
                'mac': '',
                'uplink': x['uplink'],
                'uif': x['port'],
                'eif': ''
            } for x in mux
        }
    }
    for mux in infra['MUX_MGMT']:
        infra['MUX_MGMT'][mux]['eift'] = mux_port_df[
            mux_port_df['MUX A'] == infra['MUX_MGMT'][mux]['dev']
            ][['Cisco router A', 'Cisco E1 interface A']].to_string(index=False, header=False)
    dwdm_sites = [
        'ES8_PS01', 'ES3_PS01', 'ES6_PS03', 'ES6_PS07', 'ES8_PS08', 'EXT01', 'ES8_PS07',
        'ES6_PS06', 'ES6_PS01', 'AU', 'ES7_PS01', 'ES3_PS07', 'ES7_PS16', 'ES8_PS11',
        'ES3', 'ES7', 'EXT03', 'EXT19', 'EXT21', 'EXT02', 'EXT13', 'ES7_PS14'
    ]
    if site['id'] in dwdm_sites:
        dwdm_site = vrf_ip.filter(like=site['id'] + '-RTR', axis=0)['DWDM_MGMT']
        dwdm_ip = site_net[:-4] + '38'
        try:
            infra['DWDM_MGMT'] = {
                dwdm_ip: {
                    'dev': 'DWDM',
                    'ping': False,
                    'mac': '',
                    'uplink': dwdm_site.index[dwdm_site != False].item(),
                    'uif': ''
                }}
        except:
            infra['DWDM_MGMT'] = {
                dwdm_ip: {
                    'dev': 'DWDM',
                    'ping': False,
                    'mac': '',
                    'uplink': 'Data.xslx failure',
                    'uif': ''
                }}

    if "_CP" in site['id']:
        infra['FW'].pop(site_net[:-4] + '5')
        infra['FW_MGMT'].pop(site_net[:-4] + '13')
    site['infra'] = infra
    site['site_net'] = site_net
    # return infra


def rtr_gather_data(i, rtr, infra_ip, check_fw=False):
    site_rtr = {
        'device_type': 'cisco_ios',
        'host': rtr['Loopback0'],
        'username': LOGIN,
        'password': PASSWORD,
        'secret': PASSWORD
    }
    vrf_template = PATH_TMPLT / 'cisco_ios_show_vrf.textfsm'
    ospf_template = PATH_TMPLT / 'cisco_ios_show_ip_ospf_neighbor.textfsm'
    arp_template = PATH_TMPLT / 'cisco_ios_show_ip_arp.textfsm'
    mac_template = PATH_TMPLT / 'cisco_ios_show_mac_router.textfsm'
    bgp_template = PATH_TMPLT / 'cisco_ios_show_ip_bgp_summary.textfsm'
    vrrp_template = PATH_TMPLT / 'cisco_ios_show_vrrp_brief.textfsm'
    result = {}
    with netmiko.ConnectHandler(**site_rtr) as ssh:
        print(f'Connected to {rtr["Hostname"]}')
        ssh.enable()
        if not rtr.get('config', False) or isinstance(rtr.get('sw_int', False), list):
            print('sending config')
            ssh.send_config_set(generate_config(rtr))
            print('saving config')
            ssh.fast_cli = False
            ssh.save_config()
            ssh.fast_cli = True
            rtr['config'] = True
        print('Gathering "show" commands')
        vrfs = ssh.send_command(
            'show vrf',
            use_textfsm=True,
            textfsm_template=vrf_template
        )
        vrfs = [x['name'] for x in vrfs]
        result['cli_ospf'] = ssh.send_command(
            'show ip ospf neighbor',
            use_textfsm=True,
            textfsm_template=ospf_template
        )
        result['cli_bgp_lu'] = ssh.send_command(
            'sho bgp ipv4 unicast summary',
            use_textfsm=True,
            textfsm_template=bgp_template
        )
        result['cli_bgp_vpn'] = ssh.send_command(
            'sho bgp vpnv4 unicast all summary',
            use_textfsm=True,
            textfsm_template=bgp_template
        )
        result['cli_vrrp'] = ssh.send_command(
            'show vrrp bri',
            use_textfsm=True,
            textfsm_template=vrrp_template
        )
        result['cli_rsvp'] = ssh.send_command(
            'sho mpls traffic-eng tunnels role head brief | i [1-4]_100'
        ).splitlines()
        result['cli_psu'] = ssh.send_command('show platform | i PSU')
        result['cli_ldp'] = ssh.send_command('show mpls ldp nei | i Peer')
        result['cli_inv'] = ssh.send_command('show inventory')
        with open(PATH_INV / f"{rtr['Hostname']}_{CURRENT_DATE}_show_inv.txt", 'w') as f:
            f.writelines(result['cli_inv'])
        unshut_e1(rtr, ssh)
        e1 = ssh.send_command('show controller e1 | i E1').strip().splitlines()
        result['e1'] = [re.search('[0-9]+/[0-9]+/[0-9]+', x)[0] for x in e1 if 'up' in x]
        if len(vrfs) > 1:
            result['pings'] = {}
            result['cli_arp_dict'] = {}
            ssh.send_command('clear mac address-table')
            print('Pinging infra IPs')
            # TODO don't ping if there's no connected interface in VRF
            for vrf in infra_ip.keys():
                if vrf in vrfs:
                    if 'FW' in vrf and not check_fw:
                        continue
                    result['pings'][vrf] = {}
                    for ip in infra_ip[vrf].keys():
                        res = ssh.send_command(f'ping vrf {vrf} {ip} repeat 4', strip_command=False)
                        if '!!' in res:
                            result['pings'][vrf][ip] = True
                            infra_ip[vrf][ip]['ping'] = True
                            if vrf == 'DWDM_MGMT':
                                if not ping_host(ip):
                                    print(f'!!!!! CANT PING DWDM {ip} FROM TERMINAL')
                        else:
                            # print(res)
                            result['pings'][vrf][ip] = False
                    result['cli_arp_dict'][vrf] = ssh.send_command(
                        f'show ip arp vrf {vrf}',
                        use_textfsm=True,
                        textfsm_template=arp_template
                    )
        result['cli_mac'] = ssh.send_command(
            'show mac address dynamic | b BD',
            use_textfsm=True,
            textfsm_template=mac_template
        )
    return i, result


def check_from_dc(site):
    dc1_rtr1 = {
        'device_type': 'cisco_xr',
        'host': '10.252.0.1',
        'username': LOGIN,
        'password': PASSWORD,
        'secret': PASSWORD
    }
    dc2_rtr1 = {
        'device_type': 'cisco_xr',
        'host': '10.252.0.3',
        'username': LOGIN,
        'password': PASSWORD,
        'secret': PASSWORD
    }
    print('connecting to DC1 & DC2...')
    with netmiko.ConnectHandler(**dc1_rtr1) as dc1, netmiko.ConnectHandler(**dc2_rtr1) as dc2:
        links = pd.read_excel(
            PATH / 'Data.xlsx',
            sheet_name='Links',
            header=1,
            index_col=0
        )
        ip1 = links[
            (links['Hostname A'].str.contains(site['id'] + '-RTR'))
            & ((links['VLAN A']) == site['vlan1'])
            & (links['Hostname B'] == 'CORE-DC1-WAN-RTR-01')
            ]['IP A'].to_string(index=False, header=False)
        ip2 = links[
            (links['Hostname A'].str.contains(site['id'] + '-RTR'))
            & ((links['VLAN A']) == site['vlan2'])
            & (links['Hostname B'] == 'CORE-DC2-WAN-RTR-01')
            ]['IP A'].to_string(index=False, header=False)
        print('starting ping...')
        ping_dc1 = dc1.send_command_timing(f'ping {ip1} count 4 timeout 1')
        ping_dc2 = dc2.send_command_timing(f'ping {ip2} count 4 timeout 1')
        print(ping_dc1.strip())
        print(ping_dc2.strip())
        print('-' * 25)
        if "!!" in ping_dc1 and site.get('mtu1', 0) < 1600:
            print('checking mtu via DC1, may take some time...')
            site['mtu1'] = check_mtu(dc1, ip1)
        if "!!" in ping_dc2 and site.get('mtu2', 0) < 1600:
            print('checking mtu via DC2, may take some time...')
            site['mtu2'] = check_mtu(dc2, ip2)
        if site.get('mtu1', 0) == site.get('mtu2', 0) == 1600:
            site['dg_ok'] = True
        else:
            site['dg_ok'] = False


def check_mtu(ssh, ip):
    mtu_l = 1400
    mtu_h = 1600
    mtu = mtu_h
    # divide diff by half and check MTU
    while True:
        #         ping = test_ping(mtu)
        ping = ssh.send_command_timing(f'ping {ip} count 4 timeout 1 df- size {mtu}', )
        if mtu_h - mtu_l <= 1:
            break
        if "!!" in ping:
            mtu_l = mtu
        else:
            mtu_h = mtu
        mtu = (mtu_l + mtu_h) // 2
    print(f"MTU for {ip} is {mtu}")
    return mtu


def sw_gather_data(sw_ip, send_config=True):
    site_sw = {
        'device_type': 'cisco_ios',
        'host': sw_ip,
        'username': LOGIN,
        'password': PASSWORD,
        'secret': PASSWORD
    }
    mac_template = PATH_TMPLT / 'cisco_ios_show_mac-address-table.textfsm'
    cdp_template = PATH_TMPLT / 'cisco_ios_show_cdp_neighbors.textfsm'
    sw_config = [
        'ip access-list extended ZBX_ACL',
        '10 permit ip 10.253.148.0 0.0.0.255 any',
        '20 permit ip 10.253.155.0 0.0.0.255 any',
        'snmp-server community UkR3N3rg0-ZBX RO ZBX_ACL',
        'snmp-server enable traps',
        'snmp-server host 10.253.148.10 version 2c UkR3N3rg0-ZBX ',
        'snmp-server host 10.253.155.10 version 2c UkR3N3rg0-ZBX',
        'service unsupported-transceiver',
        'no errdisable detect cause gbic-invalid'
    ]
    result = {}
    with netmiko.ConnectHandler(**site_sw) as ssh:
        ssh.enable()
        if send_config:
            print('sending config...')
            ssh.send_config_set(sw_config)
            print('saving config...')
            ssh.save_config()
            print('gathering "show" commands...')
        result['cli_cdp'] = ssh.send_command(
            'show cdp nei',
            use_textfsm=True,
            textfsm_template=cdp_template
        )
        result['cli_inv'] = ssh.send_command('show inv')
        result['cli_psu'] = ssh.send_command('show envi power | i PWR')
        if '!!' in ssh.send_command(f'ping 10.253.148.10 repeat 4', strip_command=False):
            result['ping_zb'] = True
        else:
            result['ping_zb'] = False
        result['cli_mac'] = ssh.send_command(
            'show mac add dyna',
            use_textfsm=True,
            textfsm_template=mac_template
        )
    print('Done!')
    return result


def gather_rtr_runner(site, check_fw=True):
    threads = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        for i, rtr in enumerate(site['rtrs']):
            threads.append(executor.submit(rtr_gather_data, i, rtr, site['infra'], check_fw))

        for task in as_completed(threads):
            i, result = task.result()
            site['rtrs'][i].update(result)
            print(f"Finished with {site['rtrs'][i]['Hostname']}")


def gather_site_data(site, check_fw=True):
    print("gathering info from routers")
    gather_rtr_runner(site, check_fw)

    print('refreshing switch MAC table')
    if 'sws' in site.keys():
        rtr_int = pd.read_excel(PATH / 'Data.xlsx',
                                keep_default_na=False,
                                sheet_name='VRF_Intf',
                                header=1,
                                index_col=0).fillna(False)
        print('gathering info from switches')
        for i, sw in enumerate(site['sws']):
            if 'SW-01' in sw['Hostname']:
                site['sws'][i]['ip'] = site['site_net'][:-4] + '20'
            elif 'SW-02' in sw['Hostname']:
                site['sws'][i]['ip'] = site['site_net'][:-4] + '21'
            else:
                print('Problem with switch IP')
                exit(0)
            if ['ping_zb']:
                send_config = False
            site['sws'][i].update(sw_gather_data(sw['ip'], send_config))
            print('saving inventory')
            with open(PATH_INV / f"{sw['Hostname']}_{CURRENT_DATE}_show_inv.txt", 'w') as f:
                f.writelines(site['sws'][i]['cli_inv'])
    for rtr in site['rtrs']:
        if 'sws' in site.keys():
            for sws in site['sws']:
                sws['cdp_int'] = [x['local_interface'].replace('Gig ', 'Gi') for x in sws['cli_cdp']]
                # REMOVE TRUNKS TO ROUTERS
                sws['cli_mac'] = [x for x in sws['cli_mac'] if not x['destination_port'] in sws['cdp_int']]
                for nbr in sws['cli_cdp']:
                    if rtr['Hostname'] in nbr['neighbor']:
                        if 'sw_int' in rtr.keys():
                            rtr['sw_int'].append(nbr['neighbor_interface'])
                        else:
                            rtr['sw_int'] = [nbr['neighbor_interface']]
                        assert isinstance(rtr_int, pd.DataFrame)
                        d = rtr_int.loc[rtr['Hostname']]
                        table_int = ['Gig ' + x for x in d[d.str.contains('SW')].to_string().split()[::2]]
                        if not nbr['neighbor_interface'] in table_int:
                            sws['uplink'] = 'CHECK'
                            print(
                                f"!!!!! CDP on switch shows router via \n!!!!! interface {[nbr['neighbor_interface']]} but \n!!!!! not in table list {table_int}")
                        else:
                            sws['uplink'] = 'OK'


def generate_mac_table(site):
    mac_dict = {}
    if 'sws' in site.keys():
        devices = site['rtrs'] + site['sws']
    else:
        devices = site['rtrs']
    for dev in devices:
        if 'cli_mac' in dev.keys():
            cli_mac = dev['cli_mac']
            mac_dict.update({
                x['destination_address']: [dev['Hostname'],
                                           x['destination_port']] for x in cli_mac \
                if not 'tefp' in x['destination_port'] \
                   and not '10.25' in x['destination_port']
            })
        if 'cli_arp_dict' in dev.keys():
            for vrf in site['infra'].keys():
                for ip in site['infra'][vrf].keys():
                    if site['infra'][vrf][ip]['ping'] and vrf in dev['cli_arp_dict'].keys():
                        for arp in dev['cli_arp_dict'][vrf]:
                            if ip == arp['address'] and arp['mac'] != 'Incomplete':
                                site['infra'][vrf][ip]['mac'] = arp['mac']
                                break
        dev['psu'] = 'OK'
        if not check_psu(dev['cli_psu']):
            dev['psu'] = 'FAIL'
            print(f'!!!!! PSU NOT OK on {dev["Hostname"]}')
    return mac_dict


def all_mux_check(muxes, searching_status='11', any_check=False):
    # SNMP all muxes to find 11
    for ip in muxes:
        if muxes[ip]['eif'] == '':
            i, status = get_mux_status(ip)
            # print(ip, status)
            if status == searching_status:
                if any_check:
                    print('via Shutdown')
                    return True
                return ip
            elif not status:
                print(f'No SNMP from MUX {ip}')
            elif status == '00':
                print(f"No E1 on {muxes[ip]['dev']}")
    return False


def mux_check_full(rtr, muxes, mux_status):
    site_rtr = {
        'device_type': 'cisco_ios',
        'host': rtr['Loopback0'],
        'username': LOGIN,
        'password': PASSWORD,
        'secret': PASSWORD
    }
    with netmiko.ConnectHandler(**site_rtr) as ssh:
        ssh.enable()
        for e1 in rtr['e1']:
            e1_config = [f'controller e1 {e1}',
                         'shutdown']
            ssh.send_config_set(e1_config)
            sleep(3)
            new_status = {ip: get_mux_status(ip)[1] for ip in muxes}
            for ip in mux_status:
                if mux_status[ip] != new_status[ip]:
                    if muxes[ip]['eift'] != f"{rtr['Hostname']} {e1}":
                        print(f'check E1 connect on {muxes[ip]["dev"]}')
                        muxes[ip]['eif'] = f"!!! {rtr['Hostname']} {e1}"
                    else:
                        print(f"{muxes[ip]['dev']} <-> {rtr['Hostname']} {e1} - OK")
                        muxes[ip]['eif'] = f"{rtr['Hostname']} {e1}"
                    check_via_loop = False
                    break
                else:
                    check_via_loop = True
            if check_via_loop:
                e1_config = [
                    f'controller e1 {e1}',
                    'no shutdown',
                    'loopback network line'
                ]
                ssh.send_config_set(e1_config)
                sleep(3)
                new_status = {ip: get_mux_status(ip) for ip in muxes}
                for ip in mux_status:
                    if mux_status[ip] != new_status[ip]:
                        if muxes[ip]['eift'] != f"{rtr['Hostname']} {e1}":
                            print(f'check E1 connect on {muxes[ip]["dev"]}')
                            muxes[ip]['eif'] = f"!!! {rtr['Hostname']} {e1}"
                        else:
                            print(f"{muxes[ip]['dev']} <-> {rtr['Hostname']} {e1} - OK")
                            muxes[ip]['eif'] = f"{rtr['Hostname']} {e1}"
                        break
            e1_config = [f'controller e1 {e1}',
                         'no shutdown',
                         'no loopback network line',
                         'exit']
            ssh.send_config_set(e1_config)


def remove_loops(rtr, loop_force=False):
    if rtr['loop_set'] or loop_force:
        site_rtr = {
            'device_type': 'cisco_ios',
            'host': rtr['Loopback0'],
            'username': LOGIN,
            'password': PASSWORD,
            'secret': PASSWORD
        }
        with netmiko.ConnectHandler(**site_rtr) as ssh:
            if loop_force == True:
                e1 = ssh.send_command('show controller e1 | i E1').strip().splitlines()
                e1_list = [re.search('[0-9]+/[0-9]+/[0-9]+', x)[0] for x in e1]
            else:
                e1_list = rtr['e1']
            remove_loops_config = []
            for e1 in e1_list:
                remove_loops_config.extend(
                    [f'controller e1 {e1}',
                     'no loopback',
                     'exit']
                )
            ssh.enable()
            ssh.send_config_set(remove_loops_config)
            rtr['loop_set'] = False
            print('all e1 loops removed')
    else:
        print('No loops to remove')


def manage_e1_loops(rtr, set_loops=False):
    if set_loops:
        set_loops = ''
    else:
        set_loops = 'no '
    site_rtr = {
        'device_type': 'cisco_ios',
        'host': rtr['Loopback0'],
        'username': LOGIN,
        'password': PASSWORD,
        'secret': PASSWORD
    }

    with netmiko.ConnectHandler(**site_rtr) as ssh:
        ssh.enable()
        e1 = ssh.send_command('show controller e1 | i E1').strip().splitlines()
        e1_list = [re.search('[0-9]+/[0-9]+/[0-9]+', x)[0] for x in e1]
        remove_loops_config = []
        for e1 in rtr['e1']:
            remove_loops_config.extend(
                [f'controller e1 {e1}',
                 f'{set_loops}loopback network line',
                 'exit']
            )
        if remove_loops_config:
            ssh.send_config_set(remove_loops_config)
            if set_loops == '':
                rtr['loop_set'] = True
                print('all e1 loops set')
            else:
                rtr['loop_set'] = False
                print('all e1 loops removed')
        else:
            print('No E1 on router')


def manage_cem_ifs(rtr, shut=False, ssh=False):
    if shut:
        shut = ''
    else:
        shut = 'no '
    site_rtr = {
        'device_type': 'cisco_ios',
        'host': rtr['Loopback0'],
        'username': LOGIN,
        'password': PASSWORD,
        'secret': PASSWORD
    }

    if not ssh:
        ssh = netmiko.ConnectHandler(**site_rtr)
    ssh.enable()
    cem_cli = ssh.send_command('sh ip int bri | i ^CEM').strip().splitlines()
    cem_list = [re.search('^CEM[0-9]+/[0-9]+/[0-9]+', x)[0] for x in cem_cli]
    remove_loops_config = []
    for cem in cem_list:
        remove_loops_config.extend(
            [f'interface {cem}',
             f'{shut}shutdown',
             'exit']
        )
    if remove_loops_config:
        ssh.send_config_set(remove_loops_config)
        if shut == 'no ':
            print('all CEM are up')
        else:
            print('all CEM are shut')
    else:
        print('No CEM on router')


def unshut_e1(rtr, ssh=False, e1_cli=''):
    site_rtr = {
        'device_type': 'cisco_ios',
        'host': rtr['Loopback0'],
        'username': LOGIN,
        'password': PASSWORD,
        'secret': PASSWORD
    }
    remove_shut_config = []
    e1_cli = ssh.send_command('show controller e1 | i E1').strip().splitlines()
    e1_list = [re.search('[0-9]+/[0-9]+/[0-9]+', x)[0] for x in e1_cli]
    for e1 in e1_list:
        remove_shut_config.extend(
            [f'controller e1 {e1}',
             'no shutdown']
        )
    if not ssh:
        ssh = netmiko.ConnectHandler(**site_rtr)
    ssh.enable()
    ssh.send_config_set(remove_shut_config)
    print('unshuted all e1')


def check_psu(psu):
    data = [x for x in psu.splitlines() if x]
    if all([bool(" ok " in i.lower()) for i in data] + [len(data) == 2]):
        return True
    else:
        return False


def check_site_rtrs(site):
    def check_bgp(rtr_bgp, rtr_cli, bgp_ips):
        for i, flag in enumerate(rtr_bgp):
            if flag:
                for nbr in rtr_cli:
                    if re.match(bgp_lu_ips[i], nbr['bgp_neigh']):
                        rtr_bgp[i] = (rtr_bgp[i], nbr['state_pfxrcd'])
                        break

    bgp_vpn_ips = [f'10.252.0.[1-3]{x}' for x in range(1, 5)]
    bgp_lu_ips = bgp_vpn_ips + ['10.252.[1-2].170', '10.252.[1-2].171', '10.252.[2-3].138', '10.252.[2-3].139']
    bgp = pd.read_excel(
        PATH / 'Data.xlsx',
        sheet_name='BGP',
        index_col=0
    ).fillna(False)
    for rtr in site['rtrs']:
        # CHECK BGP
        rtr['bgp_lu'] = [True if 'LU' in str(x) else False for x in bgp.loc[rtr['Hostname']]]
        rtr['bgp_vpn'] = [True if 'VPN' in str(x) else False for x in bgp.loc[rtr['Hostname']]]
        if any(rtr['bgp_lu']):
            check_bgp(rtr['bgp_lu'], rtr['cli_bgp_lu'], bgp_lu_ips)
        if any(rtr['bgp_vpn']):
            check_bgp(rtr['bgp_vpn'], rtr['cli_bgp_vpn'], bgp_vpn_ips)
        site_peer = True
        dc1_peer = True
        dc2_peer = True
        rtr['ospf'] = 'OK'
        if 'RTR-01' in rtr['Hostname']:
            site_peer = dc1_peer = dc2_peer = False
            if '_CP' in site['id']:
                site_peer_ip = ''
            else:
                site_peer_ip = format(net4(rtr['Loopback0']).network_address + 1)
        # check OSPF
        for nbr in rtr['cli_ospf']:
            if not nbr['state'] == 'FULL/  -':
                print(f"!!!!! OSPF not FULL with {nbr['neighbor_id']} on {nbr['interface']}")
                rtr['ospf'] = 'CHECK'
            if nbr['neighbor_id'] == site_peer_ip:
                site_peer = True
            elif nbr['neighbor_id'] == '10.252.0.1':
                dc1_peer = True
            elif nbr['neighbor_id'] == '10.252.0.3':
                dc2_peer = True
        if not site_peer and not '_CP' in site['id']:
            print("!!!!! CHECK OSPF RTR-01 <-> RTR-02")
            rtr['ospf'] = 'CHECK'
        if not dc1_peer:
            print("!!!!! CHECK OSPF WITH DC1 on RTR-01")
            rtr['ospf'] = 'CHECK'
        if not dc2_peer:
            print("!!!!! CHECK OSPF WITH DC2 on RTR-01")
            rtr['ospf'] = 'CHECK'
        # CHECK LDP
        rtr['ldp'] = 'OK'
        if not all([
            '10.252.0.1' in rtr['cli_ldp'],
            '10.252.0.2' in rtr['cli_ldp'],
            '10.252.0.3' in rtr['cli_ldp'],
            '10.252.0.4' in rtr['cli_ldp'],
            site_peer_ip in rtr['cli_ldp']
        ]):
            print(f"!!!! CHECK LDP peering with DC or site peer on {rtr['Hostname']}")
            rtr['ldp'] = 'CHECK'
        # CHECK RSVP
        if len(rtr['cli_rsvp']) > 2:
            rtr['rsvp'] = 'OK'
            if [rtr['cli_rsvp']] and not all(['up/up' in x for x in rtr['cli_rsvp'] if x]):
                print(f"!!!!! CHECK RSVP tunnels on {rtr['Hostname']}")
                rtr['rsvp'] = 'CHECK'
        else:
            rtr['rsvp'] = '--'
        # CHECK VRRP
        if type(rtr['cli_vrrp']) == list:
            if all([bool(x['state'] == 'MASTER') for x in rtr['cli_vrrp']]):
                rtr['vrrp'] = 'All M'
            elif all([bool(x['state'] == 'BACKUP') for x in rtr['cli_vrrp']]):
                rtr['vrrp'] = 'ALL B'
            else:
                rtr['vrrp'] = 'CHECK'
        else:
            rtr['vrrp'] = '--'


def infra_find_interface(site, check_fw=True):
    mac_dict = generate_mac_table(site)
    for vrf in site['infra']:
        if not check_fw and 'FW' in vrf:
            pass
        else:
            for ip in site['infra'][vrf].keys():
                try:
                    site['infra'][vrf][ip]['uif'] = mac_dict[site['infra'][vrf][ip]['mac']][1]
                    if site['infra'][vrf][ip]['uplink'] and site['infra'][vrf][ip]['uplink'] != \
                            mac_dict[site['infra'][vrf][ip]['mac']][0]:
                        print(
                            f"!!! Check cabling for {site['infra'][vrf][ip]['dev']}. Should be {site['infra'][vrf][ip]['uplink']} but is {mac_dict[site['infra'][vrf][ip]['mac']][0]}")
                        site['infra'][vrf][ip]['uplink'] = '!!' + mac_dict[site['infra'][vrf][ip]['mac']][0]
                    elif site['infra'][vrf][ip]["uplink"] == "":
                        site['infra'][vrf][ip]['uplink'] = mac_dict[site['infra'][vrf][ip]['mac']][0]
                except:
                    print(f'!!! Could not find MAC for {ip}')


def print_routers(rtrs, mtu1, mtu2):
    hdr = '\t'.join([x['Hostname'][-6:] + ' ' + x['Loopback0'] for x in rtrs])
    psus = '\t\t\t'.join([x['psu'] for x in rtrs])
    ospf = '\t\t\t'.join([x['ospf'] for x in rtrs])
    ldp = '\t\t\t'.join([x['ldp'] for x in rtrs])
    rsvp = '\t\t\t'.join([x['rsvp'] for x in rtrs])
    vrrp = '\t\t\t'.join([x['vrrp'] for x in rtrs])

    print(f'\t\t{hdr}')
    print(f'PSU\t\t{psus}')
    print(f'OSPF\t\t{ospf}')
    print(f'LDP\t\t{ldp}')
    print(f'RSVP\t\t{rsvp}')
    print(f'VRRP\t\t{vrrp}')
    print(f'MTU via DG \t{mtu1}, {mtu2}')

    bgps = ['DC1-RTR1', 'DC1-RTR2', 'DC2-RTR1', 'DC2-RTR2',
            'ABR-1', 'ABR-2', 'ABR-3', 'ABR-4']
    for i, peer in enumerate(bgps):
        line = " ".join([f"{x['bgp_lu'][i]!s:>12s} {x['bgp_vpn'][i]!s:<12s}" for x in rtrs])
        print(f'{peer:<8s} {line}')


def print_switches(sws):
    hdr = '\t'.join([x['Hostname'][-5:] + ' ' + x['ip'] for x in sws])
    psus = '\t'.join([x['psu'] for x in sws])
    zbx = '\t'.join([str(x['ping_zb']) for x in sws])
    uplinks = '\t'.join([x['uplink'] for x in sws])
    print(f'\t{hdr}')
    print(f'PSU\t{psus}')
    print(f'ZBX\t{zbx}')
    print(f'UPLNK\t{uplinks}')


def print_infra(infr, check_fw=True):
    infra_list = [['VRF', 'IP', 'DEVICE', 'PING', 'UPLINK', '']]
    infra_list += [
        [
            vrf, ip, infr[vrf][ip]['dev'], infr[vrf][ip]['ping'],
            f"{infr[vrf][ip]['uplink']} {infr[vrf][ip]['uif']}"
        ] for vrf in infr for ip in infr[vrf]
    ]
    for i in infra_list:
        if 'MUX' in i[0]:
            line = f'{i[0]:<10s}{i[1]:<16s}{i[2]:<24s}{i[3]!s:<8s}{i[4]:<36s}{infr[i[0]][i[1]]["eif"]:<25s}  '
            if "!!!" in line or 'WRONG' in line:
                line += infr[i[0]][i[1]]['eift']
            print(line)
        elif 'FW' in i[0] and not check_fw:
            pass
        else:
            print(f'{i[0]:<10s}{i[1]:<16s}{i[2]:<24s}{i[3]!s:<8s}{i[4]:<10s}')


def print_report(site, check_fw=False):
    if 'sws' in site.keys():
        print_switches(site['sws'])
    print_routers(site['rtrs'], site["mtu1"], site["mtu2"])
    print('\n')
    print_infra(site['infra'], check_fw)
    print(site['name'])


def read_cache(site):
    try:
        cache_file = [
            x for x in sorted(
                Path(PATH_JSON).iterdir(), key=os.path.getmtime
            ) if site['id'] + '_2021' in x.name
        ][-1]
        with cache_file.open('r') as f:
            site = json.load(f)
        return site
    except Exception as E:
        for rtr in site['rtrs']:
            rtr['config'] = False
            rtr['loop_set'] = False
        return site


def set_fw(ftds):
    for ip in ftds.keys():
        if ftds[ip]['ping']:
            print(f'Checking FMC connect on {ip}')
            ftd_device = {
                'device_type': 'cisco_ftd',
                'host': ip,
                'username': 'admin',
                'password': PASSWORD
            }
            with netmiko.ConnectHandler(**ftd_device) as ssh:
                time_set = datetime.now().strftime('%m/%d/%Y 00:00:00')
                time = ssh.send_command('show time')
                if '2021' in time.splitlines()[-1]:
                    print(f'time is already {time.splitlines()[-1][16:]}')
                else:
                    ssh.send_command('expert', expect_string='$')
                    ssh.send_command('sudo su', strip_prompt=False, expect_string='Password:')
                    ssh.send_command_timing(PASSWORD, strip_prompt=False)
                    ssh.send_command(f'hwclock --set --date "{time_set}"', strip_prompt=False)
                    ssh.send_command(f'hwclock --set --date "{time_set}"', strip_prompt=False)
                    ssh.send_command('reboot', strip_prompt=False, expect_string="#")
                    print('device sent to reboot ' + datetime.now().time().isoformat())
        else:
            print(f'Cant fix {ip}, no ping')


def mux_check_direct_e1(muxes, rtrs):
    def connect_to_rtr(ip, hname):
        rtr = {
            'device_type': 'cisco_ios',
            'host': ip,
            'username': LOGIN,
            'password': PASSWORD,
            'secret': PASSWORD
        }
        ssh = netmiko.ConnectHandler(**rtr)
        ssh.enable()
        e1 = ssh.send_command('show controller e1 | i E1').strip().splitlines()
        e1_list = [re.search('[0-9]+/[0-9]+/[0-9]+', x)[0] for x in e1]
        if not e1_list:
            ssh.disconnect()
            return {hname: 'No E1'}
        remove_loops_config = []
        for e1 in e1_list:
            remove_loops_config.extend(
                [f'controller e1 {e1}',
                 'no shut',
                 'no loopback',
                 'exit']
            )
        ssh.send_config_set(remove_loops_config)
        print(f'Connected to {hname}')
        return {hname: ssh}

    threads = []
    rtr_ssh = {}
    with ThreadPoolExecutor(max_workers=6) as executor:
        for rtr in rtrs:
            threads.append(executor.submit(connect_to_rtr, rtr['Loopback0'], rtr['Hostname']))

        for task in as_completed(threads):
            rtr_ssh.update(task.result())

    for ip in muxes:
        if not muxes[ip]['ping']:
            continue
        hname, port = muxes[ip]['eift'].split()
        if not hname in rtr_ssh.keys():
            print(f'skiping {ip}, connected to other site {muxes["eift"]}')
        else:
            status = get_mux_status(ip)
            if status[1] == '00':
                print(f'detected 00 on {ip}')
                muxes[ip]['eif'] = 'detected 00'
                continue
            elif status[1] == '11':
                check_cmd = 'shutdown'
            else:
                check_cmd = 'loopback network line'
            commands = [f'controller e1 {port}',
                        check_cmd,
                        'exit'
                        ]
            rtr_ssh[hname].send_config_set(commands)
            sleep(3)
            new_status = get_mux_status(ip)
            if new_status != status:
                muxes[ip]['eif'] = muxes[ip]['eift']
                # print(f'E1 on {ip} ok')
            else:
                print(f'E1 on {ip} WRONG')
                muxes[ip]['eif'] = 'WRONG E1 CONNECT'
            commands = [f'controller e1 {port}',
                        'no shutdown',
                        'no loopback',
                        'exit'#hwclo
                        ]
            rtr_ssh[hname].send_config_set(commands)
    for hname in rtr_ssh:
        try:
            rtr_ssh[hname].disconnect()
        except:
            pass


def form_letter(site, mtu1):
    print(f"""
tech@datagroup.ua

'Тіран Максим Леонідович' <tiran.ml@ua.energy>; 'Оконечніков Олександр Валентинович' <Okonechnikov.OV@ua.energy>; 
'Шумейко Володимир Анатолійович' <Shumeyko.VA@ua.energy>; noc@ua.energy; 
'Oleg Vystavkin' <ovystavkin@greennet.com.ua>; d.soloviov@netwave.ua

Укренерго // Тех. мережа // {site['name']}

Добрый день!
По каналу:
{site['name']}
Включились в {site['isp_eq']}
Vlan {site['vlan1']} - Наливайковка
Vlan {site['vlan2']} - Жирова
Tagged, MTU 1600
""")
    if mtu1:
        print(f'Сейчас видим MTU {mtu1}')
    else:
        print('Сейчас нет связи.')
    print('Прошу проверить.')


if __name__ == '__main__':
    cli()
