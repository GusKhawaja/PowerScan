#!/usr/bin/env python

from libs import utils
from libs.dto import *
from multiprocessing import TimeoutError
from multiprocessing import Pool
from libs.vuln_finder import VulnsSearch

nmap_tool_name = 'NMAP Telnet Enum'
hydra_brute = 'Hydra Telnet Brute Force'


def execute_nmap_telnet_enum(ip_address, port_number):
    command = "nmap -sV -p %s --script=telnet* %s" % (port_number, ip_address)
    return utils.execute_enum_cmd(nmap_tool_name, command)


def check_vulns(service):
    vs = VulnsSearch(service.product, service.version)
    return vs.get_vulns()

def brute_force(ip_address):
    file_name = './temp/' + ip_address + "_telnet.txt"
    command = 'hydra -t 10 -V -f -L ./resources/common_users.txt -P ./resources/common_passwords.txt telnet://' + ip_address + '>' + file_name
    utils.execute_enum_cmd1(hydra_brute, command)
    
    return utils.open_file(file_name)


def start(ip_address, service):
    pool = Pool(processes=2)
    service.enumeration_list = []
    try:
        result = pool.apply_async(execute_nmap_telnet_enum, [ip_address, service.port])
        output = result.get(timeout=15 * 60)
        enum = EnumerationDTO(nmap_tool_name)
        enum.results_output = output
        service.enumeration_list.append(enum)
    except TimeoutError:
        utils.print_red('[!]timeout for calling function: ' + nmap_tool_name)

    try:
        result = pool.apply_async(check_vulns, [service])
        output = result.get(timeout=10 * 60)
        enum = EnumerationDTO('Check Telnet Vulnerabilities')
        enum.results_output = output
        service.enumeration_list.append(enum)
    except TimeoutError:
        utils.print_red('[!]timeout for calling function: check_vulns()')

    try:
        result = pool.apply_async(brute_force, [ip_address])
        output = result.get(timeout=15 * 60)
        enum = EnumerationDTO(hydra_brute)
        enum.results_output = output
        service.enumeration_list.append(enum)
    except TimeoutError:
        utils.print_red('[!]timeout for calling function: ' + hydra_brute)
