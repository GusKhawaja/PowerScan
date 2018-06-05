#!/usr/bin/env python

from libs import utils
from libs.dto import *
from multiprocessing import TimeoutError
from multiprocessing import Pool
from libs.vuln_finder import VulnsSearch

nmap_tool_name = 'NMAP SNMP Enum'
snmp_tool_name = 'SNMP Check Enum'


def execute_nmap_snmp_enum(ip_address, port_number):
    command = "nmap -sV -p %s --script=snmp* %s" % (port_number, ip_address)
    return utils.execute_enum_cmd(nmap_tool_name, command)


def execute_snmpcheck_snmp_enum(ip_address):
    command = "snmp-check -t %s" % (ip_address)
    return utils.execute_enum_cmd(snmp_tool_name, command)


def check_vulns(service):
    vs = VulnsSearch(service.product, service.version)
    return vs.get_vulns()


def start(ip_address, service):
    pool = Pool(processes=3)
    service.enumeration_list = []

    try:
        result = pool.apply_async(execute_nmap_snmp_enum, [ip_address, service.port])
        output = result.get(timeout=15 * 60)
        enum = EnumerationDTO(nmap_tool_name)
        enum.results_output = output
        service.enumeration_list.append(enum)
    except TimeoutError:
        utils.print_red('[!]timeout for calling function: ' + nmap_tool_name)

    try:
        result = pool.apply_async(execute_snmpcheck_snmp_enum, [ip_address])
        output = result.get(timeout=10 * 60)
        enum = EnumerationDTO(snmp_tool_name)
        enum.results_output = output
        service.enumeration_list.append(enum)
    except TimeoutError:
        utils.print_red('[!]timeout for calling function: ' + snmp_tool_name)

    try:
        result = pool.apply_async(check_vulns, [service])
        output = result.get(timeout=10 * 60)
        enum = EnumerationDTO('Check SNMP Vulnerabilities')
        enum.results_output = output
        service.enumeration_list.append(enum)
    except TimeoutError:
        utils.print_red('[!]timeout for calling function: check_vulns()')
