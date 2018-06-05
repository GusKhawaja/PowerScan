#!/usr/bin/env python

from libs import utils
from libs.dto import *
from multiprocessing import TimeoutError
from multiprocessing import Pool
from libs.vuln_finder import VulnsSearch

nmap_tool_name = 'NMAP SMB Enum'
enum4linux_tool_name = 'Enum4Linux SMB Enum'
nmblookup_tool_name = 'NMBLookup SMB Enum'
nbtscan_tool_name = 'nbtscan SMB Enum'
extractpasswordplc_tool_name = 'Extract Password Policy - Polenum'
samrdump_tool_name = 'Samrdump SMB Enum'
showmount_tool_name = 'Showmount SMB Enum'


def execute_nmap_smb_enum(ip_address, port_number):
    command = "nmap -sV -p %s --script=smb-vuln* %s" % (port_number, ip_address)
    return utils.execute_enum_cmd(nmap_tool_name, command)


def execute_enum4linux_smb_enum(ip_address):
    command = "enum4linux -a %s" % ip_address
    return utils.execute_enum_cmd(enum4linux_tool_name, command)


def execute_nmblookup_smb_enum(ip_address):
    command = "nmblookup -A %s" % ip_address
    return utils.execute_enum_cmd(nmblookup_tool_name, command)


def execute_nbtscan_smb_enum(ip_address):
    command = "nbtscan -v -h %s" % ip_address
    return utils.execute_enum_cmd(nbtscan_tool_name, command)


def extract_password_policy(ip_address):
    command = "polenum %s" % ip_address
    return utils.execute_enum_cmd(extractpasswordplc_tool_name, command)


def execute_samrdump_smb_enum(ip_address, port_number):
    command = "python /usr/share/doc/python-impacket/examples/samrdump.py %s %s/SMB" % (ip_address, port_number)
    return utils.execute_enum_cmd(samrdump_tool_name, command)


def show_nfs_share(ip_address):
    command = "showmount -e %s" % (ip_address)
    return utils.execute_enum_cmd(showmount_tool_name, command)


def check_vulns(service):
    vs = VulnsSearch(service.product, service.version)
    return vs.get_vulns()


def start(ip_address, service):
    pool = Pool(processes=5)
    service.enumeration_list = []
    
    try:
        result = pool.apply_async(execute_nmap_smb_enum, [ip_address, service.port])
        output = result.get(timeout=30 * 60)
        enum = EnumerationDTO(nmap_tool_name)
        enum.results_output = output
        service.enumeration_list.append(enum)
    except TimeoutError:
        utils.print_red('[!]timeout for calling function: ' + nmap_tool_name)

    try:
        result = pool.apply_async(execute_enum4linux_smb_enum, [ip_address])
        output = result.get(timeout=5 * 60)
        enum = EnumerationDTO(enum4linux_tool_name)
        enum.results_output = output
        service.enumeration_list.append(enum)
    except TimeoutError:
        utils.print_red('[!]timeout for calling function: ' + enum4linux_tool_name)

    try:
        result = pool.apply_async(execute_nmblookup_smb_enum, [ip_address])
        output = result.get(timeout=5 * 60)
        enum = EnumerationDTO(nmblookup_tool_name)
        enum.results_output = output
        service.enumeration_list.append(enum)
    except TimeoutError:
        utils.print_red('[!]timeout for calling function: ' + nmblookup_tool_name)

    try:
        result = pool.apply_async(execute_samrdump_smb_enum, [ip_address, service.port])
        output = result.get(timeout=5 * 60)
        enum = EnumerationDTO(samrdump_tool_name)
        enum.results_output = output
        service.enumeration_list.append(enum)
    except TimeoutError:
        utils.print_red('[!]timeout for calling function: ' + samrdump_tool_name)

    try:
        result = pool.apply_async(extract_password_policy, [ip_address])
        output = result.get(timeout=5 * 60)
        enum = EnumerationDTO(extractpasswordplc_tool_name)
        enum.results_output = output
        service.enumeration_list.append(enum)
    except TimeoutError:
        utils.print_red('[!]timeout for calling function: ' + extractpasswordplc_tool_name)

    try:
        result = pool.apply_async(execute_nbtscan_smb_enum, [ip_address])
        output = result.get(timeout=3 * 60)
        enum = EnumerationDTO(nbtscan_tool_name)
        enum.results_output = output
        service.enumeration_list.append(enum)
    except TimeoutError:
        utils.print_red('[!]timeout for calling function: ' + nbtscan_tool_name)

    '''try:
        result = pool.apply_async(show_nfs_share, [ip_address])
        output = result.get(timeout=3 * 60)
        enum = EnumerationDTO(showmount_tool_name)
        enum.results_output = output
        service.enumeration_list.append(enum)
    except TimeoutError:
        utils.print_red('[!]timeout for calling function: ' + showmount_tool_name)'''

    
    result = check_vulns(service)
    enum = EnumerationDTO('Check SMB Vulnerabilities')
    enum.results_output = result
    service.enumeration_list.append(enum)
   

