#!/usr/bin/env python


from libs import utils
from libs.dto import *
from multiprocessing import TimeoutError
from multiprocessing import Pool
from libs.vuln_finder import VulnsSearch

nmap_tool_name = 'NMAP HTTP Enum'
nikto_tool_name = 'Nikto HTTP Enum'
crawler_tool_name = 'Dir HTTP Enum'
metasploit_tool_name = 'Metasploit HTTP Enum'
whatweb_tool_name = 'WhatWeb HTTP Enum'
screenshot_tool_name = 'Screenshot HTTP Enum'


def execute_nmap_http_enum(ip_address, port_number):
    command = "nmap -sV -p %s --script=http-enum,http-vuln*  %s" % (port_number, ip_address)
    return utils.execute_enum_cmd(nmap_tool_name, command)


def execute_nikto_http_enum(ip_address, port_number):
    file_name = 'temp/' + ip_address + '_nikto.txt'
    command = "nikto -host http://%s:%s -o %s" % (ip_address, port_number, file_name)
    utils.execute_enum_cmd(nikto_tool_name, command)
    # Parse Output
    nikto_file = open(file_name, 'r')
    output = nikto_file.read()
    output = output.replace('\n', '<br/>\n')
    return output


def execute_directories_http_enum(ip_address, port_number):
    command = "gobuster -u http://%s:%s -w /usr/share/wordlists/dirb/common.txt -s '200,204,301,302,307,403,500' -e" % (
        ip_address, port_number)
    return utils.execute_enum_cmd(crawler_tool_name, command)


def execute_metasploit_http_enum(ip_address, port_number):
    command = "service postgresql start && msfconsole -x 'load wmap; wmap_sites -a http://%s:%s; wmap_targets -t http://%s:%s; wmap_run -e; wmap_vulns -l; exit y'" % (
        ip_address, port_number, ip_address, port_number)
    return utils.execute_enum_cmd(metasploit_tool_name, command)


def execute_whatweb_http_enum(ip_address, port_number):
    command = "whatweb %s:%s" % (ip_address, port_number)
    output = utils.execute_enum_cmd(whatweb_tool_name, command)
    # Parse Output
    output = output.replace("[1m", "<br/>")
    output = output.replace("[0m]", "")
    output = output.replace("[0m[", "")
    output = output.replace("[31m", "")
    output = output.replace("[32m", "")
    output = output.replace("[33m", "")
    output = output.replace("[34m", "")
    output = output.replace("[36m", "")
    output = output.replace("[37m", "")
    utils.print_purple("[+] Finished whatweb HTTP Enum ...")
    return output


def take_screenshot(ip_address, port_number):
    url = 'http://' + ip_address + ':' + port_number
    file_path = 'temp/' + ip_address + "_" + port_number + ".png"

    command = "cutycapt --url=%s --out=%s" % (url, file_path)
    utils.execute_enum_cmd(screenshot_tool_name, command)

    return file_path


def check_vulns(service):
    vs = VulnsSearch(service.product, service.version)
    return vs.get_vulns()


def start(ip_address, service):
    pool = Pool(processes=8)

    service.enumeration_list = []

    try:
        result_nmap = pool.apply_async(execute_nmap_http_enum, [ip_address, service.port])
        output = result_nmap.get(timeout=45 * 60)
        enum = EnumerationDTO(nmap_tool_name)
        enum.results_output = output
        service.enumeration_list.append(enum)
    except TimeoutError:
        utils.print_red('[!]timeout for calling function: ' + nmap_tool_name)

    try:
        result_directories = pool.apply_async(execute_directories_http_enum, [ip_address, service.port])
        output = result_directories.get(timeout=5 * 60)
        enum = EnumerationDTO(crawler_tool_name)
        enum.results_output = output
        service.enumeration_list.append(enum)
    except TimeoutError:
        utils.print_red('[!]timeout for calling function: ' + crawler_tool_name)

    try:
        result_nikto = pool.apply_async(execute_nikto_http_enum, [ip_address, service.port])
        output = result_nikto.get(timeout=5 * 60)
        enum = EnumerationDTO(nikto_tool_name)
        enum.results_output = output
        service.enumeration_list.append(enum)
    except TimeoutError:
        utils.print_red('[!]timeout for calling function: ' + nikto_tool_name)

    try:
        result_metasploit = pool.apply_async(execute_metasploit_http_enum, [ip_address, service.port])
        output = result_metasploit.get(timeout=10 * 60)
        enum = EnumerationDTO(metasploit_tool_name)
        enum.results_output = output
        service.enumeration_list.append(enum)
    except TimeoutError:
        utils.print_red('[!]timeout for calling function: ' + metasploit_tool_name)

    try:
        result_whatweb = pool.apply_async(execute_whatweb_http_enum, [ip_address, service.port])
        output = result_whatweb.get(timeout=10 * 60)
        enum = EnumerationDTO(whatweb_tool_name)
        enum.results_output = output
        service.enumeration_list.append(enum)
    except TimeoutError:
        utils.print_red('[!]timeout for calling function: ' + whatweb_tool_name)

    try:
        result_screenshot = pool.apply_async(take_screenshot, [ip_address, service.port])
        file_path = result_screenshot.get(timeout=10 * 60)
        enum = EnumerationDTO(screenshot_tool_name)
        enum.results_output = "<img src=../%s class='img-fluid' alt='Responsive image>" % file_path
        service.enumeration_list.append(enum)
    except TimeoutError:
        utils.print_red('[!]timeout for calling function: ' + screenshot_tool_name)

    try:
        result = pool.apply_async(check_vulns, [service])
        output = result.get(timeout=10 * 60)
        enum = EnumerationDTO('Check HTTP Vulnerabilities')
        enum.results_output = output
        service.enumeration_list.append(enum)
    except TimeoutError:
        utils.print_red('[!]timeout for calling function: check_vulns()')
