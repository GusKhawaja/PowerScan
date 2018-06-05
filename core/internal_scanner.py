#!/usr/bin/env python

from libs import utils, nmap_protocol_scan
from libs.dto import *
from libs.report_creator import ReportCreator
from enums import http_enum,ssl_enum,ftp_enum,ssh_enum,smtp_enum,snmp_enum,smb_enum,mssql_enum,mysql_enum,dns_enum,rdp_enum,telnet_enum


def scan(host):
    smb_scanned = 0
    snmp_scanned = 0    
    for service_name in host.services_dic:
        
        services = host.services_dic[service_name]
        if service_name == "http":
            for service in services:
                print "[+] Enumerating: " + service.product + ":" + str(service.port)
                http_enum.start(host.ip_address, service)
        elif (service_name == "ssl/http") or ("https" in service_name):
            for service in services:
                print "[+] Enumerating: " + service.product + ":" + str(service.port)
                ssl_enum.start(host.ip_address, service)
        elif "ftp" in service_name:
            for service in services:
                print "[+] Enumerating: " + service.product + ":" + str(service.port)
                ftp_enum.start(host.ip_address, service)
        elif "ssh" in service_name:
            for service in services:
                print "[+] Enumerating: " + service.product + ":" + str(service.port)
                ssh_enum.start(host.ip_address, service)
        elif "smtp" in service_name:
            for service in services:
                print "[+] Enumerating: " + service.product + ":" + str(service.port)
                smtp_enum.start(host.ip_address, service)
        elif "snmp" in service_name:
            if snmp_scanned == 0:
                for service in services:
                    print "[+] Enumerating: " + service.product + ":" + str(service.port)
                    snmp_enum.start(host.ip_address, service)
                    snmp_scanned = 1
                    break
        elif "microsoft-ds" in service_name or "netbios-ssn" in service_name:
            if smb_scanned == 0:
                for service in services:
                    print "[+] Enumerating: " + service.product + ":" + str(service.port)
                    smb_enum.start(host.ip_address, service)
                    smb_scanned = 1
                    break
        elif "ms-sql" in service_name:
            for service in services:
                print "[+] Enumerating: " + service.product + ":" + str(service.port)
                mssql_enum.start(host.ip_address, service)
        elif "mysql" in service_name:
            for service in services:
                print "[+] Enumerating: " + service.product + ":" + str(service.port)
                mysql_enum.start(host.ip_address, service)
        elif "telnet" in service_name:
            for service in services:
                print "[+] Enumerating: " + service.product + ":" + str(service.port)
                telnet_enum.start(host.ip_address, service)        
        elif "domain" in service_name:
            for service in services:
                print "[+] Enumerating: " + service.product + ":" + str(service.port)
                dns_enum.start(host.ip_address, service)
        elif "ms-wbt-server" in service_name:
            for service in services:
                print "[+] Enumerating: " + service.product + ":" + str(service.port)
                rdp_enum.start(host.ip_address,service)
                

def start_nmap_internal_tcp_scan(host):
    utils.print_green("[+] Starting Nmap Internal TCP Scan ...")
    xml_file_path = 'temp/%s_tcp.xml' % host.ip_address
    nmap_tcp_command = "nmap -T4 -sS -sV -sC -p- -O --open --osscan-guess --version-all -oX '%s' %s" % (xml_file_path,host.ip_address)
    host = nmap_protocol_scan.execute_nmap(nmap_tcp_command,xml_file_path,'tcp',host)
    utils.print_purple("[+] Finished Nmap Internal TCP Scan ...")
    return host
    


def start_nmap_internal_udp_scan(host):
    utils.print_green("[+] Starting Nmap Internal UDP Scan ...")
    xml_file_path = 'temp/%s_udp.xml' % host.ip_address
    nmap_udp_command = "nmap -T4 -sU --top-ports 100 -oX '%s' %s" % (xml_file_path,host.ip_address)
    host = nmap_protocol_scan.execute_nmap(nmap_udp_command,xml_file_path,'udp',host)
    utils.print_purple("[+] Finished Nmap Internal UDP Scan ...")
    return host


def start_nmap_internal_scan(ip_address):
    host = HostDTO(ip_address)
    host = start_nmap_internal_tcp_scan(host)
    scan(host)
    host_udp = HostDTO(ip_address)
    host_udp = start_nmap_internal_udp_scan(host_udp)
    host.services_dic.update(host_udp.services_dic)
    host.udp_scan = host_udp.udp_scan
    
    report_creator = ReportCreator(host)
    report_creator.generate_report()
