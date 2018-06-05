#!/usr/bin/env python

from core import internal_scanner
from libs import utils


def start_internal_scan(ip_address):
    print 'You have chosen to scan %s internally' % ip_address
    print utils.separator_double_line
    internal_scanner.start_nmap_internal_scan(ip_address)
    print utils.separator_double_line
    utils.print_purple('[100%] Finished Internal Scan')


def start_external_scan(ip_address):
    print 'You have chosen to scan %s externally' % ip_address
    print 'NOT IMPLEMENTED YET'


def main():
    #try:
    print 'Welcome to PowerScan Let\'s Start'
    print utils.separator_double_line
    print 'What is the IP address that you want to scan:'
    ip_address = raw_input("IP>")
    start_internal_scan(ip_address)
    #print 'Perfect! We got the IP address, now you have two choices:'
    #print '1- Internal Scan'
    #print '2- External Scan (Not Supported)'
    #scan_choice = raw_input("Choice>")

    #if scan_choice == "1":
        #start_internal_scan(ip_address)
    #elif scan_choice == "2":
        #start_external_scan(ip_address)
    #else:
        #utils.print_red("[!]Invalid entry")
        #exit(1)
    #except Exception,e:
        #utils.print_red(str(e))
        #exit(1)


if __name__ == '__main__':
    main()
