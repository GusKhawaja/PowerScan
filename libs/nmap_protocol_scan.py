#!/usr/bin/env python

from libs import utils
from libs.dto import *
from xml.dom import minidom
from libs.nmap_xml_parser import Nmap_XML_Parser


def execute_nmap(command,xml_file_path,protocol,host):
    output = utils.execute_command(command)
    nmap_scan = None
    
    if protocol == 'tcp':
        nmap_scan = parse_xml_output(xml_file_path,host)
        nmap_scan.tcp_scan = output
        
    else:#udp
        nmap_scan = parse_xml_output(xml_file_path,host)
        nmap_scan.udp_scan = output

        
    return nmap_scan




def parse_xml_output(xml_file_path,host):
    nmap_xml_parser = Nmap_XML_Parser(xml_file_path)
    return nmap_xml_parser.parse_xml(host)
            
            
        
            
     
            
    
    
