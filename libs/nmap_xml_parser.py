from xml.dom import minidom
from libs.dto import *



class Nmap_XML_Parser:
    
    def __init__(self, xml_file_path):
        self.xml_file_path = xml_file_path
        
        
    def _hosts_iterator(self,xml_object):
        #Get the <host> tags from the XML file
        hosts_nodes = xml_object.getElementsByTagName("host")
        for host_node in hosts_nodes:
            yield(host_node)
                
            
    def _get_hostname(self,info):
        #Get the FQDN aka domain/hostname
        fqdn = str()
        info_detail = info.getElementsByTagName("hostname")
        for hostname in info_detail:
            if(hostname.getAttribute("name")): 
                fqdn = hostname.getAttribute("name")
                break
    
        return(fqdn)
            
    def _get_OS(self,info):
        #Determine the OS by the greatest percentage in accuracy
        os = str()
        os_hash = dict()
        percentage = list()
    
        info_detail = info.getElementsByTagName("osmatch")
    
        for os_detail in info_detail:
            guessed_os = os_detail.getAttribute("name")
            accuracy = os_detail.getAttribute("accuracy")
            if(guessed_os and accuracy):
                os_hash[float(accuracy)] = guessed_os
    
        percentages = os_hash.keys()
        if(percentages):
            max_percent = max(percentages)
            os = os_hash[max_percent]
    
        return(os)
            
    def _get_service_information(self,info):
        # Fetch port and service information
        info_detail = info.getElementsByTagName("port")
        for port_details in info_detail:
            protocol = port_details.getAttribute("protocol")
            port_number = port_details.getAttribute("portid")
    
            port_service = port_details.getElementsByTagName("state")
            for port_services in port_service:
                port_state = port_services.getAttribute("state")
    
                if(port_state == "open"):
    
                    service_info = port_details.getElementsByTagName("service")
                    for service_details in service_info:
                        service = service_details.getAttribute("name")
                        product = service_details.getAttribute("product")
                        version = service_details.getAttribute("version")
    
                        yield(port_number,protocol,service,product,version)  
                        
                        
    def parse_xml(self,host):
        # load xml file
        xml_object = minidom.parse(self.xml_file_path)
        host.services_dic = {}
            
        for info in self._hosts_iterator(xml_object):
            if host.computer_name is None:
                host_name = self._get_hostname(info)
                host.computer_name = host_name
            
            if host.os_info is None:
                os = self._get_OS(info)
                host.os_info = os
            
    
            for port,protocol,service,product,version in self._get_service_information(info):
                if (service == "http" and port == "443"):
                    service = "ssl/http" 
                    
                services_array = []
                service_object = ServiceDTO(service)
                
                service_object.protocol = protocol
                service_object.port = port
                service_object.product = product
                service_object.version = version
                
                
                if service in host.services_dic:
                    services_array = host.services_dic[service]
                    
                services_array.append(service_object)
                host.services_dic[service] = services_array 
                
        return host
                         
    