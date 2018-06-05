class HostDTO:
    computer_name = None
    os_info = None
    services_dic = None
    tcp_scan = None
    udp_scan = None
    
    def __init__(self, ip_address):  
        self.ip_address = ip_address

        
class EnumerationDTO:
    results_output = None
    
    def __init__(self ,tool_name):
        self.tool_name = tool_name
      
class ServiceDTO:
    enumeration_list = None
    protocol = None
    port = None
    product = None
    version = None
    
    def __init__(self ,name):
        self.name = name     
        