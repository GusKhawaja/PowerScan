from libs.dto import *
from libs import utils


class ReportCreator:
    global_counter = 1
    def __init__(self, host):
	self.host = host

    def generate_report(self):
	print '[+]Generating Report...'
	page_contents = self.__create_page_html()

	# Save The report
	self.__save_report(page_contents)

    def __save_report(self, contents):
	folder_name = 'reports/'
	file_name = self.host.ip_address + '.html'
	utils.save_results(contents, folder_name, file_name)
	utils.print_purple("The Report is saved under: " + folder_name)

    def __create_html_header(self):
	head_contents = "<head>" \
	    "<title>Power Scan</title>" \
	    "<!-- Required meta tags -->" \
	    "<meta charset='utf-8'>" \
	    "<meta name='viewport' content=width=device-width, initial-scale=1, shrink-to-fit=no>" \
	    "<!-- Bootstrap CSS -->" \
	    "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta.2/css/bootstrap.min.css' integrity='sha384-PsH8R72JQ3SOdhVi3uxftmaW6Vc51MKb0q5P2rRUpPvrszuE4W1povHYgTpBfshb' crossorigin='anonymous'>" \
	    "</head>"
	return head_contents

    def __create_nav(self):
	nav_title = 'Power Scan Report'
	nav_contents = "<nav class='navbar navbar-dark bg-dark'>" \
	    "<a class='navbar-brand' href='#'>%s</a>" \
	    "</nav>" % nav_title
	return nav_contents

    def __create_host_table(self):
	host_table_contents = "<table class='table'>" \
	    "<thead class='thead-dark'>" \
	    "<tr>" \
	    "<th scope='col'>Computer Name</th>" \
	    "<th scope='col'>IP Address</th>" \
	    "<th scope='col'>OS Info</th>" \
	    "</tr>" \
	    "</thead>" \
	    "<tbody>" \
	    "<tr>" \
	    "<td scope='row'>%s</td>" \
	    "<td>%s</td>" \
	    "<td>%s</td>" \
	    "</tr>" \
	    "</tbody>" \
	    "</table>" % (self.host.computer_name, self.host.ip_address, self.host.os_info)

	return host_table_contents

    def __create_services_summary_rows(self):
	rows = ''

	for service_name in self.host.services_dic:
	    services = self.host.services_dic[service_name]
	    for service in services:
		rows += "<tr><td scope='row'>%s</td><td>%s</td></tr>" % (
		    service_name + ':' + service.port, service.product + " version " + service.version)

	return rows

    def __create_services_summary_table(self):
	services_summary_table_contents = "<!-- Services Summary -->" \
	    "<table class='table'>" \
	    "<thead class='thead-dark'>" \
	    "<tr><th scope='col'>Services Found</th><th scope='col'>Description</th></tr>" \
	    "</thead>" \
	    "<tbody>%s</tbody>" \
	    "</table>" % self.__create_services_summary_rows()

	return services_summary_table_contents

    def __create_tcp_scan_table(self):
	tcp_scan_table_contents = "<!-- NMAP TCP Scan -->" \
	    "<table class='table'>" \
	    "<thead class='thead-dark'>" \
	    "<tr><th scope='col'>NMAP TCP Scan Results</th></tr>" \
	    "</thead>" \
	    "<tbody><tr><td scope='row'>%s</td></tr></tbody>" \
	    "</table>" % self.host.tcp_scan
	return tcp_scan_table_contents

    def __create_udp_scan_table(self):
	udp_scan_table_contents = "<!-- NMAP UDP Scan -->" \
	    "<table class='table'>" \
	    "<thead class='thead-dark'>" \
	    "<tr><th scope='col'>NMAP UDP Scan Results</th></tr>" \
	    "</thead>" \
	    "<tbody><tr><td scope='row'>%s</td></tr></tbody>" \
	    "</table>" % self.host.udp_scan
	return udp_scan_table_contents

    def __create_service_enum_rows(self,service):
	enums = ''
	

	if not (service.enumeration_list is None):
	    for enum in service.enumeration_list:
		row_contents = "<tr><td scope='row'><div id='accordion%s' role='tablist'><div class='card'>" \
		    "<div class='card-header' role='tab' id='heading%s'>" \
		    "<h5 class='mb-0'>" \
		    "<a class='collapsed' data-toggle='collapse' href='#collapse%s' role='button' aria-expanded='false' aria-controls='collapse%s'>%s</a></h5></div>" \
		    "<div id='collapse%s' class='collapse' role='tabpanel' aria-labelledby='heading%s' data-parent='#accordion%s'>" \
		    "<div class='card-body'>%s</div></div></div></div></td></tr>" % (
			self.global_counter, self.global_counter, self.global_counter, self.global_counter, enum.tool_name,
			self.global_counter, self.global_counter, self.global_counter, enum.results_output)
	    
		self.global_counter = self.global_counter + 1
		enums += row_contents	    

	return enums

    def __create_service_enum_table(self, service):
	service_table_contents = "<table class='table'>" \
	    "<thead class = 'thead-dark'>" \
	    "<tr><th scope='col'> %s</th></tr>" \
	    "</thead>" \
	    "<tbody>%s</tbody>" \
	    "</table>" % (service.name + ':' + service.port, self.__create_service_enum_rows(service))
	return service_table_contents

    def __create_services_enum_tables(self):
	enum_tables = ''

	for service_name in self.host.services_dic:
	    services = self.host.services_dic[service_name]
	    for service in services:
		enum_tables += self.__create_service_enum_table(service)

	return enum_tables

    def __create_page_bottom(self):
	bottom_contents = "</div><!-- Optional JavaScript --><!-- jQuery first, then Popper.js, then Bootstrap JS -->" \
	    "<script src='https://code.jquery.com/jquery-3.2.1.slim.min.js' integrity='sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/GpGFF93hXpG5KkN' crossorigin='anonymous'></script>" \
	    "<script src='https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.3/umd/popper.min.js' integrity='sha384-vFJXuSJphROIrBnz7yo7oB41mKfc8JzQZiCq4NCceLEaO4IHwicKwpJf9c9IpFgh' crossorigin='anonymous'></script>" \
	    "<script src='https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta.2/js/bootstrap.min.js' integrity='sha384-alpBpkh1PFOepccYVYDB4do5UnbKysX5WZXm3XxPqe5iKTfUKjNkCk9SaVuEZflJ' crossorigin='anonymous'></script>" \
	    "</body></html>"
	return bottom_contents

    def __create_page_html(self):
	page_contents = "<!doctype html><html lang='en'>" + self.__create_html_header() + \
	    "<body>" + self.__create_nav() + "<div class='container'><!-- Content here --><h1>Host " + self.host.ip_address+ "</h1>" + \
	    self.__create_host_table() + self.__create_services_summary_table() + self.__create_tcp_scan_table() + \
	    self.__create_udp_scan_table() + self.__create_services_enum_tables() + self.__create_page_bottom()

	return page_contents
