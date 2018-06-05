#!/usr/bin/env python
import io
from libs import utils

class VulnsSearch:

    def __init__(self, product, version):
        self.product = product
        self.version = version

    def __vuln_search(self):
        versioned_results = ''
        potential_results = ''
        
        with io.open(r'resources/vulns_merged.txt', "r",encoding='utf-8', errors='replace') as vulns_file_opened:
            for line in vulns_file_opened.readlines():
                #print line
                if self.product in line and self.version in line:
                    versioned_results += line
                elif self.product in line:
                    potential_results += line

        return versioned_results, potential_results

    def __get_product_name(self):
        if self.version is not None:
            full_name = self.product + " " + self.version
        else:
            full_name = self.product

        return full_name

    def __searchsploit(self):

        cmd = 'searchsploit ' + self.__get_product_name()
        output = utils.execute_command(cmd)

        return output

    def __search_metasploit(self):

        cmd = "service postgresql start && msfconsole -x 'search type:exploit name:%s; exit y'" % self.__get_product_name()
        output = utils.execute_command(cmd)

        return output

    def get_vulns(self):
        versioned_results, potential_results = self.__vuln_search()
        print '[+]Searching for vulnerabilities in: %s ' % self.__get_product_name()
        contents = "<h3>Metasploit</h3>"
        contents += '<br/>'
        contents += self.__search_metasploit()
        contents += '<br/>'
        contents += "<h3>SearchSploit</h3>"
        contents += '<br/>'
        contents += self.__searchsploit()
        contents += '<br/>'
        contents += "<h3>Potential Vulnerabilities</h3>"
        contents += '<br/>'
        contents += versioned_results
        contents += '<br/>'
        contents += "<h3>Less Potential Vulnerabilities</h3>"
        contents += '<br/>'
        contents += potential_results

        contents = contents.replace('\n', '<br/>\n')

        return contents
