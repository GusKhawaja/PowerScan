#!/usr/bin/env python

import subprocess
from libs.dto import EnumerationDTO
from multiprocessing import TimeoutError
import os
import io

# Common separator line for the application
separator_single_line = '------------------------------------------------------------'
separator_double_line = '============================================================'


def print_red(text): print("\033[91m {}\033[00m".format(text))


def print_green(text): print("\033[92m {}\033[00m".format(text))


def print_yellow(text): print("\033[93m {}\033[00m".format(text))


def print_purple(text): print("\033[95m {}\033[00m".format(text))


def extract_company_name(company_domain_name):
    return company_domain_name.split('.')[0]


# Description: Save the results to a file
# Return: (void)
def save_results(results, folder_name, file_name):
    try:
        # Save the results to a file
        file_name_path = folder_name + file_name

        if not os.path.isdir(folder_name):
            os.mkdir(folder_name)

        file_to_save = open(file_name_path, 'w')
        results = results.encode('utf-8')
        file_to_save.write(results)
        file_to_save.close()
    except Exception, e:
        exception_message = str(e)
        print_red('[!] Error: Cannot save the results to a file! Reason:\r\n' + exception_message)


# Description: Open and execute Linux Terminal command
# Return: (string) return the results output after executing the command
def execute_command(cmd):
    output = ''

    try:
        cmd = cmd.rstrip()
        output += subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        output += '\r\n'
    except Exception, e:
        exception_message = str(e)
        output += exception_message
        # [Exit Status 1] message means that application exited with status 1, we don't need to raise it as a red flag
        if 'exit status 1' not in exception_message:
            print_red("[!] Error executing the command: " + cmd + " Reason:\r\n" + exception_message)
        output += '\r\n'
    output += separator_single_line + '\r\n'

    output = output.replace('\n', '<br/>\n')

    return output

def open_file(path):
    output = ''
    try:
        with io.open(path, "r",encoding='utf-8', errors='replace') as file_contents:
            output = file_contents.read()
            
    except Exception,e:
        print_red('[!] Error opening the file: ' + str(e))
        
    output = output.replace('\n', '<br/>\n')
    return output

def execute_command1(cmd):
    try:
        os.system(cmd)
    except Exception, e:
        exception_message = str(e)
        print exception_message 

    
        


# Description: Execute an enum command
# Return: The output after command execution
def execute_enum_cmd(tool_name, cmd):
    start_msg = "[+] Starting %s ..." % tool_name
    print_green(start_msg)
    output = execute_command(cmd)
    end_msg = "[+] Finished %s ..." % tool_name
    print_purple(end_msg)
    return output

def execute_enum_cmd1(tool_name, cmd):
    start_msg = "[+] Starting %s ..." % tool_name
    print_green(start_msg)
    output = execute_command1(cmd)
    end_msg = "[+] Finished %s ..." % tool_name
    print_purple(end_msg)
    return output
