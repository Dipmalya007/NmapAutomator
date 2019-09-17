#!/usr/bin/env python

__author__ = 'Dipmalya Pyne'
__date__ = '201911709'
__version__ = '0.01'
__description__ = 'This tool aims at automating Nmap for active IP scanning to the maximum possible limit!'

import nmap
import socket
import sys
import re
import xml.etree.ElementTree as etree
import os
import csv


def get_host_data(root):
    """Traverses the xml tree and build lists of scan information
    and returns a list of lists.
    """
    host_data = []
    hosts = root.findall('host')
    for host in hosts:
        addr_info = []

        # Ignore hosts that are not 'up'
        if not host.findall('status')[0].attrib['state'] == 'up':
            continue

        # Get IP address and host info. If no hostname, then ''
        ip_address = host.findall('address')[0].attrib['addr']
        host_name_element = host.findall('hostnames')
        try:
            host_name = host_name_element[0].findall('hostname')[0].attrib['name']
        except IndexError:
            host_name = ''

        # Get the OS information if available, else ''
        try:
            os_element = host.findall('os')
            os_name = os_element[0].findall('osmatch')[0].attrib['name']
        except IndexError:
            os_name = ''

        # Get information on ports and services
        try:
            port_element = host.findall('ports')
            ports = port_element[0].findall('port')
            for port in ports:
                port_data = []
                if not port.findall('state')[0].attrib['state'] == 'open':
                    continue
                proto = port.attrib['protocol']
                port_id = port.attrib['portid']
                service = port.findall('service')[0].attrib['name']

                # Create a list of the port data
                port_data.extend((ip_address, host_name, os_name,
                                  proto, port_id, service))

                # Add the port data to the host data
                host_data.append(port_data)

        # If no port information, just create a list of host information
        except IndexError:
            addr_info.extend((ip_address, host_name))
            host_data.append(addr_info)
    return host_data


def parse_xml(filename):
    """Given an XML filename, reads and parses the XML file and passes the
    the root node of type xml.etree.ElementTree.Element to the get_host_data
    function, which will futher parse the data and return a list of lists
    containing the scan data for a host or hosts."""
    try:
        tree = etree.parse(filename)
    except Exception as error:
        print("[-] A an error occurred. The XML may not be well formed. "
              "Please review the error and try again: {}".format(error))
        exit()
    root = tree.getroot()
    scan_data = get_host_data(root)
    return scan_data


def parse_to_csv(data, csv_name):
    """Given a list of data, adds the items to (or creates) a CSV file."""
    if not os.path.isfile(csv_name):
        csv_file = open(csv_name, 'w', newline='')
        csv_writer = csv.writer(csv_file)
        top_row = ['IP', 'Host', 'OS', 'Protocol', 'Port', 'Service']
        csv_writer.writerow(top_row)
        print('\n[+] The file {} does not exist. New file created!\n'.format(
            csv_name))
    else:
        try:
            csv_file = open(csv_name, 'w', newline='')
        except PermissionError as e:
            print("\n[-] Permission denied to open the file {}. "
                  "Check if the file is open and try again.\n".format(csv_name))
            print("Print data to the terminal:\n")

        csv_writer = csv.writer(csv_file)
        top_row = ['IP', 'Host', 'OS', 'Protocol', 'Port', 'Service']
        csv_writer.writerow(top_row)
        print('\n[+] {} exists. Overwriting to file!\n'.format(csv_name))
    for item in data:
        csv_writer.writerow(item)
    csv_file.close()


def main(filename, csv_name):
    data = parse_xml(filename)
    if not data:
        print("[*] Zero hosts identified as 'Up' or with 'open' ports. "
              "Exiting.")
        sys.exit(0)
    else:
        parse_to_csv(data, csv_name)


# def take_screenshot():
#   """This module is for taking screenshot"""
#  filepath_screenshot = input("Enter the path where you want the files to be saved: ")
# if os.path.exists(filepath_screenshot):
#       d = datetime.datetime.now()
#      try:
#         file_name = os.path.join(filepath_screenshot+str(d)+".png")
#        print(file_name)
#         pyautogui.screenshot(file_name)
#    except:
#       print("File Error!!")
# else:

#    print("The path does not exist!!")

def scan(ip_addr, continueflag):
    """For the actual Nmap Scan"""
    while continueflag == 0:
        try:

            scanner = nmap.PortScanner()

            print("The Nmap Version used is: ", scanner.nmap_version())

            resp = input("Please enter the type of scan you want to run"
                         "\n\t1: ICMP Echo Scan"
                         "\n\t2: TCP Comprehensive Scan"
                         "\n\t3: UDP Comprehensive Scan"
                         "\n\t4: Full Port Scan"
                         "\n")

            if resp == '1':
                scanner.scan(hosts=ip_addr, arguments='-sn -PE -vvv')
                hosts_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
                print("The IPs responding to Ping Scan are:")
                for host, status in hosts_list:
                    print(host + ' is ' + status)

            elif resp == '2':
                args = input("Please input the arguments for the scan:")
                print("\t\t\tScanning....\t\t\t")
                scanner.scan(hosts=ip_addr, arguments=args)
                f = open("TCPoutput.xml", "w")
                f.write(scanner.get_nmap_last_output())
                f.close()
                main("TCPoutput.xml", "Output_TCP.csv")

            elif resp == '3':
                args = input("Please input the arguments for the scan:")
                print("\t\t\tScanning....\t\t\t")
                scanner.scan(ip_addr, '7,9,11,53,67-69,111,123,135,137-139,161,191-192,256,260,445,500,514,520', args)
                f = open("UDPoutput.xml", "w")
                f.write(scanner.get_nmap_last_output())
                f.close()
                main("UDPoutput.xml", "Output_UDP.csv")

            elif resp == '4':
                print("\t\t\tScanning....\t\t\t")
                scanner.scan(ip_addr, '0-65535', '-Pn')
                f = open("FullPortScan.xml", "w")
                f.write(scanner.get_nmap_last_output())
                f.close()

            else:
                print("Wrong Input Observed!!Please correct")

        except nmap.PortScannerError:
            print("Nmap Not Installed", sys.exc_info[0])
            sys.exit(0)
        except:
            print("Unknown Error!!")
            sys.exit(0)

        cont = input("Do you want to continue?Press y to continue...\t")
        if cont == 'y' or cont == 'Y':
            continueflag = 0
        else:
            continueflag = 1


yes_read_file = input("Do you want to read from a file? Press y to read from a file!!")
if yes_read_file == 'y' or yes_read_file == 'Y':
    ip_final = ''
    ip_addr = ''
    file_path = input("Please specify the full path of the file that needs to be read!!")
    regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''
    if os.path.exists(file_path):
        ip_address = open(file_path, 'r').read().split('\n')
        for ip_add in ip_address:
            if not ip_add == '0.0.0.0':
                if re.search(regex, ip_add):
                    ip_final = ip_final + ' ' + ip_add
                else:
                    try:
                        ip_soc = socket.gethostbyname(ip_add)
                        ip_final = ip_final + ' ' + ip_soc
                    except:
                        print(ip_add + " is not correctly formatted!!")

    ip_addr = ip_final.replace('0.0.0.0','').replace('1.0.0.1','')
    if not ip_addr == '':
        print(ip_addr)
        scan(ip_addr, 0)
    else:
        print("Nothing to Scan!!")


else:
    ip_addr = '0.0.0.0'
    ip_final = ''
    ip_finally = ''
    while ip_addr == '0.0.0.0':
        ip_addr = input("Please enter the IP address or hostname you want to scan: ")
        regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''
        ip_address = ip_addr.split(' ')
        for ip_add in ip_address:
            if re.search(regex, ip_add):
                ip_final = ip_final + ' ' + ip_add
            else:
                try:
                    ip_soc = socket.gethostbyname(ip_add)
                    ip_final = ip_final + ' ' + ip_soc
                except:
                    print(ip_add + " is not correctly formatted!!")

    ip_finally = ip_final.replace('0.0.0.0','').replace('1.0.0.1','')
    if not ip_finally == '':
        scan(ip_finally, 0)
    else:
        print("Nothing to Scan!!")
