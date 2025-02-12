import os, csv
import pyshark
import argparse
import sys, datetime, time
from colorama import Fore, Back, Style
from collections import defaultdict
import re
from django.conf import settings

def packet_analysis(pcap_file):
    cap_pkt = pyshark.FileCapture(pcap_file)
    src_ip = set() #To store source IPs
    dst_ip = set() #To store destination IPs
    total_ips = set() #To store total IPs found
    total_pkts = 0 #Total packets found in PCAP
    progress_log = 'PROGRESS'
    info_log = 'INFO'
    error_log = 'ERROR'
    transfer_time_10 = 0
    transfer_time_100 = 0
    transfer_time_500 = 0
    prev_packet_time = None
    curr_time = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{curr_time}] [{progress_log}] Analyzing the PCAP File...")
    for packet in cap_pkt:
        src_ip.add(packet.ip.src)
        dst_ip.add(packet.ip.dst)
        total_ips.add(packet.ip.src)
        total_ips.add(packet.ip.dst)
        total_pkts += 1
        try: #Calculates the time between packets
            packet_time = packet.sniff_time
            packet_time_micro = packet_time.microsecond
            packet_time_milli = packet_time_micro // 1000
            if prev_packet_time is not None:
                diff = packet_time_milli - prev_packet_time
                if diff < 10:
                    transfer_time_10 += 1
                elif diff < 100 and diff > 10:
                    transfer_time_100 += 1
                elif diff < 500 and diff > 100:
                    transfer_time_500 += 1
            prev_packet_time = packet_time_milli
        except AttributeError:
            curr_time_except = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"[{curr_time_except}] [{error_log}] Failed Processing the Packet Time")
            continue

    cap_http = pyshark.FileCapture(pcap_file, display_filter="http")
    http_count = 0  # A counter to count the packets.
    for _ in cap_http:  # Loop to increment the counter.
        http_count += 1
    cap_http_get = pyshark.FileCapture(pcap_file, display_filter='http && http.request.method == "GET"')
    http_server = set()  # A set to add IP addresses of HTTP servers found.
    for packet in cap_http_get:  # Getting the Destination IP of the GET request.
        http_server.add(packet.ip.dst)
        server_list = list(http_server)

    cap_http.close()
    cap_http_get.close()

    curr_time_2 = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{curr_time_2}] [{info_log}] Total Packets in PCAP File: {total_pkts}")
    time.sleep(2)
    print(f"[{curr_time_2}] [{info_log}] Total IP Addresses Identified: {total_ips}")
    time.sleep(2)
    print(f"[{curr_time_2}] [{info_log}] Total HTTP Packets Identified: {http_count}")
    time.sleep(2)
    print(f"[{curr_time_2}] [{info_log}] List of HTTP Servers: {server_list}")
    time.sleep(2)
    print(f"[{curr_time_2}] [{info_log}] {transfer_time_10} Packets Transferred within 10MS")
    time.sleep(2)
    print(f"[{curr_time_2}] [{info_log}] {transfer_time_100} Packets Transferred within 100MS")
    time.sleep(2)
    print(f"[{curr_time_2}] [{info_log}] {transfer_time_500} Packets Transferred within 500MS")
    time.sleep(2)

# def http_packet_count(pcap_file): #This func will check number of HTTP packets found.
#     print(f"Analysing {pcap_file}")
#     cap_http = pyshark.FileCapture(pcap_file, display_filter="http")
#     packet_count = 0 #A counter to count the packets.
#     for _ in cap_http: #Loop to increment the counter.
#         packet_count += 1
#     cap_http_get = pyshark.FileCapture(pcap_file, display_filter='http && http.request.method == "GET"')
#     http_server = set() #A set to add IP addresses of HTTP servers found.
#     for packet in cap_http_get: #Getting the Destination IP of the GET request.
#         http_server.add(packet.ip.dst)
#         server_list = list(http_server)
#     print(f"There are total {packet_count} HTTP packets found!")
#     print(f"Found HTTP Server {server_list}")
#     cap_http.close()
#     cap_http_get.close()

def port_scan(pcap_file):
    cap_packet_syn_ack = pyshark.FileCapture(pcap_file, display_filter="tcp.flags.syn == 1 && tcp.flags.ack == 0")
    port_scan_src_ip = set()
    port_scan_dst_ports = set()
    prev_packet_time_syn = None
    syn_count_10 = 0
    syn_count_100 = 0
    syn_count_500 = 0
    common_ports_dst = set()
    ip_occ_syn = dict()
    progress_log = 'PROGRESS'
    info_log = 'INFO'
    error_log = 'ERROR'
    curr_time = datetime.datetime.now().strftime("%H:%M:%S")
    time.sleep(2)
    print("\n")
    print(f"[{curr_time}] [{progress_log}] Analysing Packets with SYN ACK Flags for Port Scanning Attempts...")
    for packet in cap_packet_syn_ack:
        port_scan_src_ip.add(packet.ip.src)
        port_scan_dst_ports.add(packet.tcp.dstport)
        try:  # Calculates the time between packets
            packet_time_syn = packet.sniff_time
            packet_time_micro_syn = packet_time_syn.microsecond
            packet_time_milli_syn = packet_time_micro_syn // 1000
            if prev_packet_time_syn is not None:
                diff = packet_time_milli_syn - prev_packet_time_syn
                if diff < 10:
                    syn_count_10 += 1
                elif diff < 100 and diff > 10:
                    syn_count_100 += 1
                elif diff < 500 and diff > 100:
                    syn_count_500 += 1
            prev_packet_time_syn = packet_time_milli_syn
        except AttributeError:
            curr_time_except = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"[{curr_time_except}] [{error_log}] Failed Processing the Packet Time")
            continue

        dst_port = int(packet.tcp.dstport)
        if 1 <= dst_port <= 1024:
            common_ports_dst.add(dst_port)
    cap_packet_syn_ack.close()

    for packet in cap_packet_syn_ack:
        for i in port_scan_src_ip:
            if i == packet.ip.src:
                ip_occ_syn.setdefault(i, 0)
                ip_occ_syn[i] += 1
    suspected_src_ip = max(ip_occ_syn, key=ip_occ_syn.get)
    cap_packet_syn_ack.close()
    curr_time_2 = datetime.datetime.now().strftime("%H:%M:%S")
    time.sleep(2)
    print(f"[{curr_time_2}] [{progress_log}] Analysing Packets with RST Flags for Port Scanning Attempts...")
    cap_packet_reset = pyshark.FileCapture(pcap_file, display_filter="tcp.flags.reset == 1")
    port_scan_dst_ip = set()
    port_scan_src_ports = set()
    rst_count_10 = 0
    rst_count_100 = 0
    rst_count_500 = 0
    ip_occ_rst = dict()
    common_ports_src = set()
    prev_packet_time_rst = None
    for packet in cap_packet_reset:
        port_scan_dst_ip.add(packet.ip.dst)
        port_scan_src_ports.add(packet.tcp.srcport)
        try:  # Calculates the time between packets
            packet_time_rst = packet.sniff_time
            packet_time_micro_rst = packet_time_rst.microsecond
            packet_time_milli_rst = packet_time_micro_rst // 1000
            if prev_packet_time_rst is not None:
                diff = packet_time_milli_rst - prev_packet_time_rst
                if diff < 10:
                    rst_count_10 += 1
                elif diff < 100 and diff > 10:
                    rst_count_100 += 1
                elif diff < 500 and diff > 100:
                    rst_count_500 += 1
            prev_packet_time_rst = packet_time_milli_rst
        except AttributeError:
            curr_time_except_2 = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"[{curr_time_except_2}] [{error_log}] Failed Processing the Packet Time")
            continue

        src_port = int(packet.tcp.srcport)
        for i in range(1, 1025):
            if i == src_port:
                common_ports_src.add(src_port)

    for packet in cap_packet_reset:
        for i in port_scan_dst_ip:
            if i == packet.ip.dst:
                ip_occ_rst.setdefault(i, 0)
                ip_occ_rst[i] += 1
    cap_packet_reset.close()
    suspected_dst_ip = max(ip_occ_rst, key=ip_occ_rst.get)

# ----------------------------------------------------------------------------------------------------------------
    curr_time_3 = datetime.datetime.now().strftime("%H:%M:%S")
    time.sleep(2)
    print(f"[{curr_time_3}] [{info_log}] Possible Port Scan Attempt")
    time.sleep(2)
    print(f"[{curr_time_3}] [{info_log}] Source of the Port Scan: {suspected_src_ip}")
    time.sleep(2)
    print(f"[{curr_time_3}] [{info_log}] Common Ports Scanned: {common_ports_src}")
    time.sleep(2)
    print(f"[{curr_time_3}] [{info_log}] There are total {syn_count_10} SYN-ACK Packets Identified with less than 10 Milli Sec Transfer Time.")
    time.sleep(2)
    print(f"[{curr_time_3}] [{info_log}] There are total {rst_count_10} RST Packets Identified with less than 10 Milli Sec Transfer Time.")
# ----------------------------------------------------------------------------------------------------------------

def brute_force_activity(pcap_file, threshold=10):
    cap_packet = pyshark.FileCapture(pcap_file, display_filter='http && http.request.method=="GET"')
    columns = ['request_method', 'request_uri', 'user_agent', 'time']
    prev_pkt_time = None
    time_diff_count = 0
    info_log = 'INFO'
    progress_log = 'PROGRESS'
    error_log = 'ERROR'
    time.sleep(2)
    print("\n")
    curr_time = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{curr_time}] [{progress_log}] Analysing HTTP Directory or File Brute Force Attempts...")
    with open('http_bruteforce_data.csv', mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        curr_time = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"[{curr_time}] [{progress_log}] Collecting Information [Request URI, Packet Time Frame and User Agent]")
        for packet in cap_packet:
            request_method = packet.http.request_method
            request_uri = packet.http.request_uri
            user_agent = packet.http.user_agent
            packet_time = packet.sniff_time

            if prev_pkt_time is not None:
                time_diff = (packet_time - prev_pkt_time).total_seconds() * 1000
                if time_diff < 100:
                    time_diff_count += 1
            else:
                time_diff = 0
            prev_pkt_time = packet_time
            writer.writerow({
                'request_method': request_method,
                'request_uri': request_uri,
                'user_agent': user_agent,
                'time': time_diff
            })
    cap_packet.close()

    if time_diff_count > 1000:
        time.sleep(2)
        curr_time = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"[{curr_time}] [{info_log}] There are {time_diff_count} Packets Found Indicating Brute Force Attempt!")
        time.sleep(2)
        curr_time = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"[{curr_time}] [{info_log}] Check 'http_bruteforce_data.csv' File for Detailed Report.")
    else:
        curr_time = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"[{curr_time}] [{info_log}] No Directory or File Brute Force Patterns Detected, Check 'http_bruteforce_data.csv' File for Detailed Analysis.")

    curr_time_4 = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{curr_time_4}] [{progress_log}] Analysing HTTP Login Page Brute Force Attempts...")
    login_brute_force = dict()
    cap_packet_login = pyshark.FileCapture(pcap_file, display_filter='http.request.method == "POST"')
    for packet in cap_packet_login:
        post_request_uri = packet.http.request_uri
        login_brute_force[post_request_uri] = login_brute_force.get(post_request_uri, 0) + 1
    if login_brute_force:
        targeted_uri = max(login_brute_force, key=login_brute_force.get)
        curr_time = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"[{curr_time}] [{info_log}] Targeted Web Page for the Login Brute Force: {targeted_uri}")
    else:
        curr_time = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"[{curr_time}] [{info_log}] No login page brute force attempts found!")

if __name__ == '__main__':
    pcap_filename = 'small.pcap'  # Replace with the actual PCAP file name you want to process
    pcap_file = os.path.join(settings.MEDIA_ROOT, 'pcap_files', pcap_filename)

    packet_analysis(pcap_file)
    port_scan(pcap_file)
    brute_force_activity(pcap_file)
