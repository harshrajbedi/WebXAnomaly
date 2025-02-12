# WebXAnomaly
WebXAnomaly tool is a PCAP analysis tool to detect unusual network patterns including port scans and web brute forcing, allows investigators to quickly identify and investigate malicious network activities.
## Description
WebXAnomaly is a project developed to detect unusual network patterns in web server’s network traffic by analysing PCAP file. This tool extracts data such as Total number of packets and IP addresses, List of HTTP servers and List of User Agents.  
WebXAnomaly can detect port scanning activities along with the identification of source of the port scan, scanned ports, total number of packets sent within less than 10 Milli seconds of time frame. For the detection of port scan, SYN-ACK and RST packets are examined.
Directory and File Brute Forcing activities are also be detected using this tool. WebXAnomaly extracts data such as request url, request uri, request method, user agent and time between consecutive packets.
