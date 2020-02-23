#! /user/bin/python3
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import sys
from datetime import datetime
from time import strftime
protocol = ""
try:
   target = input("[*] Enter Target IP Address: ")
   while protocol != "t" and protocol != "u" and protocol != "i":
      protocol = input("[*] Enter Target Protocol: (i)cmp (u)dp or (t)cp: ").lower()
   min_port = input("[*] Enter Minimum Port Number: ")
   max_port = input("[*] Enter Maximum Port Number: ")
   try:
      if int(min_port) >= 0 and int(max_port) >= 0 and int(max_port) >= int(min_port):
         pass
      else:
         print("\n[!] Invalid Port Range")
         print("[!] Exiting...")
         sys.exit(1)
   except Exception:
      print("\n[!] Invalid Port Range")
      print("[!] Exiting...")
      sys.exit(1)
except KeyboardInterrupt:
   print("[!] Requested Shutdown")
ports = range(int(min_port),int(max_port)+1)
start_clock = datetime.now()
SYNACK = 0x12
RSTACK = 0x14
def host_reachable(ip):
   conf.verb = 0
   try:
      ping = sr1(IP(dst = ip)/ICMP(),timeout=1)
      print("\n[*] Host Reachable via ICMP")
   except Exception:
      print("\n[!] Couldn't resolve target, Exiting.")
      sys.exit(1)
def scanport(port): 
  try:
    src_port = RandShort()
    tcp_connect_scan_resp = sr1(IP(dst=target)/TCP(sport=src_port,dport=port,flags="S"),timeout=1)
    if(tcp_connect_scan_resp == None):
        return "Closed"
    elif(tcp_connect_scan_resp.haslayer(TCP)):
        if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=target)/TCP(sport=src_port,dport=port,flags="AR"),timeout=1)
            return "Open"
        elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
            return "Closed"
    else:
        return "CHECK"       
  except KeyboardInterrupt: 
       RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, timeout=1, flags = "R") 
       send(RSTpkt) 
       print( "\n[*] User Requested Shutdown...")
       print ("[*] Exiting...")
       sys.exit(1)
#Adapted from https://github.com/interference-security/Multiport/blob/master/multiport.py
def udp_scan(dst_ip,dst_port):
  try:
    udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=2)
    if (udp_scan_resp == None):
        retrans = []
        for count in range(0,3):
            retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=2))
        for item in retrans:
            if ((item)!= None):
                udp_scan(dst_ip,dst_port)
        return "Open|Filtered"
    elif(udp_scan_resp.haslayer(UDP)):
        return "Open"
    elif(udp_scan_resp.haslayer(ICMP)):
        if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
            return "Closed"
        elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
            return "Filtered"
    else:
        return "CHECK"
  except KeyboardInterrupt:
    RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, timeout=1, flags = "R") 
    send(RSTpkt) 
    print( "\n[*] User Requested Shutdown...")
    print ("[*] Exiting...")
    sys.exit(1)
host_reachable(target) 
if protocol == "i":
   print("ICMP Scan Complete.")
   sys.exit(1)
print("[*] Scanning Started at " + strftime("%H:%M:%S") + "!\n")
for port in ports: 
   if protocol == "t":
      status = scanport(port) 
      if status == "Open": 
         print ("Port " + str(port) + ": Open" )
   elif protocol == "u":
      srcport = RandShort()
      ans = udp_scan(target, port)
      if ans == "Open":
         print ("Port " + str(port) + ": Open" )
      elif ans == "Open|Filtered":
         print ("Port " + str(port) + ": Open|Filtered" )     
stop_clock = datetime.now()
total_time = stop_clock - start_clock 
print ("\n[*] Scanning Finished!")
print("[*] Total Scan Duration: " + str(total_time))
