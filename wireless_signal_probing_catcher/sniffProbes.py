#!/usr/bin/env python3

import sys
from scapy.all import *
from optparse import OptionParser

interface = ''
probeReqs = []

#TODO:
#def enableMonitorMode(iface):
   #iface

def sniffProbe(p):
   #print p.show2()
   #print -(256-ord(p.notdecoded[-4:-3]))
   #print p.addr2
   #print p.getlayer(Dot11ProbeReq).addr2
   if p.haslayer(Dot11ProbeReq):
      netName = p.getlayer(Dot11ProbeReq).info
      if netName not in probeReqs:
         probeReqs.append(netName)
         netName = str(netName).strip('b\'')
         if( netName != None and netName != '' ):
            print('[+] Detected New Probe Request: ' + str(netName))

def main():
   print(interface)
   sniff(iface=interface, prn=sniffProbe)

if __name__ == '__main__':
   parser = OptionParser()
   parser.add_option("-i", "--interface", dest="interface",
                  help="interface for monitoring", metavar="INTERFACE")

   (options, args) = parser.parse_args()

   interface = options.interface
   #exit(0)

   main()
