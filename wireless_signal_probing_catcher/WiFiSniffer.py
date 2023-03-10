#!/usr/bin/python

import sys
from scapy.all import *
from optparse import OptionParser

interface = '<iface_name>'
probeReqs = []
def sniffProbe(p):
   #print p.show2()
   #print -(256-ord(p.notdecoded[-4:-3]))
   #print p.addr2
   #print p.getlayer(Dot11ProbeReq).addr2
   if p.haslayer(Dot11ProbeReq):
      netName = p.getlayer(Dot11ProbeReq).info
      if netName not in probeReqs:
         probeReqs.append(netName)
         print '[+] Detected New Probe Request: ' + netName
sniff(iface=interface, prn=sniffProbe)


hiddenNets = []
unhiddenNets = []
def sniffDot11(p):
   if p.haslayer(Dot11ProbeResp):
      addr2 = p.getlayer(Dot11).addr2
      if (addr2 in hiddenNets) & (addr2 not in unhiddenNets):
         netName = p.getlayer(Dot11ProbeResp).info
         print '[+] Decloaked Hidden SSID: ' + netName + ' for MAC: ' + addr2
         unhiddenNets.append(addr2)
   if p.haslayer(Dot11Beacon):
      if p.getlayer(Dot11Beacon).info == '':
         addr2 = p.getlayer(Dot11).addr2
         if addr2 not in hiddenNets:
            print '[-] Detected Hidden SSID with MAC: ' + addr2
            hiddenNets.append(addr2)
sniff(iface=interface, prn=sniffDot11)
