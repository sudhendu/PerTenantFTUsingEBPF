#!/usr/bin/env python
# coding: utf-8

import sys
from socket import inet_ntop, AF_INET, AF_INET6
from bcc import BPF
import ctypes as ct
import subprocess
from struct import pack
import time
import collections
import copy

# IFNAMSIZ defined in uapi/linux/if.h
IFNAMSIZ = 16

requestTable = collections.OrderedDict()
averages = collections.OrderedDict()
i = 0
firstEntry = ""
readingCount = 0

# Event structure that gets mapped to 'route_evt_t' event structure in tracepkt.c
class TestEvt(ct.Structure):
    _fields_ = [
        # Routing information
        ("ifname",  ct.c_char * IFNAMSIZ),
        ("netns",   ct.c_ulonglong),
        ("func_name", ct.c_char * 100),
	("ts", ct.c_ulonglong),

        # Packet type (IPv4 or IPv6) and address
        ("ip_version",  ct.c_ulonglong),
        ("icmptype",    ct.c_ulonglong),
        ("icmpid",      ct.c_ulonglong),
        ("icmpseq",     ct.c_ulonglong),
        ("saddr",       ct.c_ulonglong * 2),
        ("daddr",       ct.c_ulonglong * 2),
    ]

PING_PID="-1"

# requestTable list indexes are mapped as follows
# requestTable[interfaceName][0] -> net_dev_queue call made on the interface
# requestTable[interfaceName][1] -> netif_rx call made on the interface
# requestTable[interfaceName][2] -> net_dev_start_xmit call made on the interface
# requestTable[interfaceName][3] -> net_dev_xmit call made on the interface
def compute(firstEntry):
    global readingCount
    readingCount = readingCount + 1
    entry = 0
    previousEntryOfRequestTable = copy.deepcopy(requestTable[firstEntry])
    previousEntry = firstEntry
    currentEntryOfRequestTable = []
    for key in requestTable:
        # Check to ignore first entry in the dictionary
        if entry != 0:
            currentEntryOfRequestTable = copy.deepcopy(requestTable[key])
            averageKey = previousEntry + key
            currentSum = 0
            if averageKey in averages:
                currentSum = averages[averageKey]
            else:
                currentSum = 0
            if currentEntryOfRequestTable[0] == 0:  # ingress (traversed interface and received it)
                if previousEntryOfRequestTable[3] != 0:
                    currentSum = currentSum + currentEntryOfRequestTable[1] - previousEntryOfRequestTable[3]
                    print("veth pair: ", currentEntryOfRequestTable[1] - previousEntryOfRequestTable[3]) # netif_rx - net_dev_xmit
                else:
                    currentSum = currentSum + currentEntryOfRequestTable[1] - previousEntryOfRequestTable[2]
                    print("veth pair: ", currentEntryOfRequestTable[1] - previousEntryOfRequestTable[2]) # netif_rx - net_dev_start_xmit
            elif currentEntryOfRequestTable[3] != 0:    # net_dev_xmit value present
                currentSum = currentSum + currentEntryOfRequestTable[3] - previousEntryOfRequestTable[1]
                print("Device: ", currentEntryOfRequestTable[3] - previousEntryOfRequestTable[1]) # net_dev_xmit - netif_rx
            else:   # net_dev_xmit not present, use net_dev_start_xmit
                currentSum = currentSum + currentEntryOfRequestTable[2] - previousEntryOfRequestTable[1]
                print("Device: ", currentEntryOfRequestTable[2] - previousEntryOfRequestTable[1]) # net_dev_start_xmit - netif_rx
            averages[averageKey] = currentSum
            #print(averages[averageKey])
            for index in range(4):
                previousEntryOfRequestTable[index] = currentEntryOfRequestTable[index]
                index = index + 1
            previousEntry = key
        else:   # Just increment the value so that all values from second ownwards are considered
            entry = entry + 1



def event_printer(cpu, data, size):
    global i
    global firstEntry
    global readingCount
    # Decode event
    event = ct.cast(data, ct.POINTER(TestEvt)).contents

    # Decode address
    if event.ip_version == 4:
        saddr = inet_ntop(AF_INET, pack("=I", event.saddr[0]))
        daddr = inet_ntop(AF_INET, pack("=I", event.daddr[0]))
    else:
        return

    # Decode direction
    if event.icmptype in [8, 128]:
        direction = "request"
    elif event.icmptype in [0, 129]:
        direction = "reply"
    else:
        direction = "tunnel"    # Will be needed to see VxLAN encapsulated packets too

    # Print event
    print "[%12s] %16s %7s %s -> %s %s \t%d" % (event.netns, event.ifname, direction, saddr, daddr, event.func_name, event.ts)

    if direction == "request" or direction == "tunnel":
        if i == 0:
            firstEntry = event.ifname
            print(firstEntry)
            i = i + 1
        i = 1
        if event.ifname not in requestTable:
            requestTable[event.ifname] = [0, 0, 0, 0]

        if event.func_name == "net_dev_queue":
            requestTable[event.ifname][0] = event.ts
        elif event.func_name == "netif_rx":
            requestTable[event.ifname][1] = event.ts
        elif event.func_name == "net_dev_start_xmit":
            requestTable[event.ifname][2] = event.ts
        elif event.func_name == "net_dev_xmit":
            requestTable[event.ifname][3] = event.ts

        #tempDict = {}
        #tempDict[event.func_name] = event.ts
        #requestTable[event.ifname] = requestTable.get(event.ifname, {})
        #requestTable[event.ifname][event.func_name] = tempDict[event.func_name]
        #print(requestTable[event.ifname])
        #print(len(requestTable[event.ifname]))
    elif i == 1:
        compute(firstEntry)
        i = i + 1

    if readingCount == 100:
        for key in averages:
            totalSum = averages[key]
            averages[key] = totalSum / 100
            print("Average with key ", key, averages[key])
        readingCount = 0

    #for key, value in requestTable.iteritems():
    #    print(key, value)

if __name__ == "__main__":
    i = 0
    # Build probe and open event buffer
    b = BPF(src_file='tracepkt.c')
    b["route_evt"].open_perf_buffer(event_printer)

    print "%14s %16s %7s %s \t \t   %s \t%14s" % ('NETWORK NS', 'INTERFACE', 'TYPE', 'ADDRESSES', 'FUNCTION NAME', 'TIMESTAMP')

    # Keep listening for events (whenever a function attached to a tracepoint gets called)
    while True:
        b.kprobe_poll()

    # Forward ping's exit code
    sys.exit(ping.poll())
