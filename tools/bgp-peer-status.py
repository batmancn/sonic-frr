#!/bin/env python

import time
import json
import syslog
import subprocess
import re

SLEEP_INTERVAL = 3 # in second

def runCommand(command):
    syslog.syslog(syslog.LOG_INFO, 'cmd: {}'.format(command))
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ret, err = child.communicate()
    if err == None:
        return ret
    else:
        syslog.syslog(syslog.LOG_ERR, 'err: {}'.format(err))
        return ""

def setPeerStatus(peerRemoteAddr, status):
    newDict = {'BGP_NEIGHBORS': {peerRemoteAddr: {'peer_status': status}}}
    newJson = json.dumps(newDict)
    command = ['sonic-cfggen', '-a', newJson, '-w']
    runCommand(command)

def getPeerStatus(peerRemoteAddr):
    command = ['vtysh', '-c', 'show bgp neighbor {}'.format(peerRemoteAddr)]
    ret = runCommand(command)
    if ret != '':
        res = re.search('BGP state = [a-zA-Z]*', ret)
        res = res.group()[12:len(res.group())]
        return res
    else:
        return ""

def readConfigDb():
    command = ['sonic-cfggen', '-d', '--print-data']
    return runCommand(command)

def main():
    while True:
        # read config
        sonicCfgJson = readConfigDb()
        # change into dict
        sonicCfgDict = json.loads(sonicCfgJson)

        for (k, v) in sonicCfgDict.items():
            if k == 'BGP_NEIGHBORS':
                bgpNeighbors = v
                for (k, v) in bgpNeighbors.items():
                    peerRemoteAddr = k
                    newStatus = getPeerStatus(k)
                    oldStatus = v['peer_status'] if 'peer_status' in v.keys() else ''
                    if newStatus != '' and newStatus != oldStatus:
                        setPeerStatus(peerRemoteAddr, newStatus)

        # sleep SLEEP_INTERVAL
        time.sleep(SLEEP_INTERVAL)

if __name__ == '__main__':
    main()