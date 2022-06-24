#!/usr/bin/python3

import sys, json, syslog

# Opening JSON file
f = open(sys.argv[1])

# returns JSON object as 
# a dictionary
data = json.load(f)

# Get data details
sourceAddress = data['_source']['source']['ip']
sourcePort = data['_source']['source']['port']
destinationAddress = data['_source']['destination']['ip']
destinationPort = data['_source']['destination']['port']
applicationProtocol = data['_source']['network']['transport']
destinationServiceName = data['_source']['service']['type']

attack_data = '{},{},{},{},{},{}'.format(
                                    sourceAddress,
                                    destinationAddress,
                                    sourcePort,
                                    destinationPort,
                                    applicationProtocol,
                                    destinationServiceName
                                    )

print(attack_data)
syslog.syslog(attack_data)

# Closing file
f.close()
