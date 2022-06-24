#!/usr/bin/python3

import sys, json, syslog

# Opening JSON file
f = open(sys.argv[1])

# returns JSON object as 
# a dictionary
data = json.load(f)

# Iterating through the json
# list
for i in data['_source']['fortinet']['firewall'].items():
	if (i[0] == 'srcip'):
		sourceAddress = i[1]
	elif (i[0] == 'dstip'):
		destinationAddress = i[1]
	elif (i[0] == 'srcport'):
		sourcePort = i[1]
	elif (i[0] == 'dstport'):
		destinationPort = i[1]
	elif (i[0] == 'service'):
		applicationProtocol = i[1]
	elif (i[0] == 'attack'):
		destinationServiceName = i[1]

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
