#!/usr/bin/python3

import sys, json, syslog

# Opening JSON file
f = open(sys.argv[1])

# returns JSON object as 
# a dictionary
data = json.load(f)

# Iterating through the json
# list
for i in data['_source']['cef']['extensions'].items():
	if (i[0] == 'sourceAddress'):
		sourceAddress = i[1]
	elif (i[0] == 'destinationAddress'):
		destinationAddress = i[1]
	elif (i[0] == 'sourcePort'):
		sourcePort = i[1]
	elif (i[0] == 'destinationPort'):
		destinationPort = i[1]
	elif (i[0] == 'applicationProtocol'):
		applicationProtocol = i[1]
	elif (i[0] == 'destinationServiceName'):
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
