#!/usr/bin/python3

import sys, json, requests
from urllib.request import urlopen

# Opening JSON file
f = open(sys.argv[1])

# returns JSON object as 
# a dictionary
data = json.load(f)

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

# response = urlopen('https://ipwho.is/' + sourceAddress)
# jsondata = json.load(response)
# for x, y in jsondata.items():
#     if (x != 'flag'):
#         print(x, y)
# print("---------")
# print("Success: " + str(jsondata['success']))
# if (jsondata['success']):
#     print("IP: " + jsondata['ip'])
#     print("Continent: " + jsondata['continent'])
#     print("Country: " + jsondata['country'])
#     print("Region: " + jsondata['region'])
#     print("City: " + jsondata['city'])
#     print("Latitude: " + str(jsondata['latitude']))
#     print("Longitude: " + str(jsondata['longitude']))
# else:
#     print("Message: " + jsondata['message'])

# response = requests.get('https://ipwho.is/' + sourceAddress)
# print("Response code: " + str(response.status_code))
# jsondata = json.loads(response.content.decode("utf-8"))
# for x, y in jsondata.items():
#     if (x != 'flag'):
#         print(x, y)
# print("---------")
# print("IP: " + jsondata['ip'])
# print("Continent: " + jsondata['continent'])
# print("Country: " + jsondata['country'])
# print("Region: " + jsondata['region'])
# print("City: " + jsondata['city'])
# print("Latitude: " + str(jsondata['latitude']))
# print("Longitude: " + str(jsondata['longitude']))

#response = requests.get('https://ipgeolocation.abstractapi.com/v1/?api_key=cd2accb3c58c4396a6415306bf169608&fields=continent,country,city,latitude,longitude&ip_address=' + sourceAddress)
#print(response.status_code)
#print(response.json())

#loc = requests.get('https://ipapi.co/' + sourceAddress + '/json/')
#print (loc.json())

response = urlopen('http://ip-api.com/json/' + sourceAddress)
jsondata = json.load(response)
print(jsondata)
print("---------")
print("IP: " + jsondata['query'])
print("City: " + jsondata['city'])
print("Continent: " + jsondata['regionName'])
print("Continent Code: " + jsondata['region'])
print("Country: " + jsondata['country'])
print("Country Code: " + jsondata['countryCode'])
print("Latitude: " + str(jsondata['lat']))
print("Longitude: " + str(jsondata['lon']))
print("Postal Code: " + str(jsondata['zip']))

# Closing file
f.close()
