#!/usr/bin/python3

import json
import maxminddb
import redis
import io

from const import META, PORTMAP

from argparse import ArgumentParser, RawDescriptionHelpFormatter
from os import getuid
from sys import exit
from time import gmtime, localtime, sleep, strftime
from urllib.request import urlopen
from pymongo import MongoClient

redis_ip = '127.0.0.1'
redis_instance = None

# mongo_url = 'mongodb://log_admin:password@localhost:27017/'
mongo_url = 'mongodb://log_admin:password@192.168.18.25:27017/'
db = None

geoip_url = 'http://ip-api.com/json/'

# required input paths
syslog_path = '/var/log/messages'
db_path = '../DataServerDB/GeoLite2-City.mmdb'

# stats
server_start_time = strftime("%d-%m-%Y %H:%M:%S", localtime()) # local time
event_count = 0
continents_tracked = {}
countries_tracked = {}
country_to_code = {}
ip_to_code = {}
ips_tracked = {}
unknowns = {}

# Create clean dictionary using unclean db dictionary contents
def clean_db(unclean):
    selected = {}
    for tag in META:
        head = None
        if tag['tag'] in unclean:
            head = unclean[tag['tag']]
            for node in tag['path']:
                if node in head:
                    head = head[node]
                else:
                    head = None
                    break
            selected[tag['lookup']] = head

    return selected

def connect_redis(redis_ip):
    r = redis.StrictRedis(host=redis_ip, port=6379, db=0)
    return r

def connect_mongo(mongo_url):
    client = MongoClient(mongo_url)
    d = client['bindb'].geoipdb
    return d

def get_msg_type():
    # @TODO
    # Add support for more message types later
    return "Traffic"

# Check to see if packet is using an interesting TCP/UDP protocol based on source or destination port
def get_tcp_udp_proto(src_port, dst_port):
    src_port = int(src_port)
    dst_port = int(dst_port)

    if src_port in PORTMAP:
        return PORTMAP[src_port]
    if dst_port in PORTMAP:
        return PORTMAP[dst_port]

    return "OTHER"

def parse_maxminddb(db_path, ip):
    try:
        reader = maxminddb.open_database(db_path)
        response = reader.get(ip)
        reader.close()
        return response
    except FileNotFoundError:
        print('DB not found')
        print('SHUTTING DOWN')
        exit()
    except ValueError:
        return False

def parse_syslog(line):
    line = line.split()
    data = line[-1]
    data = data.split(',')

    if len(data) != 6:
        print('NOT A VALID LOG')
        return False
    else:
        src_ip = data[0]
        dst_ip = data[1]
        src_port = data[2]
        dst_port = data[3]
        type_attack = data[4]
        cve_attack = data[5]
        data_dict = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'type_attack': type_attack,
                    'cve_attack': cve_attack
                    }
        return data_dict

def shutdown_and_report_stats():
    print('\nSHUTTING DOWN')
    # Report stats tracked
    print('\nREPORTING STATS...')
    print('\nEvent Count: {}'.format(event_count)) # report event count
    print('\nContinent Stats...') # report continents stats 
    for key in continents_tracked:
        print('{}: {}'.format(key, continents_tracked[key]))
    print('\nCountry Stats...') # report country stats
    for country in countries_tracked:
        print('{}: {}'.format(country, countries_tracked[country]))
    print('\nCountries to iso_codes...')
    for key in country_to_code:
        print('{}: {}'.format(key, country_to_code[key]))
    print('\nIP Stats...') # report IP stats
    for ip in ips_tracked:
        print('{}: {}'.format(ip, ips_tracked[ip]))
    print('\nIPs to iso_codes...')
    for key in ip_to_code:
        print('{}: {}'.format(key, ip_to_code[key]))
    print('\nUnknowns...')
    for key in unknowns:
        print('{}: {}'.format(key, unknowns[key]))
    exit()

def merge_dicts(*args):
    super_dict = {}
    for arg in args:
        super_dict.update(arg)
    return super_dict

def track_flags(super_dict, tracking_dict, key1, key2):
    if key1 in super_dict:
        if key2 in super_dict:
            if key1 in tracking_dict:
                return None
            else:
                tracking_dict[super_dict[key1]] = super_dict[key2]
        else:
            return None
    else:
        return None

def track_stats(super_dict, tracking_dict, key):
    if key in super_dict:
        node = super_dict[key]
        if node in tracking_dict:
            tracking_dict[node] += 1
        else:
            tracking_dict[node] = 1
    else:
        if key in unknowns:
            unknowns[key] += 1
        else:
            unknowns[key] = 1

def find_dst_lat_long(hq_ip):
    hq_ip_db_clean = db.find_one({"query": hq_ip})
    if hq_ip_db_clean:
        print('get dst data from mongo')
        dst_lat = hq_ip_db_clean['lat']
        dst_long = hq_ip_db_clean['lon']
        hq_dict = {
                'dst_lat': dst_lat,
                'dst_long': dst_long
                }
        return hq_dict
    else:
        print('get dst data from api')
        resp_dst = urlopen(geoip_url + hq_ip)
        json_dst = json.load(resp_dst)
        if (json_dst['status'] == 'success'):
            db.insert_one(json_dst)
            dst_lat = str(json_dst['lat'])
            dst_long = str(json_dst['lon'])
            hq_dict = {
                    'dst_lat': dst_lat,
                    'dst_long': dst_long
                    }
            return hq_dict
        else:
            print(json_dst['message'])
            hq_dict = {
                    'dst_lat': -6.17,
                    'dst_long': 106.8
                    }
            return hq_dict

def main():
    if getuid() != 0:
        print('Please run this script as root')
        print('SHUTTING DOWN')
        exit()

    global db_path, log_file_out, redis_ip, redis_instance, syslog_path, hq_ip, db
    global continents_tracked, countries_tracked, ips_tracked, postal_codes_tracked, event_count, unknown, ip_to_code, country_to_code

    #args = menu()

    # Connect to Redis
    redis_instance = connect_redis(redis_ip)

    # Connect to MongoDB
    db = connect_mongo(mongo_url)

    # Follow/parse/format/publish syslog data
    with io.open(syslog_path, "r", encoding='ISO-8859-1') as syslog_file:
        syslog_file.readlines()
        while True:
            where = syslog_file.tell()
            line = syslog_file.readline()
            if not line:
                sleep(.1)
                syslog_file.seek(where)
            else:
                syslog_data_dict = parse_syslog(line)
                if syslog_data_dict:
                    ip_db_unclean = db.find_one({"query": syslog_data_dict['src_ip']})
                    hq_dict = find_dst_lat_long(syslog_data_dict['dst_ip'])

                    if ip_db_unclean:
                        print('get src data from mongo')
                        event_count += 1
                        ip_db_clean = {'city': ip_db_unclean['city'],
                                    'continent': ip_db_unclean['regionName'],
                                    'continent_code': ip_db_unclean['region'],
                                    'country': ip_db_unclean['country'],
                                    'iso_code': ip_db_unclean['countryCode'],
                                    'latitude': ip_db_unclean['lat'],
                                    'longitude': ip_db_unclean['lon'],
                                    'metro_code': 0,
                                    'postal_code': ip_db_unclean['zip']
                                    }
                    else:
                        print('get src data from api')
                        event_count += 1
                        resp_src = urlopen(geoip_url + syslog_data_dict['src_ip'])
                        json_src = json.load(resp_src)
                        if (json_src['status'] == 'success'):
                            db.insert_one(json_src)
                            ip_db_clean = {'city': json_src['city'],
                                        'continent': json_src['regionName'],
                                        'continent_code': json_src['region'],
                                        'country': json_src['country'],
                                        'iso_code': json_src['countryCode'],
                                        'latitude': json_src['lat'],
                                        'longitude': json_src['lon'],
                                        'metro_code': 0,
                                        'postal_code': json_src['zip']
                                        }
                        else:
                            ip_db_clean = {'city': 'Jakarta',
                                        'continent': 'Asia',
                                        'continent_code': 'AS',
                                        'country': 'Indonesia',
                                        'iso_code': 'ID',
                                        'latitude': -6.17,
                                        'longitude': 106.8,
                                        'metro_code': 0,
                                        'postal_code': ""
                                        }
                            print(json_src['message'])

                    msg_type = {'msg_type': get_msg_type()}
                    msg_type2 = {'msg_type2': syslog_data_dict['type_attack']}
                    msg_type3 = {'msg_type3': syslog_data_dict['cve_attack']}

                    proto = {'protocol': get_tcp_udp_proto(
                                                        syslog_data_dict['src_port'],
                                                        syslog_data_dict['dst_port']
                                                        )}
                    super_dict = merge_dicts(
                                            hq_dict,
                                            ip_db_clean,
                                            msg_type,
                                            msg_type2,
                                            msg_type3,
                                            proto,
                                            syslog_data_dict
                                            )

                    # Track Stats
                    track_stats(super_dict, continents_tracked, 'continent')
                    track_stats(super_dict, countries_tracked, 'country')
                    track_stats(super_dict, ips_tracked, 'src_ip')
                    event_time = strftime("%d-%m-%Y %H:%M:%S", localtime()) # local time
                    #event_time = strftime("%Y-%m-%d %H:%M:%S", gmtime()) # UTC time
                    track_flags(super_dict, country_to_code, 'country', 'iso_code')
                    track_flags(super_dict, ip_to_code, 'src_ip', 'iso_code')

                    # Append stats to super_dict
                    super_dict['event_count'] = event_count
                    super_dict['continents_tracked'] = continents_tracked
                    super_dict['countries_tracked'] = countries_tracked
                    super_dict['ips_tracked'] = ips_tracked
                    super_dict['unknowns'] = unknowns
                    super_dict['event_time'] = event_time
                    super_dict['country_to_code'] = country_to_code
                    super_dict['ip_to_code'] = ip_to_code

                    json_data = json.dumps(super_dict)
                    print(json_data)
                    redis_instance.publish('attack-map-production', json_data)

                    print('Event Count: {}'.format(event_count))
                    print('------------------------')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        shutdown_and_report_stats()

