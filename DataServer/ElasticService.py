#!/usr/bin/python3

import warnings, sys, json, syslog, time
from datetime import datetime
from elasticsearch import Elasticsearch, RequestsHttpConnection

def main():
	kpu_index = 'coba1_kpu'
	kl_index = 'coba_kl'
	pa_index = 'coba_palo_alto'

	es = Elasticsearch(
	    ['https://elastic:_UNzJtTqkv+wmNj-jZZ=@10.8.30.235:9200'],
	    connection_class=RequestsHttpConnection,
	    verify_certs=False
	)
	print(es.ping())

	while True:
		time.sleep(4)
		# Get KPU data

		resp = es.search(index=kpu_index, query={"match_all":{}}, size=4, sort={"@timestamp":{"order":"desc"}})
		print("Got %d Hits:" % resp['hits']['total']['value'])
		for hit in resp['hits']['hits']:
		    sourceAddress = hit['_source']['fortinet']['firewall']['srcip']
		    sourcePort = hit['_source']['fortinet']['firewall']['srcport']
		    destinationAddress = hit['_source']['fortinet']['firewall']['dstip']
		    destinationPort = hit['_source']['fortinet']['firewall']['dstport']
		    applicationProtocol = hit['_source']['fortinet']['firewall']['service']
		    destinationServiceName = hit['_source']['fortinet']['firewall']['attack']

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
		    time.sleep(0.2)

		# Get KL data

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        exit()
