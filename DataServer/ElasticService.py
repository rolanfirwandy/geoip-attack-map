#!/usr/bin/python3

import warnings, sys, json, syslog, time
from datetime import datetime
from elasticsearch import Elasticsearch, RequestsHttpConnection

def main():
	warnings.filterwarnings("ignore")
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
		time.sleep(6)

		# Get KPU data
		resp = es.search(index=kpu_index, query={"match_all":{}}, size=4, sort={"@timestamp":{"order":"desc"}})
		print("Got %d Hits:" % resp['hits']['total']['value'])
		for hit in resp['hits']['hits']:
			try:
				kpuSourceAddress = hit['_source']['fortinet']['firewall']['srcip']
				kpuSourcePort = hit['_source']['fortinet']['firewall']['srcport']
				kpuDestinationAddress = hit['_source']['fortinet']['firewall']['dstip']
				kpuDestinationPort = hit['_source']['fortinet']['firewall']['dstport']
				kpuApplicationProtocol = hit['_source']['fortinet']['firewall']['service']
				kpuDestinationServiceName = hit['_source']['fortinet']['firewall']['attack']
			except KeyError:
				kpuSourceAddress = hit['_source']['fortinet']['firewall']['src']
				kpuSourcePort = hit['_source']['fortinet']['firewall']['src_port']
				kpuDestinationAddress = hit['_source']['fortinet']['firewall']['dst']
				kpuDestinationPort = hit['_source']['fortinet']['firewall']['dst_port']
				kpuApplicationProtocol = hit['_source']['fortinet']['firewall']['service']
				kpuDestinationServiceName = hit['_source']['fortinet']['firewall']['signature_cve_id']

			kpu_attack_data = '{},{},{},{},{},{}'.format(
											kpuSourceAddress,
											kpuDestinationAddress,
											kpuSourcePort,
											kpuDestinationPort,
											kpuApplicationProtocol,
											kpuDestinationServiceName
											)

			syslog.syslog(kpu_attack_data)
			time.sleep(0.2)

		# Get KL data
		resp = es.search(index=kl_index, query={"match_all":{}}, size=4, sort={"@timestamp":{"order":"desc"}})
		print("Got %d Hits:" % resp['hits']['total']['value'])
		for hit in resp['hits']['hits']:
			klSourceAddress = hit['_source']['cef']['extensions']['sourceAddress']
			klSourcePort = hit['_source']['cef']['extensions']['sourcePort']
			klDestinationAddress = hit['_source']['cef']['extensions']['destinationAddress']
			klDestinationPort = hit['_source']['cef']['extensions']['destinationPort']
			klApplicationProtocol = hit['_source']['cef']['extensions']['applicationProtocol']
			klDestinationServiceName = hit['_source']['cef']['extensions']['destinationServiceName']

			kl_attack_data = '{},{},{},{},{},{}'.format(
											klSourceAddress,
											klDestinationAddress,
											klSourcePort,
											klDestinationPort,
											klApplicationProtocol,
											klDestinationServiceName
											)

			syslog.syslog(kl_attack_data)
			time.sleep(0.2)

		# Get Palo Alto data
		resp = es.search(index=pa_index, query={"match_all":{}}, size=4, sort={"@timestamp":{"order":"desc"}})
		print("Got %d Hits:" % resp['hits']['total']['value'])
		for hit in resp['hits']['hits']:
			paSourceAddress = hit['_source']['source']['ip']
			paSourcePort = hit['_source']['source']['port']
			paDestinationAddress = hit['_source']['destination']['ip']
			paDestinationPort = hit['_source']['destination']['port']
			paApplicationProtocol = hit['_source']['network']['transport']
			paDestinationServiceName = hit['_source']['service']['type']

			pa_attack_data = '{},{},{},{},{},{}'.format(
											paSourceAddress,
											paDestinationAddress,
											paSourcePort,
											paDestinationPort,
											paApplicationProtocol,
											paDestinationServiceName
											)

			syslog.syslog(pa_attack_data)
			time.sleep(0.2)

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		exit()
