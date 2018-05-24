'''
Aouidene Imed 

Viri 2018

'''


import requests
import json
import time




block_time = 30 #time to bloc the flow
rule_id = 1
sFlow_RT = 'http://127.0.0.1:8008'
priority = '32767'
black_list = []
floodlight = 'http://127.0.0.1:8080'

#define vars sFlow_RT
var = {'external': ['0.0.0.0/0'], 'internal': ['10.0.0.2/32']}
r = requests.put(sFlow_RT + '/group/lf/json', data=json.dumps(var))



icmp_flood_threshold_value = 200
icmp_flood_metric_name = 'icmp_flood'
icmp_flood_keys = 'ipsource,ipdestination,macsource,macdestination,ethernetprotocol,ipprotocol'
icmp_flood_filter = 'group:ipsource:lf=external&group:ipdestination:lf=internal&outputifindex!=discard&ipprotocol=1'
icmp_flood_threshold = {'metric': icmp_flood_metric_name, 'value': icmp_flood_threshold_value}
icmp_flood_flows = {'keys': icmp_flood_keys, 'value': 'bytes', 'filter': icmp_flood_filter}
#  SYN flood attack attributes #
syn_flood_threshold_value = 200
syn_flood_metric_name = 'syn_flood'
syn_flood_filter = 'group:ipsource:lf=external&group:ipdestination:lf=internal&outputifindex!=discard&tcpflags~.......1.'
syn_flood_keys = 'ipsource,ipdestination,macsource,macdestination,ethernetprotocol,ipprotocol'
syn_flood_flows = {'keys': syn_flood_keys, 'value': 'bytes', 'filter': syn_flood_filter}
syn_flood_threshold = {'metric': syn_flood_metric_name, 'value': syn_flood_threshold_value}


    # define flows and threshold of ICMP flood
r = requests.put(sFlow_RT + '/flow/' + icmp_flood_metric_name + '/json', data=json.dumps(icmp_flood_flows))
r = requests.put(sFlow_RT + '/threshold/' + icmp_flood_metric_name + '/json', data=json.dumps(icmp_flood_threshold))
	
    # define flows and threshold of SYN flood
r = requests.put(sFlow_RT + '/flow/' + syn_flood_metric_name + '/json', data=json.dumps(syn_flood_flows))
r = requests.put(sFlow_RT + '/threshold/' + syn_flood_metric_name + '/json', data=json.dumps(syn_flood_threshold))


event_url = sFlow_RT + '/events/json?maxEvents=10&timeout=60'
ev_id = -1 # first event has an id of 0

while True:
    #Black list is used to save all added rules added to the controller
    if black_list.__len__() > 0 and black_list[0][0] < time.time():
        #r = requests.delete(floodlight + '/wm/staticflowentrypusher/json', data=black_list.pop(0)[1])
        r = requests.delete(floodlight + '/wm/acl/rules/json',data=black_list.pop(0)[1])
        print r.json()['status']

    r = requests.get(event_url + '&ev_id=' + str(ev_id))
    events = r.json()
    #print "listing events*** "
    #print events
    if events.__len__() > 0:
        ev_id = events[0]["ev_id"]
    events.reverse() #reverse is used to take only new events 
    #print "Event ID *******"
    #print  ev_id
 
    for e in events:
        #print "mini-event ~~~~~~~~~~"
        #print e
        if e['metric'] == syn_flood_metric_name:
            r = requests.get(sFlow_RT + '/metric/' + e['agent'] + '/' + e['dataSource'] + '.' + e['metric'] + '/json')
            metrics = r.json()
			# processing the event
            if metrics and metrics.__len__() > 0:
                metric = metrics[0]
                if metric.__contains__("metricValue") \
                        and metric['metricValue'] > syn_flood_threshold_value\
                        and metric['topKeys']\
                        and metric['topKeys'].__len__() > 0:

                    for topKey in metric['topKeys']:
                        if topKey['value'] > syn_flood_threshold_value:
                            key = topKey['key']
                            print key,
                            parts = key.split(',')
			    msg = {'name': 'ICMP_block_'+parts[5],
                                   'src-ip': parts[5]+'/32',
                                   'dst-ip': parts[6]+'/32',
                                   'action': 'deny',
                                   'nw-proto':'tcp'}
                            new_data = json.dumps(msg)
                            blockrule = {'ruleid':rule_id}
                            rule_id = rule_id+1
                            block_rule = json.dumps(blockrule)
                            #print push_data
                            #r = requests.post(floodlight + '/wm/staticflowentrypusher/json', data=push_data)
                            r = requests.post(floodlight + '/wm/acl/rules/json',data=new_data)
			    black_list.append([time.time()+block_time, block_rule ])
                            result = r.json()
                            print ""
                            print result['status']
                    print ""

        elif e['metric'] == icmp_flood_metric_name:
            r = requests.get(sFlow_RT + '/metric/' + e['agent'] + '/' + e['dataSource'] + '.' + e['metric'] + '/json')
            metrics = r.json()
            if metrics and metrics.__len__() > 0:
                metric = metrics[0]
                if metric.__contains__("metricValue") \
                        and metric['metricValue'] > icmp_flood_threshold_value\
                        and metric['topKeys']\
                        and metric['topKeys'].__len__() > 0:

                    for topKey in metric['topKeys']:
                        if topKey['value'] > icmp_flood_threshold_value:
                            key = topKey['key']
                            print key,
                            parts = key.split(',')

                            msg = {'name': 'ICMP_block_'+parts[5],
                                   'src-ip': parts[5]+'/32',
                                   'dst-ip': parts[6]+'/32',
                                   'action': 'deny',
                                   'nw-proto':'icmp'}

                            new_data = json.dumps(msg)
                            blockrule = {'ruleid':rule_id}
                            rule_id = rule_id+1
                            block_rule = json.dumps(blockrule)
                            r = requests.post(floodlight + '/wm/acl/rules/json',data=new_data)
                            black_list.append([time.time()+block_time, block_rule ])
                            result = r.json()
                            print  "priting results ~~~~~"
                            print result
                            print result['status']
                    print ""

