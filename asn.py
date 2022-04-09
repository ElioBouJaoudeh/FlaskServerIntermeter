# from asyncio import events
# import requests
# import json
# import datetime
# import time

# from flask import Flask

# app1=Flask(__name__)
# @app1.route("/as")


# def asn_info():
#     asn="42020"
#     dictionary = {}
#     sous_dictionnaire = {}
#     dictionnaire={}
#     # sourceasn="https://stat.ripe.net/data/country-resource-list/data.json?resource=LB"
#     # responseasn = requests.get(sourceasn).json()
#     # ASN=responseasn["data"]["resources"]["asn"]

#     # for asn in ASN:
#     source = "https://stat.ripe.net/data/visibility/data.json?include=peers_seeing&resource="+asn
#     source2 = "https://stat.ripe.net/data/routing-status/data.json?resource="+asn
#     source3 = "https://stat.ripe.net/data/whois/data.json?resource="+asn
#     source1 = 'https://ihr.iijlab.net/ihr/api/networks/?number='+asn

#     #nb of prefixes for each autonomous system
#     url= "https://stat.ripe.net/data/routing-status/data.json?resource="+asn
#     response1 = requests.get(url).json()
#     nb_prefix = response1["data"]["announced_space"]
#     nb= response1["data"]["announced_space"]["v4"]["prefixes"] + response1["data"]["announced_space"]["v6"]["prefixes"]
#     print(nb)
#     sous_dictionnaire["Number of prefixes"] = nb
#     sous_dictionnaire["v4"]= response1["data"]["announced_space"]["v4"]["prefixes"]
#     sous_dictionnaire["v6"]= response1["data"]["announced_space"]["v6"]["prefixes"]

#     #list of prefixes for an as
#     list_prefixe="https://stat.ripe.net/data/announced-prefixes/data.json?resource="+asn
#     lists= requests.get(list_prefixe).json()
#     j=0
#     for i in lists["data"]["prefixes"]:
#         prefix = i["prefix"]
#         print(prefix)
#         dictionnaire[j]=prefix
#         j=j+1
#     sous_dictionnaire["List of prefixes"]=dictionnaire
#     ipv4_seeing = 0
#     ipv4_total = 0
#     ipv6_seeing = 0
#     ipv6_total = 0
#     response1 = requests.get(source2).json()
#     response2 = requests.get(source3).json()
#     response3 = requests.get(source1).json()

#     print("Time:")
#     time = response1["data"]["last_seen"]["time"]
#     sous_dictionnaire["time"] = time
#     print(time)

#     name = response2["data"]["records"][0][1]["value"]
#     print("ASN name:"+name)
#     print(response1["data"]["visibility"])
#     sous_dictionnaire["name"] = name
#     print(name)

#     disco = response3["results"][0]["disco"]
#     print("Disconnection:"+str(disco))
#     sous_dictionnaire["disconnection"] = disco

#     for i in response1:
#         ipv4_seeing = response1["data"]["visibility"]["v4"]["ris_peers_seeing"]
#         ipv4_total = response1["data"]["visibility"]["v4"]["total_ris_peers"]
#     if (ipv4_seeing == ipv4_total):
#         sous_dictionnaire["ipv4"] = 100
#         print("100% visibility ipv4")
#     else:
#         per = (ipv4_seeing*100)/ipv4_total
#         sous_dictionnaire["ipv4"] = per
#         print(str(per)+"% Visibility ipv4")

#     for i in response1:
#         ipv6_seeing = response1["data"]["visibility"]["v6"]["ris_peers_seeing"]
#         ipv6_total = response1["data"]["visibility"]["v6"]["total_ris_peers"]
#     if (ipv6_seeing == ipv6_total):
#         sous_dictionnaire["ipv6"] = 100
#         print("100% visibility ipv6")
#     else:
#         per = (ipv6_seeing*100)/ipv6_total
#         sous_dictionnaire["ipv6"] = per
#         print(str(per)+"% Visibility ipv6")

#     dictionary[asn] = sous_dictionnaire
#     with open("sample.json", "w") as outfile:
#         json.dump(dictionary, outfile, indent=4)

#     return dictionary


# ##def event():
# ##    dict = {}
# ##
# ##    previous_date = datetime.datetime.today() - datetime.timedelta(days=1)
# ##    times = str(int(round(previous_date.timestamp())))
# ##
# ##    curr_date = datetime.datetime.now()
# ##    times1 = str(int(round(curr_date.timestamp())))
# ##
# ##    url = 'https://ioda.caida.org/ioda/data/events?from=' + \
# ##        times+'&until='+times1+'&human=true&meta=country/LB'
# ##    events = requests.get(url).json()
# ##
# ##    start_time = events["queryParameters"]["from"]
# ##    end_time = events["queryParameters"]["until"]
# ##
# ##    timestamp = datetime.datetime.fromtimestamp(int(start_time))
# ##    start = timestamp.strftime('%Y-%m-%d %H:%M:%S')
# ##
# ##    timestamp1 = datetime.datetime.fromtimestamp(int(end_time))
# ##    end = timestamp1.strftime('%Y-%m-%d %H:%M:%S')
# ##
# ##    print("Events occured:")
# ##    list_events = events["data"]["events"]
# ##    print(list_events)
# ##    dict["Events"] = list_events
# ##
# ##    print("Country:")
# ##    place = events["queryParameters"]["meta"]
# ##    print(place)
# ##    dict["Country"] = place
# ##
# ##    print("Start time:")
# ##    print(start)
# ##    dict["Start-time"] = start
# ##    print("End time:")
# ##    print(end)
# ##    dict["End-time"] = end
# ##
# ##    with open("events.json", "w") as outfile:
# ##        json.dump(dict, outfile)
# ##
# ##
# ##def alert():
# ##    dict = {}
# ##
# ##    curr_date = datetime.datetime.now()
# ##    # print(curr_date)
# ##    timestamp = str(int(round(curr_date.timestamp())))
# ##    # print(timestamp)
# ##
# ##    url = 'https://ioda.caida.org/ioda/data/alerts?from='+timestamp + \
# ##        '&until='+timestamp+'&annotateMeta=true&human=true&meta=country/LB'
# ##    alerts = requests.get(url).json()
# ##
# ##    start_time = alerts["queryParameters"]["from"]
# ##    end_time = alerts["queryParameters"]["until"]
# ##
# ##    timestamp1 = datetime.datetime.fromtimestamp(int(start_time))
# ##    start = timestamp1.strftime('%Y-%m-%d %H:%M:%S')
# ##
# ##    timestamp2 = datetime.datetime.fromtimestamp(int(end_time))
# ##    end = timestamp2.strftime('%Y-%m-%d %H:%M:%S')
# ##
# ##    print("Alerts:")
# ##    list_alerts = alerts["data"]["alerts"]
# ##    print(list_alerts)
# ##    dict["Alerts"] = list_alerts
# ##
# ##    print("Start time:")
# ##    print(start)
# ##    dict["Start-time"] = start
# ##    print("End time:")
# ##    print(end)
# ##    dict["End-time"] = end
# ##
# ##    with open("alerts.json", "w") as outfile:
# ##        json.dump(dict, outfile)
# ##
# ##
# ##event()
# ##alert()

# if __name__=="__main__":
#     app1.run(debug=True)
