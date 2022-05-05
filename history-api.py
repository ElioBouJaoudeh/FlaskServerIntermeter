# # announced prefixes: on la utiliser pour afficher les prefixes d'un asn specific
# https: // stat.ripe.net/data/announced-prefixes/data.json?resource = AS38999

# OK # routing history: gives us each prefix of this asn and all the starttime endtime from first seen till last seen with the nb of peers seeing
# https: // stat.ripe.net/data/routing-history/data.json?min_peers = 0 & resource = AS38999

# # routing history for a prefix: Routing History shows the time range(s) when a particular prefix was announced, and by which AS it was announced.
# https: // stat.ripe.net/data/routing-history/data.json?min_peers = 0 & resource = 212.98.134.0 % 2F24

# # routing-status: for an asn, shows a summary of the current BGP routing state of a prefix or AS number, as observed by the RIPE RIS route collectors.
# https: // stat.ripe.net/data/routing-status/data.json?resource = AS38999

# # shows us for a specific prefix the first and last seen with the peers seeing and announced space
# https: // stat.ripe.net/data/routing-status/data.json?resource = 212.98.134.0/24

# # bgp-update gives for the last 2 weeks every hour of every day the announcements
# https: // stat.ripe.net/data/bgp-update-activity/data.json?endtime = 2022-04-01T07 % 3A00 % 3A00 & hide_empty_samples = false & max_samples = 350 & resource = AS38999 & starttime = 2022-03-18T07 % 3A00 % 3A00
# # cached true false?

# # bgplay: shows the routing history related to a specific set of resources (prefixes, Autonomous Systems, IPs)
# # initial state, events, nodes, sources
# https: // stat.ripe.net/data/bgplay/data.json?resource = 212.98.134.0 % 2F24 & unix_timestamps = TRUE

# # bgp update activity within the past 2 weeks
# #  shows the frequency of update and withdrawal messages for a prefix
# https: // stat.ripe.net/data/bgp-update-activity/data.json?endtime = 2022-04-01T07 % 3A00 % 3A00 & hide_empty_samples = false & max_samples = 350 & resource = 212.98.134.0 % 2F24 & starttime = 2022-03-18T07 % 3A00 % 3A00


# # Probes:  shows the deployment of RIPE Atlas probes over time.
# https: // stat.ripe.net/data/atlas-probe-deployment/data.json?resource = AS38999

# https: // stat.ripe.net/data/atlas-probe-deployment/data.json?resource = asn4_42020 % 2Ccc_lb
# from asyncio import events
# from sys import prefix
# import time
# from datetime import date, timedelta, datetime
# import datetime
# import requests
# import json
# from requests import get
# import pyasn

# from flask import Flask

# app = Flask(__name__)


# @app.route("/history")
# def History(asn):
#     history = {}
#     sous_dict = {}
#     url = "https://stat.ripe.net/data/routing-history/data.json?min_peers=0&resource="+asn
#     hist = requests.get(url).json()
#     list = []
#     with open(r'C:\Users\Lea\Desktop\MDP\FlaskServerIntermeter\ip.json', 'r') as f:
#         data = json.load(f)
#     pref = data["prefix"]
#     for p in hist["data"]["by_origin"][0]["prefixes"]:
#         list.append(p["prefix"])
#         # print(p)
#     for l in list:
#         if l == pref:
#             # date = "2022"
#             i = 0
#             for d in p["timelines"]:
#                 # print(d)
#                 # print(d["starttime"])
#                 if "2022" in d["starttime"]:
#                     print("hi")
#                     # print(p["timelines"])
#                     sous_dict[i] = d
#                     i = i+1
#     history[p["prefix"]] = sous_dict

#     with open("history.json", "w") as outfile:
#         json.dump(history, outfile)

#     print(history)
#     return history


# def bgp():
#     curr_date = datetime.datetime.now()
#     now = str(curr_date.strftime("%Y-%m-%d %H:%M:%S"))
#     yesterday = curr_date + timedelta(days=-1)
#     yest = str(yesterday.strftime("%Y-%m-%d %H:%M:%S"))

#     date = now[0:10]
#     before = yest[0:10]

#     hour = now[11:13]
#     minute = now[14:16]
#     second = now[17:]

#     url = "https://stat.ripe.net/data/bgp-update-activity/data.json?endtime=" + \
#         str(date)+"T"+hour+"%3A"+minute+"%3A"+second+"&hide_empty_samples=false&max_samples100&resource=AS42020&starttime=" + \
#         str(before)+"T"+hour+"%3A"+minute+"%3A"+second
#     bgp = requests.get(url).json()
#     print(bgp)
#     somme = 0
#     comp = 0
#     bgp_update = {}
#     sous_dict1 = {}
#     sous_dict2 = {}
#     for i in bgp["data"]["updates"]:
#         comp += 1
#         somme = somme + i["announcements"]
#         # print(i["announcements"])
#     avg = somme/comp
#     for i in bgp["data"]["updates"]:
#         time = i["starttime"]
#         # print(i["announcements"])
#         bgp_update[time] = ""
#         if i["announcements"] < avg:
#             # print("instability")
#             sous_dict1["instability"] = "yes"
#             bgp_update[time] = sous_dict1
#         elif i["announcements"] >= avg:
#             sous_dict2["instability"] = "no"
#             bgp_update[time] = sous_dict2
#     with open("bgp.json", "w") as outfile:
#         json.dump(bgp_update, outfile)


# History("206472")
# bgp()
