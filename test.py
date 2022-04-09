# import requests
# import json
# from ripe.atlas.sagan import SslResult
# from datetime import datetime

# #LIBANTELECOM
# ASN1="AS42020"
# #MTCTOUCH
# ASN2="AS38999"
# dictionary ={}
# for k in [ASN1,ASN2]:
#     source ="https://stat.ripe.net/data/visibility/data.json?include=peers_seeing&resource="+k
#     source2="https://stat.ripe.net/data/routing-status/data.json?resource="+k
#     source3="https://stat.ripe.net/data/whois/data.json?resource="+k

#     sous={}
#     a=0
#     b=0
#     c=0
#     d=0
#     response1 = requests.get(source2).json()
#     response2= requests.get(source3).json()
#     print("Time:")
#     time=response1["data"]["last_seen"]["time"]
#     sous["time"]=time
#     print(time)
#     name=response2["data"]["records"][0][1]["value"]
#     print("ASN name:"+name)
#     print(response1["data"]["visibility"])
#     sous["name"]=name
#     print(name)
#     for i in response1:
#         a=response1["data"]["visibility"]["v4"]["ris_peers_seeing"]
#         b=response1["data"]["visibility"]["v4"]["total_ris_peers"]
#     if (a==b):
#         sous["ipv4"]=100
#         print("100% visibility ipv4")
#     else:
#         per=(a*100)/b
#         sous["ipv4"]=per
#         print(str(per)+"% Visibility ipv4")

#     for i in response1:
#         c=response1["data"]["visibility"]["v6"]["ris_peers_seeing"]
#         d=response1["data"]["visibility"]["v6"]["total_ris_peers"]
#     if (c==d):
#         sous["ipv6"]=100
#         print("100% visibility ipv6")
#     else:
#         per=(c*100)/d
#         sous["ipv6"]=per
#         print(str(per)+"% Visibility ipv6")

#     dictionary[k]=sous
#     with open("sample.json", "w") as outfile:
#         json.dump(dictionary, outfile)

from requests import get



ip = get('https://api.ipify.org').text
print(f'My public IP address is: {ip}')
