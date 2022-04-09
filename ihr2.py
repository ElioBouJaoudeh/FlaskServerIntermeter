import requests
import json
from ripe.atlas.sagan import SslResult
import socket
from datetime import datetime
from requests import get

ip={}

# private=socket.gethostbyname(socket.gethostname())
#adr="185.185.179.8"
adr= get('https://api.ipify.org').text

sourceip="https://stat.ripe.net/data/whois/data.json?resource="+adr+"%2F24"
sourcevisib="https://stat.ripe.net/data/routing-status/data.json?resource="+adr+"%2F24"


responseip= requests.get(sourceip).json()
vis= requests.get(sourcevisib).json()

prefix=responseip["data"]["records"][0][0]["value"]
ip["prefix"]=prefix
rpki="https://stat.ripe.net/data/rpki-validation/data.json?resource=38999&prefix="+prefix
pk=requests.get(rpki).json()
isp=responseip["data"]["records"][0][1]["value"]
ip["isp"]=isp
country=responseip["data"]["records"][0][2]["value"]
ip["country"]=country
ipp=responseip["data"]["irr_records"][0][0]["value"]
ip["ip"]=ipp
asn_name=responseip["data"]["irr_records"][0][2]["value"]
ip["asnname"]=asn_name
asn_code=responseip["data"]["irr_records"][0][1]["value"]
ip["asncode"]=asn_code
try:
    rpk=pk["data"]["validating_roas"]["validity"]
    ip["rpki"]=rpk
except:
    ip["rpki"]="Not valid"

a=vis["data"]["visibility"]["v4"]["ris_peers_seeing"]
b=vis["data"]["visibility"]["v4"]["total_ris_peers"]
if (a==b):
    ip["ipv4"]=100
    print("100% visibility ipv4")
else:
    per=(a*100)/b
    ip["ipv4"]=per
    print(str(per)+"% Visibility ipv4")


c=vis["data"]["visibility"]["v6"]["ris_peers_seeing"]
d=vis["data"]["visibility"]["v6"]["total_ris_peers"]
if (c==d):
    ip["ipv6"]=100
    print("100% visibility ipv6")
else:
    per=(c*100)/d
    ip["ipv6"]=per
    print(str(per)+"% Visibility ipv6")
with open("sampleip.json", "w") as outfile:
    json.dump(ip, outfile)
