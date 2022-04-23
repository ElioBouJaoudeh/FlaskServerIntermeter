from asyncio import events
import requests
import json
from requests import get
from flask import Flask
from flask_cors import CORS
from flask import request 
app = Flask(__name__)

CORS(app)

@app.route('/', methods=['GET'])
def get_tasks():
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return {'ip': request.environ['REMOTE_ADDR']}
    else:
        return {'ip': request.environ['HTTP_X_FORWARDED_FOR']}

@app.route("/ip")
# private=socket.gethostbyname(socket.gethostname())
# adr="185.185.179.8"
def ip_info():
    ip = {}
    adrr = get_tasks()
    adr=adrr['ip']
    
    sourceip = "https://stat.ripe.net/data/whois/data.json?resource="+adr+"%2F24"
    sourcevisib = "https://stat.ripe.net/data/routing-status/data.json?resource="+adr+"%2F24"

    responseip = requests.get(sourceip).json()
    visible = requests.get(sourcevisib).json()

    prefix = responseip["data"]["records"][0][0]["value"]
    ip["prefix"] = prefix

    rpki = "https://stat.ripe.net/data/rpki-validation/data.json?resource=38999&prefix="+prefix
    pk = requests.get(rpki).json()
    isp = responseip["data"]["records"][0][1]["value"]
    ip["isp"] = isp
    country = responseip["data"]["records"][0][2]["value"]
    ip["country"] = country
    ipp = responseip["data"]["irr_records"][0][0]["value"]
    ip["ip"] = ipp
    asn_name = responseip["data"]["irr_records"][0][1]["value"]
    ip["asnname"] = asn_name
    asn_code = responseip["data"]["irr_records"][0][2]["value"]
    ip["asncode"] = asn_code

    try:
        rpk = pk["data"]["validating_roas"]["validity"]
        ip["rpki"] = rpk
    except:
        ip["rpki"] = "Not valid"

    ipv4_seeing = visible["data"]["visibility"]["v4"]["ris_peers_seeing"]
    ipv4_total = visible["data"]["visibility"]["v4"]["total_ris_peers"]

    if (ipv4_seeing == ipv4_total):
        ip["ipv4"] = 100
        print("100% visibility ipv4")
    else:
        per = (ipv4_seeing*100)/ipv4_total
        ip["ipv4"] = per
        print(str(per)+"% Visibility ipv4")

    ipv6_seeing = visible["data"]["visibility"]["v6"]["ris_peers_seeing"]
    ipv6_total = visible["data"]["visibility"]["v6"]["total_ris_peers"]

    if (ipv6_seeing == ipv6_total):
        ip["ipv6"] = 100
        print("100% visibility ipv6")
    else:
        per = (ipv6_seeing*100)/ipv6_total
        ip["ipv6"] = per
        print(str(per)+"% Visibility ipv6")

    with open("ip.json", "w") as outfile:
        json.dump(ip, outfile)

    return ip


@app.route("/as")
def asn_info():
    adrr = get_tasks()
    adr=adrr['ip']
    sourceip = "https://stat.ripe.net/data/whois/data.json?resource="+adr+"%2F24"
    responseip = requests.get(sourceip).json()
    asn = responseip["data"]["irr_records"][0][2]["value"]
    dictionary = {}
    sous_dictionnaire = {}
    dictionnaire = {}
    # sourceasn="https://stat.ripe.net/data/country-resource-list/data.json?resource=LB"
    # responseasn = requests.get(sourceasn).json()
    # ASN=responseasn["data"]["resources"]["asn"]

    # for asn in ASN:
    source = "https://stat.ripe.net/data/visibility/data.json?include=peers_seeing&resource="+asn
    source2 = "https://stat.ripe.net/data/routing-status/data.json?resource="+asn
    source3 = "https://stat.ripe.net/data/whois/data.json?resource="+asn
    source1 = 'https://ihr.iijlab.net/ihr/api/networks/?number='+asn

    # nb of prefixes for each autonomous system
    url = "https://stat.ripe.net/data/routing-status/data.json?resource="+asn
    response1 = requests.get(url).json()
    nb = response1["data"]["announced_space"]["v4"]["prefixes"]+response1["data"]["announced_space"]["v6"]["prefixes"]
    sous_dictionnaire["Number of prefixes"] = nb
    sous_dictionnaire["v4"] = response1["data"]["announced_space"]["v4"]["prefixes"]
    sous_dictionnaire["v6"] = response1["data"]["announced_space"]["v6"]["prefixes"]

    # list of prefixes for an as
    list_prefixe = "https://stat.ripe.net/data/announced-prefixes/data.json?resource="+asn
    lists = requests.get(list_prefixe).json()
    j = 0
    for i in lists["data"]["prefixes"]:
        prefix = i["prefix"]
        print(prefix)
        dictionnaire[j] = prefix
        j = j+1
    sous_dictionnaire["List of prefixes"] = dictionnaire
    ipv4_seeing = 0
    ipv4_total = 0
    ipv6_seeing = 0
    ipv6_total = 0
    response1 = requests.get(source2).json()
    response2 = requests.get(source3).json()
    response3 = requests.get(source1).json()

    print("Time:")
    time = response1["data"]["last_seen"]["time"]
    sous_dictionnaire["time"] = time
    print(time)

    name = response2["data"]["records"][0][1]["value"]
    print("ASN name:"+name)
    print(response1["data"]["visibility"])
    sous_dictionnaire["name"] = name
    print(name)

    disco = response3["results"][0]["disco"]
    print("Disconnection:"+str(disco))
    sous_dictionnaire["disconnection"] = disco

    for i in response1:
        ipv4_seeing = response1["data"]["visibility"]["v4"]["ris_peers_seeing"]
        ipv4_total = response1["data"]["visibility"]["v4"]["total_ris_peers"]
    if (ipv4_seeing == ipv4_total):
        sous_dictionnaire["ipv4"] = 100
        print("100% visibility ipv4")
    else:
        per = (ipv4_seeing*100)/ipv4_total
        sous_dictionnaire["ipv4"] = per
        print(str(per)+"% Visibility ipv4")

    for i in response1:
        ipv6_seeing = response1["data"]["visibility"]["v6"]["ris_peers_seeing"]
        ipv6_total = response1["data"]["visibility"]["v6"]["total_ris_peers"]
    if (ipv6_seeing == ipv6_total):
        sous_dictionnaire["ipv6"] = 100
        print("100% visibility ipv6")
    else:
        per = (ipv6_seeing*100)/ipv6_total
        sous_dictionnaire["ipv6"] = per
        print(str(per)+"% Visibility ipv6")

    dictionary[asn] = sous_dictionnaire
    with open("sample.json", "w") as outfile:
        json.dump(dictionary, outfile, indent=4)

    return dictionary


# def event():
##    dict = {}
##
##    previous_date = datetime.datetime.today() - datetime.timedelta(days=1)
##    times = str(int(round(previous_date.timestamp())))
##
##    curr_date = datetime.datetime.now()
##    times1 = str(int(round(curr_date.timestamp())))
##
# url = 'https://ioda.caida.org/ioda/data/events?from=' + \
# times+'&until='+times1+'&human=true&meta=country/LB'
##    events = requests.get(url).json()
##
##    start_time = events["queryParameters"]["from"]
##    end_time = events["queryParameters"]["until"]
##
##    timestamp = datetime.datetime.fromtimestamp(int(start_time))
##    start = timestamp.strftime('%Y-%m-%d %H:%M:%S')
##
##    timestamp1 = datetime.datetime.fromtimestamp(int(end_time))
##    end = timestamp1.strftime('%Y-%m-%d %H:%M:%S')
##
##    print("Events occured:")
##    list_events = events["data"]["events"]
# print(list_events)
##    dict["Events"] = list_events
##
# print("Country:")
##    place = events["queryParameters"]["meta"]
# print(place)
##    dict["Country"] = place
##
##    print("Start time:")
# print(start)
##    dict["Start-time"] = start
##    print("End time:")
# print(end)
##    dict["End-time"] = end
##
# with open("events.json", "w") as outfile:
##        json.dump(dict, outfile)
##
##
# def alert():
##    dict = {}
##
##    curr_date = datetime.datetime.now()
# print(curr_date)
##    timestamp = str(int(round(curr_date.timestamp())))
# print(timestamp)
##
# url = 'https://ioda.caida.org/ioda/data/alerts?from='+timestamp + \
# '&until='+timestamp+'&annotateMeta=true&human=true&meta=country/LB'
##    alerts = requests.get(url).json()
##
##    start_time = alerts["queryParameters"]["from"]
##    end_time = alerts["queryParameters"]["until"]
##
##    timestamp1 = datetime.datetime.fromtimestamp(int(start_time))
##    start = timestamp1.strftime('%Y-%m-%d %H:%M:%S')
##
##    timestamp2 = datetime.datetime.fromtimestamp(int(end_time))
##    end = timestamp2.strftime('%Y-%m-%d %H:%M:%S')
##
# print("Alerts:")
##    list_alerts = alerts["data"]["alerts"]
# print(list_alerts)
##    dict["Alerts"] = list_alerts
##
##    print("Start time:")
# print(start)
##    dict["Start-time"] = start
##    print("End time:")
# print(end)
##    dict["End-time"] = end
##
# with open("alerts.json", "w") as outfile:
##        json.dump(dict, outfile)
##
##
# event()
# alert()
@app.route("/history")

def History():
    adrr = get_tasks()
    adr=adrr['ip']
    sourceip = "https://stat.ripe.net/data/whois/data.json?resource="+adr+"%2F24"
    responseip = requests.get(sourceip).json()
    asn = responseip["data"]["irr_records"][0][2]["value"]

    history = {}

    sous_dict = {}

    url = "https://stat.ripe.net/data/routing-history/data.json?min_peers=0&resource="+asn

    hist = requests.get(url).json()

    list = []

    pref = responseip["data"]["records"][0][0]["value"]
    pref=pref[0:(len(pref)-3)]

    for p in hist["data"]["by_origin"][0]["prefixes"]:

        list.append(p["prefix"])

        # print(p)

    for l in list:

        if l == pref:

            # date = "2022"

            i = 0

            for d in p["timelines"]:

                # print(d)

                # print(d["starttime"])

                if "2022" in d["starttime"]:

                    print("hi")

                    # print(p["timelines"])

                    sous_dict[i] = d

                    i = i+1

    history[p["prefix"]] = sous_dict


    print(history)

    return history

@app.route("/pred")
def Pred():
    adrr = get_tasks()
    adr=adrr['ip']
    sourceip = "https://stat.ripe.net/data/whois/data.json?resource="+adr+"%2F24"
    responseip = requests.get(sourceip).json()
    asn = responseip["data"]["irr_records"][0][2]["value"]
    url = 'https://stat.ripe.net/data/bgp-update-activity/data.json?endtime=2022-04-11T12%3A00%3A00&hide_empty_samples=false&max_samples=5000&resource=AS'+str(asn)+'&starttime=2021-04-11T00%3A00%3A00'
    r = requests.get(url)
    json = r.json()
    return json 

if __name__ == "__main__":
    app.run(debug=True)