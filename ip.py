from asyncio import events
from pytz import country_names
import requests
import json
from requests import get
from flask import Flask
from flask_cors import CORS
from flask import request
import datetime
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC

app = Flask(__name__)

CORS(app)


@ app.route('/', methods=['GET'])
def get_tasks():
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return {'ip': request.environ['REMOTE_ADDR']}
    else:
        return {'ip': request.environ['HTTP_X_FORWARDED_FOR']}


@ app.route("/ip")
# private=socket.gethostbcket.gethos
# adr="185.185.179.8"
def ip_info():
    ip = {}
    adrr = get_tasks()
    adr = adrr['ip']

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
    a = responseip["data"]["irr_records"][0][2]["value"]
    b = responseip["data"]["irr_records"][0][1]["value"]
    if (any(c.isalpha() for c in a) == False):
        ip["asncode"] = a
        ip["asnname"] = b
    if (any(c.isalpha() for c in b) == False):
        ip["asncode"] = b
        ip["asnname"] = a

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


@ app.route("/as")
def asn_info():
    adrr = get_tasks()
    adr = adrr['ip']
    sourceip = "https://stat.ripe.net/data/whois/data.json?resource="+adr+"%2F24"
    responseip = requests.get(sourceip).json()
    a = responseip["data"]["irr_records"][0][2]["value"]
    b = responseip["data"]["irr_records"][0][1]["value"]
    if (any(c.isalpha() for c in a) == False):
        asn = a
    if (any(c.isalpha() for c in b) == False):
        asn = b
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
    nb = response1["data"]["announced_space"]["v4"]["prefixes"] + \
        response1["data"]["announced_space"]["v6"]["prefixes"]
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
# #    dict = {}
# #
# #    previous_date = datetime.datetime.today() - datetime.timedelta(days=1)
# #    times = str(int(round(previous_date.timestamp())))
# #
# #    curr_date = datetime.datetime.now()
# #    times1 = str(int(round(curr_date.timestamp())))
# #
# url = 'https://ioda.caida.org/ioda/data/events?from=' + \
# times+'&until='+times1+'&human=true&meta=country/LB'
# #    events = requests.get(url).json()
# #
# #    start_time = events["queryParameters"]["from"]
# #    end_time = events["queryParameters"]["until"]
# #
# #    timestamp = datetime.datetime.fromtimestamp(int(start_time))
# #    start = timestamp.strftime('%Y-%m-%d %H:%M:%S')
# #
# #    timestamp1 = datetime.datetime.fromtimestamp(int(end_time))
# #    end = timestamp1.strftime('%Y-%m-%d %H:%M:%S')
# #
# #    print("Events occured:")
# #    list_events = events["data"]["events"]
# print(list_events)
# #    dict["Events"] = list_events
# #
# print("Country:")
# #    place = events["queryParameters"]["meta"]
# print(place)
# #    dict["Country"] = place
# #
# #    print("Start time:")
# print(start)
# #    dict["Start-time"] = start
# #    print("End time:")
# print(end)
# #    dict["End-time"] = end
# #
# with open("events.json", "w") as outfile:
# #        json.dump(dict, outfile)
# #
# #
# def alert():
# #    dict = {}
# #
# #    curr_date = datetime.datetime.now()
# print(curr_date)
# #    timestamp = str(int(round(curr_date.timestamp())))
# print(timestamp)
# #
# url = 'https://ioda.caida.org/ioda/data/alerts?from='+timestamp + \
# '&until='+timestamp+'&annotateMeta=true&human=true&meta=country/LB'
# #    alerts = requests.get(url).json()
# #
# #    start_time = alerts["queryParameters"]["from"]
# #    end_time = alerts["queryParameters"]["until"]
# #
# #    timestamp1 = datetime.datetime.fromtimestamp(int(start_time))
# #    start = timestamp1.strftime('%Y-%m-%d %H:%M:%S')
# #
# #    timestamp2 = datetime.datetime.fromtimestamp(int(end_time))
# #    end = timestamp2.strftime('%Y-%m-%d %H:%M:%S')
# #
# print("Alerts:")
# #    list_alerts = alerts["data"]["alerts"]
# print(list_alerts)
# #    dict["Alerts"] = list_alerts
# #
# #    print("Start time:")
# print(start)
# #    dict["Start-time"] = start
# #    print("End time:")
# print(end)
# #    dict["End-time"] = end
# #
# with open("alerts.json", "w") as outfile:
# #        json.dump(dict, outfile)
# #
# #
# event()
# alert()
@ app.route("/history")
def History():
    adrr = get_tasks()
    adr = adrr['ip']
    # adr='94.187.8.0'
    sourceip = "https://stat.ripe.net/data/whois/data.json?resource="+adr+"%2F24"
    responseip = requests.get(sourceip).json()
    a = responseip["data"]["irr_records"][0][2]["value"]
    b = responseip["data"]["irr_records"][0][1]["value"]
    if (any(c.isalpha() for c in a) == False):
        asn = a
    if (any(c.isalpha() for c in b) == False):
        asn = b

    history = {}

    sous_dict = {}

    url = "https://stat.ripe.net/data/routing-history/data.json?min_peers=0&resource="+asn

    hist = requests.get(url).json()

    liste = []

    pref = responseip["data"]["records"][0][0]["value"]
    pref = pref[0:(len(pref)-3)]

    for p in hist["data"]["by_origin"][0]["prefixes"]:

        liste.append(p["prefix"])

    j = 0
    while(j < len(liste)):
        liste[j] = liste[j][0:(len(liste[j])-3)]
        j = j+1

    for l in liste:

        if (pref == l):

            # date = "2022"

            i = 0

            for d in p["timelines"]:

                # print(d)

                # print(d["starttime"])

                if "2022" in d["starttime"]:

                    sous_dict[d["starttime"][0:10]] = d["full_peers_seeing"]
                    sous_dict[d["endtime"][0:10]] = d["full_peers_seeing"]
                    i = i+1

    return sous_dict


@ app.route("/all")
def All():

    adrr = get_tasks()
    adr = adrr['ip']
    # adr='91.232.100.0'
    dictionnaire = {}
    sourceip = "https://stat.ripe.net/data/whois/data.json?resource="+adr+"%2F24"
    responseip = requests.get(sourceip).json()
    a = responseip["data"]["irr_records"][0][2]["value"]
    b = responseip["data"]["irr_records"][0][1]["value"]
    if (any(c.isalpha() for c in a) == False):
        asn = a
    if (any(c.isalpha() for c in b) == False):
        asn = b
    sous_dict = {}

    list_prefixe = "https://stat.ripe.net/data/announced-prefixes/data.json?resource="+asn
    lists = requests.get(list_prefixe).json()
    j = 0
    for i in lists["data"]["prefixes"]:
        prefix = i["prefix"]
        dictionnaire[j] = prefix
        j = j+1
    sous_dict = {}

    k = 0

    while (k < len(dictionnaire)):

        url = "https://stat.ripe.net/data/routing-history/data.json?min_peers=0&resource=" + \
            str(dictionnaire[k][0:(len(dictionnaire[k])-3)])

        hist = requests.get(url).json()

        for p in hist["data"]["by_origin"]:
            if (p["origin"] == asn):

                for d in p["prefixes"][0]["timelines"]:
                    # print(d)

                    # print(d["starttime"])

                    if "2022" in d["starttime"]:
                        if (d["starttime"][0:10] in sous_dict.keys()):
                            sous_dict[d["starttime"][0:10]] = sous_dict[d["starttime"]
                                                                        [0:10]]+d["full_peers_seeing"]
                        if (d["endtime"][0:10] in sous_dict.keys()):
                            sous_dict[d["endtime"][0:10]] = sous_dict[d["endtime"]
                                                                      [0:10]] + d["full_peers_seeing"]
                        else:
                            sous_dict[d["starttime"][0:10]
                                      ] = d["full_peers_seeing"]
                            sous_dict[d["endtime"][0:10]
                                      ] = d["full_peers_seeing"]

        k = k+1
    for i in sous_dict.keys():
        sous_dict[i] = sous_dict[i]/len(dictionnaire)

    return sous_dict


@ app.route("/pred")
def Pred():
    adrr = get_tasks()
    adr = adrr['ip']
    sourceip = "https://stat.ripe.net/data/whois/data.json?resource="+adr+"%2F24"
    responseip = requests.get(sourceip).json()
    a = responseip["data"]["irr_records"][0][2]["value"]
    b = responseip["data"]["irr_records"][0][1]["value"]
    if (any(c.isalpha() for c in a) == False):
        asn = a
    if (any(c.isalpha() for c in b) == False):
        asn = b
    url = 'https://stat.ripe.net/data/bgp-update-activity/data.json?endtime=2022-04-11T12%3A00%3A00&hide_empty_samples=false&max_samples=5000&resource=AS' + \
        str(asn)+'&starttime=2021-04-11T00%3A00%3A00'
    r = requests.get(url)
    json = r.json()
    return json


@ app.route("/pay")
def pays():
    country_names = {
        {"afghanistan": "AF"},
        {"land Islands": "AX"},
        {"albania": "AL"},
        {"algeria": "DZ"},
        {"american Samoa": "AS"},
        {"andorrA": "AD"},
        {"angola": "AO"},
        {"anguilla": "AI"},
        {"antarctica": "AQ"},
        {"antigua and Barbuda": "AG"},
        {"argentina": "AR"},
        {"armenia": "AM"},
        {"aruba": "AW"},
        {"australia": "AU"},
        {"austria": "AT"},
        {"azerbaijan": "AZ"},
        {"bahamas""BS"},
        {"bahrain": "BH"},
        {"bangladesh": "BD"},
        {"barbados": "BB"},
        {"belarus": "BY"},
        {"belgium": "BE"},
        {"belize": "BZ"},
        {"benin": "BJ"},
        {"bermuda": "BM"},
        {"bhutan": "BT"},
        {"bolivia": "BO"},
        {"bosnia and herzegovina": "BA"},
        {"botswana": "BW"},
        {"bouvet island": "BV"},
        {"brazil": "BR"},
        {"british indian ocean territory": "IO"},
        {"brunei darussalam": "BN"},
        {"bulgaria": "BG"},
        {"burkina faso": "BF"},
        {"burundi": "BI"},
        {"cambodia": "KH"},
        {"cameroon": "CM"},
        {"canada": "CA"},
        {"cape verde": "CV"},
        {"cayman islands": "KY"},
        {"central african republic": "CF"},
        {"chad": "TD"},
        {"chile": "CL"},
        {"china": "CN"},
        {"christmas island": "CX"},
        {"cocos (Keeling) islands": "CC"},
        {"colombia": "CO"},
        {"comoros": "KM"},
        {"congo": "CG"},
        {"congo, The Democratic Republic of the": "CD"},
        {"cook islands": "CK"},
        {"costa rica": "CR"},
        {"cote d\"ivoire": "CI"},
        {"croatia": "HR"},
        {"cuba": "CU"},
        {"cyprus": "CY"},
        {"czech republic": "CZ"},
        {"denmark": "DK"},
        {"djibouti": "DJ"},
        {"dominica": "DM"},
        {"dominican republic": "DO"},
        {"ecuador": "EC"},
        {"egypt": "EG"},
        {"el salvador": "SV"},
        {"equatorial guinea": "GQ"},
        {"eritrea": "ER"},
        {"estonia": "EE"},
        {"ethiopia": "ET"},
        {"falkland islands (malvinas)": "FK"},
        {"faroe islands": "FO"},
        {"fiji": "FJ"},
        {"finland": "FI"},
        {"france": "FR"},
        {"french guiana": "GF"},
        {"french polynesia": "PF"},
        {"french southern territories": "TF"},
        {"gabon": "GA"},
        {"gambia": "GM"},
        {"georgia": "GE"},
        {"germany": "DE"},
        {"ghana": "GH"},
        {"gibraltar": "GI"},
        {"greece": "GR"},
        {"greenland": "GL"},
        {"grenada": "GD"},
        {"guadeloupe": "GP"},
        {"guam": "GU"},
        {"guatemala": "GT"},
        {"guernsey": "GG"},
        {"guinea": "GN"},
        {"guinea-bissau": "GW"},
        {"guyana": "GY"},
        {"haiti": "HT"},
        {"heard island and mcdonald islands": "HM"},
        {"holy see (vatican city state)": "VA"},
        {"honduras": "HN"},
        {"hong kong": "HK"},
        {"hungary": "HU"},
        {"iceland": "IS"},
        {"india": "IN"},
        {"indonesia": "ID"},
        {"iran, islamic republic of": "IR"},
        {"iraq": "IQ"},
        {"ireland": "IE"},
        {"isle of man": "IM"},
        {"israel": "IL"},
        {"italy": "IT"},
        {"jamaica": "JM"},
        {"japan": "JP"},
        {"jersey": "JE"},
        {"jordan": "JO"},
        {"kazakhstan": "KZ"},
        {"kenya": "KE"},
        {"kiribati": "KI"},
        {"korea, democratic people\"s republic of": "KP"},
        {"korea, republic of": "KR"},
        {"kuwait": "KW"},
        {"kyrgyzstan": "KG"},
        {"lao people\"s democratic republic": "LA"},
        {"latvia": "LV"},
        {"lebanon": "LB"},
        {"lesotho": "LS"},
        {"liberia": "LR"},
        {"libyan Arab Jamahiriya": "LY"},
        {"liechtenstein": "LI"},
        {"lithuania": "LT"},
        {"luxembourg": "LU"},
        {"macao": "MO"},
        {"macedonia, the former yugoslav republic of": "MK"},
        {"madagascar": "MG"},
        {"malawi": "MW"},
        {"malaysia": "MY"},
        {"maldives": "MV"},
        {"mali": "ML"},
        {"malta": "MT"},
        {"marshall islands": "MH"},
        {"martinique": "MQ"},
        {"mauritania": "MR"},
        {"mauritius": "MU"},
        {"mayotte": "YT"},
        {"mexico": "MX"},
        {"micronesia, federated states of": "FM"},
        {"moldova, republic of": "MD"},
        {"monaco": "MC"},
        {"mongolia": "MN"},
        {"montenegro": "ME"},
        {"montserrat": "MS"},
        {"morocco": "MA"},
        {"mozambique": "MZ"},
        {"myanmar": "MM"},
        {"namibia": "NA"},
        {"nauru": "NR"},
        {"nepal": "NP"},
        {"netherlands": "NL"},
        {"netherlands antilles": "AN"},
        {"new caledonia": "NC"},
        {"new zealand": "NZ"},
        {"nicaragua": "NI"},
        {"niger": "NE"},
        {"nigeria": "NG"},
        {"niue": "NU"},
        {"norfolk island": "NF"},
        {"northern mariana islands": "MP"},
        {"norway": "NO"},
        {"oman": "OM"},
        {"pakistan": "PK"},
        {"palau": "PW"},
        {"palestinian territory, occupied": "PS"},
        {"panama": "PA"},
        {"papua new guinea": "PG"},
        {"paraguay": "PY"},
        {"peru": "PE"},
        {"philippines": "PH"},
        {"pitcairn": "PN"},
        {"poland": "PL"},
        {"portugal": "PT"},
        {"puerto rico": "PR"},
        {"qatar": "QA"},
        {"reunion": "RE"},
        {"romania": "RO"},
        {"russian federation": "RU"},
        {"rwanda": "RW"},
        {"saint helena": "SH"},
        {"saint kitts and nevis": "KN"},
        {"saint lucia": "LC"},
        {"saint pierre and miquelon": "PM"},
        {"saint vincent and the grenadines": "VC"},
        {"samoa": "WS"},
        {"san marino": "SM"},
        {"sao tome and principe": "ST"},
        {"saudi arabia": "SA"},
        {"senegal": "SN"},
        {"serbia": "RS"},
        {"seychelles": "SC"},
        {"sierra leone": "SL"},
        {"singapore": "SG"},
        {"slovakia": "SK"},
        {"slovenia": "SI"},
        {"solomon islands": "SB"},
        {"somalia": "SO"},
        {"south africa": "ZA"},
        {"south georgia and the south sandwich islands": "GS"},
        {"spain": "ES"},
        {"sri lanka": "LK"},
        {"sudan": "SD"},
        {"s": "SR"},
        {"svalbard and jan mayen": "SJ"},
        {"swaziland": "SZ"},
        {"sweden": "SE"},
        {"switzerland": "CH"},
        {"syrian arab republic": "SY"},
        {"taiwan, province of china": "TW"},
        {"tajikistan": "TJ"},
        {"tanzania, united republic of": "TZ"},
        {"thailand": "TH"},
        {"timor-leste": "TL"},
        {"togo": "TG"},
        {"tokelau": "TK"},
        {"tonga": "TO"},
        {"trinidad and tobago": "TT"},
        {"tunisia": "TN"},
        {"turkey": "TR"},
        {"turkmenistan": "TM"},
        {"turks and caicos islands": "TC"},
        {"tuvalu": "TV"},
        {"uganda": "UG"},
        {"ukraine": "UA"},
        {"united arab emirates": "AE"},
        {"united kingdom": "GB"},
        {"united states": "US"},
        {"united states minor outlying islands": "UM"},
        {"uruguay": "UY"},
        {"uzbekistan": "UZ"},
        {"vanuatu": "VU"},
        {"venezuela": "VE"},
        {"viet nam": "VN"},
        {"virgin islands, british": "VG"},
        {"virgin islands, U.S.": "VI"},
        {"wallis and futuna": "WF"},
        {"western sahara": "EH"},
        {"yemen": "YE"},
        {"zambia": "ZM"},
        {"zimbabwe": "ZW"}
    }
    return country_names

# @app.route("/alert")
# def alert():
#     dict = {}

#     curr_date = datetime.datetime.now()

#     timestamp = str(int(round(curr_date.timestamp())))


#     url = 'https://ioda.caida.org/ioda/data/alerts?from='+timestamp + \
#     '&until='+timestamp+'&annotateMeta=true&human=true&meta=asn/3307'
#     alerts = requests.get(url).json()

#     start_time = alerts["queryParameters"]["from"]
#     end_time = alerts["queryParameters"]["until"]

#     timestamp1 = datetime.datetime.fromtimestamp(int(start_time))
#     start = timestamp1.strftime('%Y-%m-%d %H:%M:%S')

#     timestamp2 = datetime.datetime.fromtimestamp(int(end_time))
#     end = timestamp2.strftime('%Y-%m-%d %H:%M:%S')


#     list_alerts = alerts["data"]["alerts"]

#     dict["Alerts"] = list_alerts


#     dict["Start-time"] = start


#     dict["End-time"] = end

#     s=""

#     if not list_alerts:
#         s="No Outages are expected"
#         return s
#     else:
#         return list_alerts

@ app.route("/message")
def message():
    adrr = get_tasks()
    adr = adrr['ip']

    sourceip = "https://stat.ripe.net/data/whois/data.json?resource="+adr+"%2F24"
    responseip = requests.get(sourceip).json()
    a = responseip["data"]["irr_records"][0][2]["value"]
    b = responseip["data"]["irr_records"][0][1]["value"]
    if (any(c.isalpha() for c in a) == False):
        asn = a
    if (any(c.isalpha() for c in b) == False):
        asn = b
    dict = {}
    mssg = {}
    previous_date = datetime.datetime.today() - datetime.timedelta(days=1)
    times = str(int(round(previous_date.timestamp())))

    curr_date = datetime.datetime.now()
    times1 = str(int(round(curr_date.timestamp())))

    url = 'https://ioda.caida.org/ioda/data/events?from=' + \
        times+'&until='+times1+'&human=true&meta=asn/'+asn
    events = requests.get(url).json()

    start_time = events["queryParameters"]["from"]
    end_time = events["queryParameters"]["until"]

    timestamp1 = datetime.datetime.fromtimestamp(int(start_time))
    start = timestamp1.strftime('%Y-%m-%d %H:%M:%S')

    timestamp2 = datetime.datetime.fromtimestamp(int(end_time))
    end = timestamp2.strftime('%Y-%m-%d %H:%M:%S')

    list_events = events["data"]["events"]

    dict["events"] = list_events

    dict["Start-time"] = start

    dict["End-time"] = end

    s = ""

    if not list_events:
        s = "No outages occured while you were away"
        mssg["outages"] = s

    else:
        s = "An Outage Occured"
        mssg["outages"] = s

    return mssg

    @app.route("/ml")
    def ML():
        adrr = get_tasks()
        adr=adrr['ip']
        #adr='94.187.8.0'
        sourceip = "https://stat.ripe.net/data/whois/data.json?resource="+adr+"%2F24"
        responseip = requests.get(sourceip).json()
        a = responseip["data"]["irr_records"][0][2]["value"]
        b=responseip["data"]["irr_records"][0][1]["value"]
        if (any(c.isalpha() for c in a)==False):
            asn=a
        if (any(c.isalpha() for c in b)==False):
            asn=b
        url = "https://stat.ripe.net/data/routing-history/data.json?min_peers=0&resource="+asn

        pref = responseip["data"]["records"][0][0]["value"]
        pref=pref[0:(len(pref)-3)]
        url = 'https://stat.ripe.net/data/bgp-update-activity/data.json?endtime=2022-04-15T12%3A00%3A00&hide_empty_samples=false&max_samples=10000&resource='+pref+'&starttime=2021-04-29T00%3A00%3A00'
        r = requests.get(url)
        json = r.json()
        df = pd.DataFrame(json['data']['updates'])
        df.drop("starttime", axis=1, inplace=True)
        r=df.shape[0]-1
        nb=df.iloc[r,0:2].values
        df = df.drop(df.shape[0]-1, axis=0)

        l=[]
        av=df["announcements"].mean()
        l.append(int(df["announcements"][0]>av))
        l.append(int(df["announcements"][1]>av))
        i=2
        while (i<df.shape[0]):
            m=(df["announcements"][i-1]+df["announcements"][i-2])/2
            if (df["announcements"][i]<m):
                l.append(0)
            else:
                l.append(1)
            i=i+1
        df["label"]=l


        training_set, test_set = train_test_split(df, test_size = 0.2)   

        X_train = training_set.iloc[:,0:2].values
        Y_train = training_set.iloc[:,2].values


        classifier = SVC(kernel='rbf', random_state = 1,gamma=0.01)
        classifier.fit(X_train,Y_train)
        Y_pred = classifier.predict(nb)
        s=""
        mssg={}
        if not list_events:
            s="No outages occured while you were away"
            mssg["outages"]=s

        else:
            s="An Outage Occured"
            mssg["outages"]=s



        if (Y_pred==1):

            s="Your network is prone to instability in the upcoming hours!"
            mssg["outages"]=s

        else:
            s="Safe:No instability detected!"
            mssg["outages"]=s

        return mssg

# if __name__ == "__main__":
#     app.run(debug=True)