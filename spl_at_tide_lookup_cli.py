import sys
import datetime
import csv
###there is no sqlite3 lib on splunk  
from subprocess import Popen, PIPE
###TIDE
import requests
from requests.auth import HTTPBasicAuth

#Path to DB and debug log
CPATH="/opt/splunk/cache"
#Online Infoblox TIDE search and cache of unknown indicators
TIDESearch=0

#Infoblox TIDE API Key
with open(CPATH+'/at_api_key.txt', 'r') as f:
    ATTIDE_KEY = f.read().rstrip()

def get_IOC(type,IOC):
    result=""
    sql=""
    pre="" if type=="ip" else "," if type == "host" else ",,"
    post=",,," if type=="ip" else ",," if type == "host" else ","
    url='https://platform.activetrust.net:8000/api/data/threats/state/'+type+'?field='+type+',property&data_format=csv&rlimit=10&'+type+'='+IOC
    response = requests.get(url,auth=HTTPBasicAuth(ATTIDE_KEY, ''))
    for msg in response.text.encode('utf-8').split('\n')[1:]:
        line=msg.split(",")
        if len(line)>1 and line[0] == IOC:
            result+=pre+IOC+post+line[1]+"\n"
            sql+='insert into combo ('+type+',property) values("'+IOC+'","'+line[1]+'")'+"\n"
    return result if result != "" else pre+IOC+post, sql if sql != "" else 'insert into combo ('+type+',property) values("'+IOC+'","")'


#TIDE DB
DB=CPATH+"/active-threat-intel.db"
#Threats Descriptions DB
DBTreats=CPATH+"/threat_properties.db"
#Response header
header="ip,host,url,property\n"
#Check all subdomains
ch_sub=True 
#TODO Check unmatched requests online
ch_online=True 

#f = open(CPATH+"/at_lookup.log", "a") ###Debug log

#print response header
print header

#IOCs are passed via STDIN in CSV format
infile = sys.stdin
r = csv.DictReader(infile)

c_host="null"
c_domain="null"
c_url="null"
c_ip="null"
c_sdom={}
c_ioc={}
r_ioc={}

for result in r:
    if result["ip"] != "":
        c_ip+=',"'+result["ip"]+'"'
        r_ioc[result["ip"]]="ip"

    if result["url"] != "":
        c_url+=',"'+result["url"]+'"'
        r_ioc[result["url"]]="url"

    if result["host"] != "" and not ch_sub:
        c_host+=',"'+result["host"]+'"'
        c_domain+=',"'+result["host"]+'"'
        r_ioc[result["host"]]="host"

    if result["host"] != "" and ch_sub:
        subdomains=result["host"].split(".")[::-1]
        r_ioc[result["host"]]="host"
        s_domain=subdomains.pop(0)
        for label in subdomains:
            s_domain=label+"."+s_domain
            if s_domain not in c_sdom:
                c_sdom[s_domain]=[]
                c_host+=',"'+s_domain+'"'
                c_domain+=',"'+s_domain+'"'
            if result["host"] not in c_sdom[s_domain]:
                c_sdom[s_domain].append(result["host"])


request = 'SELECT ip,host,url,property FROM combo WHERE ip in ('+c_ip+') or host in ('+c_host+') or domain in ('+c_domain+') or url in ('+c_url+')'
#f.write(str(datetime.datetime.now())+" SQL: "+request+"\n") ###Debug log
sql = Popen(["/usr/bin/sqlite3","-csv",DB,request], stdout=PIPE)
outs, errs = sql.communicate()
if outs != "":
    #f.write(str(datetime.datetime.now())+" Request "+ioctype+" "+result[ioctype]+" response: "+outs.splitlines()[0]+"\n") ###Debug log
    o = csv.DictReader((header+outs).splitlines())
    for result in o:
        if result["ip"] != "":
            print (result["ip"]+",,,"+result["property"])
            if result["ip"] in r_ioc:
                del r_ioc[result["ip"]]
        if result["url"] != "":
            print (",,"+result["url"]+","+result["property"]) 
            if result["url"] in r_ioc:
                del r_ioc[result["url"]]
        if result["host"] != "" and not ch_sub:
            print (","+result["host"]+",,"+result["property"]) 
            if result["host"] in r_ioc:
                del r_ioc[result["host"]]
        if result["host"] != "" and ch_sub and result["host"] in c_sdom:
            #host=result["host"]
            for host in c_sdom[result["host"]]:
                print (","+host+",,"+result["property"])
                if host in r_ioc:
                    del r_ioc[host]

if TIDESearch:
    update=""
    for ioc in r_ioc:
        #print r_ioc[ioc]+" "+ioc
        res,sqlr=get_IOC(r_ioc[ioc],ioc)
        update+=sqlr
        print res
    
    sql = Popen(["/usr/bin/sqlite3","-csv",DB,update], stdout=PIPE)
    outs, errs = sql.communicate()

#f.close  ###Debug log
