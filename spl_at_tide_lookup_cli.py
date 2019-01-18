import sys
import datetime
import csv
###there is no sqlite3 lib on splunk  
from subprocess import Popen, PIPE
###TIDE
import requests
from requests.auth import HTTPBasicAuth


CPATH="/opt/splunk/cache" #Path to DB and debug log
DB=CPATH+"/active-threat-intel.db" #TIDE DB
DBTreats=CPATH+"/threat_properties.db" #Threats Descriptions DB

header="ip,host,url,property\n" #Response header

TIDE_URL="https://platform.activetrust.net:8000/api/data/threats/state/" #TIDE URL
TIDE_max=63 #TIDE max indicators online

ch_sub=True #Check all subdomains
ch_DB=True #Check indicators in DB

#Infoblox TIDE API Key
with open(CPATH+'/at_api_key.txt', 'r') as f:
    ATTIDE_KEY = f.read().rstrip()

#f = open(CPATH+"/at_lookup.log", "a") ###Debug log

#IOCs are passed via STDIN in CSV format
infile = sys.stdin
r = csv.DictReader(infile)

c_host= c_domain= c_url= c_ip="null"
c_sdom= {}
c_ioc= {}
r_ioc={}

#Prepare lists of indicators
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

#print response header
print header

#check indicators in cache
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

#f.close  ###Debug log
