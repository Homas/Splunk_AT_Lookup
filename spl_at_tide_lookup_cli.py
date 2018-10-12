import sys
import datetime
import csv
###there is no sqlite3 lib on splunk  
from subprocess import Popen, PIPE

#Path to DB and debug log
CPATH="/opt/splunk/cache"

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

for result in r:
    if result["ip"] != "":
        c_ip+=',"'+result["ip"]+'"'

    if result["url"] != "":
        c_url+=',"'+result["url"]+'"'

    if result["host"] != "" and not ch_sub:
        c_host+=',"'+result["host"]+'"'
        c_domain+=',"'+result["host"]+'"'

    if result["host"] != "" and ch_sub:
        subdomains=result["host"].split(".")[::-1]
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
    #TODO parse output. Find unmatched requests (for all indicators). Find FQDNs which were checked by a domain (for HOSTs only)
    #print outs
    o = csv.DictReader((header+outs).splitlines())
    for result in o:
        if result["ip"] != "":
            print (result["ip"]+",,,"+result["property"])    
        if result["url"] != "":
            print (",,"+result["url"]+","+result["property"]) 
        if result["host"] != "" and not ch_sub:
            print (","+result["host"]+",,"+result["property"]) 
        if result["host"] != "" and ch_sub and result["host"] in c_sdom:
            #host=result["host"]
            for host in c_sdom[result["host"]]:
                print (","+host+",,"+result["property"])
    
#else:
#    #f.write(str(datetime.datetime.now())+" Request "+ioctype+" "+result[ioctype]+" response: empty\n") ###Debug log
#    for result in r:
#        print result["ip"]+","+result["host"]+","+result["url"]+","


#f.close  ###Debug log
