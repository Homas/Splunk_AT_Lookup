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

#f = open(CPATH+"/at_lookup.log", "a") ###Debug log

#print response header
print ("ip,host,url,property")

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

    if result["host"] != "":
        c_host+=',"'+result["host"]+'"'
        c_domain+=',"'+result["host"]+'"'
        if result["host"] not in c_sdom:
            c_sdom[result["host"]]=result["host"]
        subdomains=result["host"].split(".")[::-1]
        s_domain=subdomains.pop(0)
        for label in subdomains:
            s_domain=label+"."+s_domain
            if s_domain not in c_sdom:
                c_sdom[s_domain]=result["host"] #handle a domain for different subdomains
                c_host+=',"'+s_domain+'"'
                c_domain+=',"'+s_domain+'"'



request = 'SELECT ip,host,url,property FROM combo WHERE ip in ('+c_ip+') or host in ('+c_host+') or domain in ('+c_domain+') or url in ('+c_url+')'
#f.write(str(datetime.datetime.now())+" SQL: "+request+"\n") ###Debug log
sql = Popen(["/usr/bin/sqlite3","-csv",DB,request], stdout=PIPE)
outs, errs = sql.communicate()
if outs != "":
    #f.write(str(datetime.datetime.now())+" Request "+ioctype+" "+result[ioctype]+" response: "+outs.splitlines()[0]+"\n") ###Debug log
    #TODO parse output. Find unmatched requests (for all indicators). Find FQDNs which were checked by a domain (for HOSTs only)
    print outs

#else:
#    #f.write(str(datetime.datetime.now())+" Request "+ioctype+" "+result[ioctype]+" response: empty\n") ###Debug log
#    for result in r:
#        print result["ip"]+","+result["host"]+","+result["url"]+","


#f.close  ###Debug log
