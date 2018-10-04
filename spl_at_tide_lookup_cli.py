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
#Check IOCs one by one. not optimal
# for result in r:
#     ioctype = "ip" if result["ip"] != "" else "host" if result["host"] != "" else "url"
#     domain_chk = ' or domain="'+result[ioctype]+'"' if result["host"] != "" else ""
#     request = 'SELECT ip,host,url,property FROM combo WHERE '+ioctype+'="'+result[ioctype]+'"'+domain_chk
#     sql = Popen(["/usr/bin/sqlite3","-csv",DB,request], stdout=PIPE)
#     outs, errs = sql.communicate()
#     if outs == "":
#         #f.write(str(datetime.datetime.now())+" Request "+ioctype+" "+result[ioctype]+" response: empty\n") ###Debug log
#         print result["ip"]+","+result["host"]+","+result["url"]+","
#     else:
#         #f.write(str(datetime.datetime.now())+" Request "+ioctype+" "+result[ioctype]+" response: "+outs.splitlines()[0]+"\n") ###Debug log
#         print outs

c_host="null"
c_domain="null"
c_url="null"
c_ip="null"

for result in r:
    if result["ip"] != "":
        c_ip+=',"'+result["ip"]+'"'

    if result["url"] != "":
        c_url+=',"'+result["url"]+'"'

    if result["host"] != "":
        c_host+=',"'+result["host"]+'"'
        c_domain+=',"'+result["host"]+'"'

request = 'SELECT ip,host,url,property FROM combo WHERE ip in ('+c_ip+') or host in ('+c_host+') or domain in ('+c_domain+') or url in ('+c_url+')'
sql = Popen(["/usr/bin/sqlite3","-csv",DB,request], stdout=PIPE)
outs, errs = sql.communicate()
if outs != "":
    #f.write(str(datetime.datetime.now())+" Request "+ioctype+" "+result[ioctype]+" response: "+outs.splitlines()[0]+"\n") ###Debug log
    print outs

###Do we need an empty lookup result?
#else:
#    #f.write(str(datetime.datetime.now())+" Request "+ioctype+" "+result[ioctype]+" response: empty\n") ###Debug log
#    for result in r:
#        print result["ip"]+","+result["host"]+","+result["url"]+","


#f.close  ###Debug log
