#!/usr/bin/python2

import sys
###there is no sqlite3 lib on splunk  
from subprocess import Popen, PIPE

CPATH="/opt/splunk/cache"

#TIDE DB
DB=CPATH+"/active-threat-intel.db"
#Threats Descriptions DB
DBTreats=CPATH+"/threat_properties.db"

#select = 'SELECT * FROM '+table+' WHERE host="'+query_data+'" OR domain="'+query_data+'"'
#select = 'SELECT * FROM '+table+' WHERE ip="'+query_data+'"'
#select = 'SELECT * FROM '+table+' WHERE url="'+query_data+'"'


table = "host"
query_data = "eicar.co"
request = 'SELECT * FROM '+table+' WHERE host="'+query_data+'" OR domain="'+query_data+'"'

try:
	sql = Popen(["/usr/bin/sqlite3 "+DB+" '"+request+"'"], stdout=PIPE)
	print sql.communicate()
except IOError:	
	print("Can not request DB")
	sys.exit()


#AT API Key
try:
	with open ("at_api_key.txt", "r") as myfile:
		APIKEY=myfile.read().replace('\n', '')
except IOError:	
	print("Please set API key in the 'at_api_key.txt' file")
	sys.exit()


