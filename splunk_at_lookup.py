#!/usr/local/bin/python3

import sqlite3
#conn = sqlite3.connect('example.db')

#AT API Key
try:
	with open ("at_api_key.txt", "r") as myfile:
		APIKEY=myfile.read().replace('\n', '')
except FileNotFoundError:	
	print("Please set API key in the 'at_api_key.txt' file")
	sys.exit()

#TIDE DB
DB="${CPATH}/active-threat-intel.db"
#Threats Descriptions DB
DBTreats="${CPATH}/threat_properties.db"
