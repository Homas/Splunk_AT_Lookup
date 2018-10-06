#!/bin/sh

CPATH="/opt/splunk/cache"
APIKEY=`cat $CPATH/at_api_key.txt`
DATE=`date +%Y%m%d%H%M`

if [ -z "$APIKEY" ]; then
	echo "Please set API key in the 'at_api_key.txt' file"
	exit 1
fi

#TIDE DB
DB="${CPATH}/active-threat-intel.db"
#Threats Descriptions DB
DBTreats="${CPATH}/threat_properties.db"


### Get active threats for type ${TYPE} via TIDE API ###
GetActiveThreats(){
	curl -s -X GET --url "https://platform.activetrust.net:8000/api/data/threats/state/${2}?field=host,ip,domain,url,property&data_format=csv" -H "Accept-Encoding:gzip" -u ${APIKEY}: | gunzip - > $1
	if [ $? -ne 0 ]; then
		echo "Failed to retrieve data from TIDE for type ${2}"
		exit 1
	fi
}

CreateThreatsDB () {
	curl -s -H "Content-Type":"application/json"  -H "Accept-Encoding:gzip" -X GET -u ${APIKEY}: "https://platform.activetrust.net:8000/api/data/properties?detail=true"  | gunzip - > "${CPATH}/threat_properties_${DATE}.json" 
	if [ $? -ne 0 ]; then
		echo "Failed to retrieve threat information from TIDE"
		exit 1
	fi
	
	#md5 or diff to check updates
	echo "id^class^threat_level^active^reference^description"> "${CPATH}/threat_properties_${DATE}.csv"
	cat "${CPATH}/threat_properties_${DATE}.json" | sed 's#\\n#<br>#g' | sed 's#^# #g'  | jq -r '.property[] | "\(.id)^\(.class)^\(.threat_level)^\(.active)^\(.reference[0])^\(.description)"' >> "${CPATH}/threat_properties_${DATE}.csv"
	
	sqlite3 --batch "${DBTreats}_${DATE}" << EOF
.mode csv
.separator ^
.import ${CPATH}/threat_properties_${DATE}.csv threats
CREATE INDEX idx_id on threats (id);
EOF
	#.schema
	
	rm "${CPATH}/threat_properties_${DATE}.json" "${CPATH}/threat_properties_${DATE}.csv"
}

### Create db with domain index ###
CreateTIDEDB () {  
	HOSTFILE="${CPATH}/TIDE-host-${DATE}.csv" 
	IPFILE="${CPATH}/TIDE-ip-${DATE}.csv"
	URLFILE="${CPATH}/TIDE-url-${DATE}.csv"
	
	GetActiveThreats $HOSTFILE "host"
	GetActiveThreats $IPFILE "ip"
	GetActiveThreats $URLFILE "url"
	
	sqlite3 --batch "${DB}_${DATE}" << EOF
.mode csv
.import ${HOSTFILE} combo
.import ${IPFILE} combo
.import ${URLFILE} combo
CREATE INDEX idx_host on combo (host);
CREATE INDEX idx_domain on combo (domain);
CREATE INDEX idx_ip on combo (ip);
CREATE INDEX idx_url on combo (url);
EOF
	#.schema
	rm $HOSTFILE $IPFILE $URLFILE
}

#Current DBs
C_DB=`readlink -f ${DB}`
C_DBTreats=`readlink -f ${DBTreats}`

#Create new DBs
CreateTIDEDB
CreateThreatsDB

#Update DBs
ln -sf "${DB}_${DATE}" $DB; if [ "${DB}_${DATE}" != $C_DB ] && [ ! -z "$C_DB" ]; then rm $C_DB;fi
ln -sf "${DBTreats}_${DATE}" $DBTreats;  if [ "${DBTreats}_${DATE}" != $C_DBTreats ] && [ ! -z "$C_DBTreats" ]; then rm $C_DBTreats;fi
